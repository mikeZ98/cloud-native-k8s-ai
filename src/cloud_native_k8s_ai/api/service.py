"""The control plane's work, independent of HTTP: compile, validate, self-check.

``ControlPlane.start`` runs the readiness self-checks once at startup: the chart loads,
its default values satisfy the schema and the typed contracts (the *reference stack*),
the reference stack compiles to a zero-trust bundle, and the chart lints clean. All
methods are synchronous and CPU-bound; routes call them in a worker thread.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from cloud_native_k8s_ai.api.config import ApiSettings
from cloud_native_k8s_ai.api.models import (
    AdmissionResponse,
    InfraSpec,
    RemediationSummary,
    TopologyResponse,
)
from cloud_native_k8s_ai.api.problems import ControlPlaneUnavailableError
from cloud_native_k8s_ai.api.telemetry import Metrics
from cloud_native_k8s_ai.core import (
    AIStackGenerator,
    K8sAiCoreError,
    ManifestBundle,
    ManifestRenderError,
    TopologySolver,
    compile_ai_stack,
    screen_untrusted_yaml,
)
from cloud_native_k8s_ai.guardrails import AdmissionDeniedError, AdmissionEngine
from cloud_native_k8s_ai.schemas import NetworkPolicy
from cloud_native_k8s_ai.tools.helm import Chart, LintReport, Release, lint_chart, validate_values

CHECK_OK = "ok"


def _failure(exc: Exception) -> str:
    return f"{type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}".rstrip(": ")


@dataclass
class ControlPlane:
    settings: ApiSettings
    metrics: Metrics
    chart: Chart | None = None
    reference: InfraSpec | None = None
    checks: dict[str, str] = field(default_factory=dict)
    draining: bool = False

    @classmethod
    def start(cls, settings: ApiSettings, metrics: Metrics) -> ControlPlane:
        plane = cls(settings, metrics)
        plane.checks = plane._self_check()
        return plane

    def _self_check(self) -> dict[str, str]:
        checks = dict.fromkeys(
            ("chart", "schemas", "generator", "guardrails", "chartLint"), "skipped"
        )
        try:
            self.chart = Chart.load(self.settings.chart_dir)
            checks["chart"] = CHECK_OK
            stack = validate_values(self.chart, self.chart.values)
            reference = InfraSpec(
                environment=stack.settings.environment,
                namespace=stack.settings.namespace,
                stack=stack.spec,
            )
            if InfraSpec.from_wire(reference.to_wire()) != reference:
                raise ManifestRenderError("reference stack does not survive a wire round trip")
            self.reference = reference
            checks["schemas"] = CHECK_OK
            bundle = compile_ai_stack(reference.settings(), reference.stack)
            if not len(bundle):
                raise ManifestRenderError("reference stack compiled to an empty bundle")
            checks["generator"] = CHECK_OK
            AdmissionEngine().admit(bundle)
            checks["guardrails"] = CHECK_OK
            report = lint_chart(self.chart)
            checks["chartLint"] = CHECK_OK if report.ok else f"{len(report.findings)} finding(s)"
        except K8sAiCoreError as exc:
            failed = next(name for name, state in checks.items() if state == "skipped")
            checks[failed] = _failure(exc)
        return checks

    @property
    def ready(self) -> bool:
        return not self.draining and all(state == CHECK_OK for state in self.checks.values())

    def require_reference(self) -> tuple[Chart, InfraSpec]:
        if self.chart is None or self.reference is None:
            raise ControlPlaneUnavailableError(
                f"reference chart unavailable at {self.settings.chart_dir} "
                "(see /readyz; set K8SAI_API_CHART_DIR)"
            )
        return self.chart, self.reference

    def reference_spec(self, overrides: dict[str, Any]) -> InfraSpec:
        """The reference stack with environment/namespace overrides, revalidated."""
        _, reference = self.require_reference()
        return InfraSpec.from_wire(reference.to_wire() | overrides)

    # -- operations -------------------------------------------------------
    def compile(self, spec: InfraSpec) -> ManifestBundle:
        begin = time.perf_counter()
        try:
            bundle = compile_ai_stack(spec.settings(), spec.stack)
        except K8sAiCoreError:
            self.metrics.compilations.labels("failure").inc()
            raise
        self.metrics.compilations.labels("success").inc()
        self.metrics.compile_latency.observe(time.perf_counter() - begin)
        for resource in bundle:
            self.metrics.documents.labels(resource.kind).inc()
        return bundle

    def validate_chart(self, values: dict[str, Any], release: Release) -> LintReport:
        chart, _ = self.require_reference()
        report = lint_chart(chart, {"request": values}, release, include_defaults=False)
        self.metrics.validations.labels("chart", "pass" if report.ok else "fail").inc()
        report.raise_for_findings()
        return report

    def admit(self, manifests: str, *, remediate: bool) -> AdmissionResponse:
        """Every admission guardrail; with ``remediate`` the critic loop runs first."""
        engine = AdmissionEngine()
        try:
            result = engine.remediate(manifests) if remediate else None
            report = result.final if result is not None else engine.evaluate(manifests)
        except K8sAiCoreError:
            self.metrics.validations.labels("admission", "error").inc()
            raise
        self.metrics.validations.labels("admission", report.decision.lower()).inc()
        if not report.allowed:
            raise AdmissionDeniedError(report, result)
        summary = None if result is None else RemediationSummary.from_result(result)
        return AdmissionResponse(report=report, remediation=summary)

    def validate_topology(self, manifests: str, spec: InfraSpec | None) -> TopologyResponse:
        spec = spec or self.require_reference()[1]
        try:
            screen_untrusted_yaml(manifests)
            bundle = ManifestBundle.from_yaml(manifests)
            generator = AIStackGenerator(spec.settings(), spec.stack)
            report = TopologySolver(generator.topology(bundle)).verify(generator.intent())
            report.raise_for_violations()
        except K8sAiCoreError:
            self.metrics.validations.labels("topology", "fail").inc()
            raise
        self.metrics.validations.labels("topology", "pass").inc()
        return TopologyResponse(
            namespace=spec.namespace,
            policies=len(bundle.of_kind(NetworkPolicy)),
            workloads=len(bundle.workloads()),
            reachable=tuple(sorted(str(flow) for flow in report.reachable)),
        )
