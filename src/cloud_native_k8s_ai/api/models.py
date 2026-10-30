"""Request and response contracts of the control plane (camelCase on the wire)."""

from __future__ import annotations

from collections import Counter
from typing import Any, Literal

from pydantic import Field

from cloud_native_k8s_ai.core import AIStackSpec, ManifestBundle
from cloud_native_k8s_ai.schemas import DNS1123Label, InfraSettings, K8sModel
from cloud_native_k8s_ai.schemas.settings import DEFAULT_NAMESPACE, Environment
from cloud_native_k8s_ai.tools.helm import Release, ReleaseName


class InfraSpec(K8sModel):
    """What to compile: target environment and namespace plus the AI stack."""

    environment: Environment = "dev"
    namespace: DNS1123Label = DEFAULT_NAMESPACE
    stack: AIStackSpec

    def settings(self) -> InfraSettings:
        return InfraSettings(environment=self.environment, namespace=self.namespace)


class CompileResponse(K8sModel):
    """A compiled bundle in apply order (NetworkPolicies first, ScaledObject last)."""

    environment: Environment
    namespace: DNS1123Label
    count: int
    kinds: dict[str, int]
    documents: tuple[dict[str, Any], ...]

    @classmethod
    def from_bundle(cls, spec: InfraSpec, bundle: ManifestBundle) -> CompileResponse:
        documents = tuple(bundle.to_documents())
        return cls(
            environment=spec.environment,
            namespace=spec.namespace,
            count=len(documents),
            kinds=dict(Counter(d["kind"] for d in documents)),
            documents=documents,
        )


class ReleaseRef(K8sModel):
    name: ReleaseName = "ai"
    namespace: DNS1123Label = DEFAULT_NAMESPACE

    def to_release(self) -> Release:
        return Release(name=self.name, namespace=self.namespace)


class ChartValidationRequest(K8sModel):
    """A values overlay, merged over the chart defaults like ``helm install -f``."""

    values: dict[str, Any] = Field(default_factory=dict)
    release: ReleaseRef = Field(default_factory=ReleaseRef)


class ChartValidationResponse(K8sModel):
    status: Literal["pass"] = "pass"
    release: ReleaseRef
    findings: tuple[str, ...] = ()


class TopologyRequest(K8sModel):
    """Multi-document manifest YAML, checked against the intent of ``spec``
    (the reference stack when omitted)."""

    manifests: str = Field(min_length=1)
    spec: InfraSpec | None = None


class TopologyResponse(K8sModel):
    status: Literal["pass"] = "pass"
    namespace: DNS1123Label
    policies: int
    workloads: int
    reachable: tuple[str, ...]
    """Every flow the policies allow between the probed endpoints."""


class HealthResponse(K8sModel):
    status: Literal["ok"] = "ok"
    version: str
    uptime_seconds: float


class ReadinessResponse(K8sModel):
    status: Literal["ready", "unavailable"]
    checks: dict[str, str]
