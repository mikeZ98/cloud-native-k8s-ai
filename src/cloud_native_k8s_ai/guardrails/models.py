"""Typed results of admission guardrails: violations, remediation advice and reports.

Guardrails judge *raw* manifests, like an admission webhook sees them: the strict schema
models would refuse to even parse most of what admission control has to catch.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Any, Literal

from pydantic import Field

from cloud_native_k8s_ai.core import K8sAiCoreError, render_yaml
from cloud_native_k8s_ai.schemas import K8sModel


class GuardrailDecision(StrEnum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    DENY = "DENY"

    @property
    def rank(self) -> int:
        return _RANK[self]

    @classmethod
    def worst(cls, decisions: Sequence[GuardrailDecision]) -> GuardrailDecision:
        return max(decisions, key=lambda d: d.rank, default=cls.ALLOW)


_RANK = {GuardrailDecision.ALLOW: 0, GuardrailDecision.WARN: 1, GuardrailDecision.DENY: 2}


class ObjectRef(K8sModel):
    kind: str
    namespace: str | None = None
    name: str

    @classmethod
    def of(cls, document: Mapping[str, Any]) -> ObjectRef:
        metadata = document.get("metadata")
        metadata = metadata if isinstance(metadata, Mapping) else {}
        namespace = metadata.get("namespace")
        return cls(
            kind=str(document.get("kind", "?")),
            namespace=str(namespace) if namespace is not None else None,
            name=str(metadata.get("name", "?")),
        )

    def __str__(self) -> str:
        return f"{self.kind} {self.namespace or '-'}/{self.name}"


class JsonPatchOp(K8sModel):
    """One RFC 6902 operation (``add``, ``replace`` or ``remove``) on a JSON pointer."""

    op: Literal["add", "replace", "remove"]
    path: str
    value: Any = None


class RemediationAdvice(K8sModel):
    """How to fix a violation: a patch on the object, a new object, or manual steps."""

    summary: str
    action: Literal["patch", "create", "manual"]
    patch: tuple[JsonPatchOp, ...] = ()
    document: dict[str, Any] | None = None

    @property
    def automatic(self) -> bool:
        return self.action != "manual"


class PolicyViolation(K8sModel):
    code: str
    """Stable kebab-case identifier, e.g. ``privilege-escalation-allowed``."""
    policy: str
    """Guardrail that raised it: ``workload-security``, ``network-zero-trust``, ``autoscaling``."""
    decision: Literal[GuardrailDecision.WARN, GuardrailDecision.DENY]
    target: ObjectRef
    path: str = ""
    """JSON pointer inside the target object ("" for the whole object)."""
    message: str
    remediation: RemediationAdvice

    def __str__(self) -> str:
        return f"[{self.decision}] {self.code} {self.target}{self.path}: {self.message}"


class ObjectDecision(K8sModel):
    target: ObjectRef
    decision: GuardrailDecision


class AdmissionReport(K8sModel):
    decision: GuardrailDecision
    objects: tuple[ObjectDecision, ...]
    violations: tuple[PolicyViolation, ...]

    @classmethod
    def build(
        cls, documents: Sequence[Mapping[str, Any]], violations: Sequence[PolicyViolation]
    ) -> AdmissionReport:
        objects = tuple(
            ObjectDecision(
                target=(ref := ObjectRef.of(d)),
                decision=GuardrailDecision.worst(
                    [v.decision for v in violations if v.target == ref]
                ),
            )
            for d in documents
        )
        return cls(
            decision=GuardrailDecision.worst([v.decision for v in violations]),
            objects=objects,
            violations=tuple(violations),
        )

    @property
    def allowed(self) -> bool:
        return self.decision is not GuardrailDecision.DENY

    def codes(self) -> set[str]:
        return {v.code for v in self.violations}

    def raise_for_denial(self) -> None:
        if not self.allowed:
            raise AdmissionDeniedError(self)


class RemediationRound(K8sModel):
    round: int = Field(ge=1)
    applied: tuple[str, ...]
    """``<code> <target>`` of every remediation applied in this round."""
    remaining: int


class RemediationResult(K8sModel):
    """Outcome of a critic loop: the manifests after automatic fixes, and both reports."""

    initial: AdmissionReport
    final: AdmissionReport
    rounds: tuple[RemediationRound, ...]
    converged: bool
    """No automatically fixable violation is left (manual ones may remain)."""
    documents: tuple[dict[str, Any], ...]

    def to_yaml(self) -> str:
        return render_yaml(self.documents)


class GuardrailError(K8sAiCoreError):
    """A guardrail could not run (e.g. a remediation patch does not apply)."""


class AdmissionDeniedError(GuardrailError):
    """Admission denied; ``report`` holds every violation and its remediation advice, and
    ``remediation`` the critic loop that ran first (if any)."""

    def __init__(
        self, report: AdmissionReport, remediation: RemediationResult | None = None
    ) -> None:
        self.report = report
        self.remediation = remediation
        denied = [v for v in report.violations if v.decision is GuardrailDecision.DENY]
        detail = "".join(f"\n  - {v}" for v in denied)
        super().__init__(f"admission denied: {len(denied)} blocking violation(s){detail}")
