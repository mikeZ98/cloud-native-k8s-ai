"""The catalog of every built-in violation code: owning guardrail, decision, remediation.

A code always carries the same decision and the same kind of remediation, so both live
here once instead of at each call site. ``docs/security_model.md`` documents exactly this
catalog (a test keeps the two in sync).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal

from cloud_native_k8s_ai.guardrails.models import (
    GuardrailDecision,
    GuardrailError,
    ObjectRef,
    PolicyViolation,
    RemediationAdvice,
)

type Remediation = Literal["patch", "create", "manual"]
type Verdict = Literal[GuardrailDecision.WARN, GuardrailDecision.DENY]

WORKLOAD: Final = "workload-security"
NETWORK: Final = "network-zero-trust"
AUTOSCALING: Final = "autoscaling"

_D: Final[Verdict] = GuardrailDecision.DENY
_W: Final[Verdict] = GuardrailDecision.WARN


@dataclass(frozen=True, slots=True)
class CodeSpec:
    policy: str
    decision: Verdict
    remediation: Remediation
    summary: str


def _codes(policy: str, *entries: tuple[str, Verdict, Remediation, str]) -> dict[str, CodeSpec]:
    return {
        code: CodeSpec(policy, decision, fix, summary) for code, decision, fix, summary in entries
    }


CATALOG: Final[Mapping[str, CodeSpec]] = {
    **_codes(
        WORKLOAD,
        ("run-as-root", _D, "patch", "a container runs as UID 0"),
        (
            "run-as-non-root-not-enforced",
            _D,
            "patch",
            "runAsNonRoot is not true (container or pod)",
        ),
        ("writable-root-filesystem", _D, "patch", "readOnlyRootFilesystem is not true"),
        ("privilege-escalation-allowed", _D, "patch", "allowPrivilegeEscalation is not false"),
        ("privileged-container", _D, "patch", "privileged: true"),
        ("capabilities-not-dropped", _D, "patch", "capabilities.drop does not contain ALL"),
        ("capabilities-added", _D, "patch", "adds a capability outside the allow list"),
        ("host-namespace", _D, "patch", "hostNetwork, hostPID or hostIPC is true"),
        (
            "selector-template-mismatch",
            _D,
            "manual",
            "spec.selector does not select the pod template",
        ),
        ("best-effort-container", _D, "manual", "no resource requests or limits at all"),
        ("missing-resource-requests", _D, "manual", "cpu or memory request missing"),
        ("missing-resource-limits", _D, "manual", "cpu or memory limit missing"),
        ("requests-exceed-limits", _D, "manual", "a request is larger than its limit"),
        ("invalid-resource-quantity", _D, "manual", "a quantity does not parse"),
        ("image-untagged", _D, "manual", "image has no tag or digest (implicit :latest)"),
        ("image-latest-tag", _D, "manual", "image uses the mutable :latest tag"),
        ("image-invalid-digest", _D, "manual", "image digest is not sha256:<64 hex>"),
    ),
    **_codes(
        NETWORK,
        ("invalid-pod-selector", _D, "manual", "a policy's podSelector is not a valid selector"),
        ("ingress-from-anywhere", _D, "patch", "an ingress rule has no from: every source"),
        ("egress-to-anywhere", _D, "patch", "an egress rule has no to: every destination"),
        ("external-ingress", _D, "patch", "ipBlock source outside the allow-listed CIDRs"),
        ("external-egress", _D, "patch", "ipBlock destination outside the allow-listed CIDRs"),
        ("cross-namespace-ingress", _D, "patch", "source namespace is broad or untrusted"),
        ("cross-namespace-egress", _D, "patch", "destination namespace is broad or untrusted"),
        ("invalid-peer", _D, "patch", "a peer selects nothing valid"),
        ("missing-default-deny-ingress", _D, "create", "namespace has no default-deny ingress"),
        ("missing-default-deny-egress", _D, "create", "namespace has no default-deny egress"),
        ("missing-dns-egress", _W, "create", "egress-isolated pods cannot resolve DNS"),
        (
            "qdrant-ingress-not-exclusive",
            _D,
            "patch",
            "Qdrant admits more than the API on its ports",
        ),
        ("qdrant-not-isolated", _D, "create", "no ingress policy selects Qdrant"),
        (
            "qdrant-unreachable-from-api",
            _W,
            "create",
            "Qdrant is isolated but the API cannot reach it",
        ),
        (
            "workload-selector-overlap",
            _D,
            "manual",
            "pods carry another workload's selector labels",
        ),
    ),
    **_codes(
        AUTOSCALING,
        ("keda-invalid-field", _D, "manual", "a timing or replica field is not an integer >= 0"),
        (
            "keda-cooldown-below-polling",
            _D,
            "patch",
            "cooldownPeriod < pollingInterval (thrashing)",
        ),
        (
            "keda-polling-too-aggressive",
            _W,
            "manual",
            "pollingInterval below the minimum (flapping)",
        ),
        ("keda-replica-bounds", _D, "manual", "minReplicaCount > maxReplicaCount"),
        ("keda-no-scaling-range", _W, "manual", "minReplicaCount == maxReplicaCount"),
        ("keda-idle-replicas", _D, "manual", "idleReplicaCount is not below minReplicaCount"),
        ("keda-no-triggers", _D, "manual", "ScaledObject without triggers"),
        ("keda-threshold-invalid", _D, "manual", "a trigger threshold is not a number"),
        ("keda-threshold-not-positive", _D, "manual", "a per-replica target is <= 0"),
        ("keda-activation-negative", _D, "manual", "an activation threshold is < 0"),
        ("keda-target-missing", _W, "manual", "the scale target is not in the manifest set"),
        ("keda-conflicting-scalers", _D, "manual", "several autoscalers target one workload"),
        ("keda-exceeds-quota", _D, "manual", "max scale-out breaches the namespace ResourceQuota"),
    ),
}


def violation(
    code: str,
    *,
    policy: str,
    target: ObjectRef,
    path: str,
    message: str,
    remediation: RemediationAdvice,
) -> PolicyViolation:
    """A violation whose decision comes from the catalog; built-in guardrails create every
    violation here, so an unregistered code (KeyError) or a remediation of the wrong kind
    (GuardrailError) cannot slip out unnoticed."""
    spec = CATALOG[code]
    if remediation.action != spec.remediation:
        raise GuardrailError(
            f"{code}: remediation {remediation.action!r} contradicts the catalog's "
            f"{spec.remediation!r}"
        )
    return PolicyViolation(
        code=code,
        policy=policy,
        decision=spec.decision,
        target=target,
        path=path,
        message=message,
        remediation=remediation,
    )
