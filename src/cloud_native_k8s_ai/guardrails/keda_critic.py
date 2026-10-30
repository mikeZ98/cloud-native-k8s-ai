"""Autoscaling safety guardrail for KEDA ScaledObjects (raw manifests).

Refuses configurations that thrash or cannot work: cooldown shorter than the polling
interval, inconsistent replica bounds, non-positive scaling thresholds, several scalers
fighting over one workload, and a maximum scale-out that breaches the namespace's
ResourceQuota. Missing fields take KEDA's defaults (polling 30s, cooldown 300s,
minReplicaCount 0, maxReplicaCount 100).
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Final

from cloud_native_k8s_ai.guardrails.catalog import AUTOSCALING, violation
from cloud_native_k8s_ai.guardrails.models import (
    JsonPatchOp,
    ObjectRef,
    PolicyViolation,
    RemediationAdvice,
)
from cloud_native_k8s_ai.guardrails.objects import (
    Workload,
    dig,
    mapping,
    namespace_of,
    pointer,
    sequence,
    workloads,
)
from cloud_native_k8s_ai.schemas import cpu_millicores, memory_bytes

POLICY: Final = AUTOSCALING
KEDA_DEFAULTS: Final = {
    "pollingInterval": 30,
    "cooldownPeriod": 300,
    "minReplicaCount": 0,
    "maxReplicaCount": 100,
}
TARGET_KEYS: Final = frozenset(
    {"listLength", "pendingEntriesCount", "lagCount", "lagThreshold", "value", "targetValue",
     "threshold", "queueLength"}
)  # fmt: skip
"""Trigger metadata keys that set the per-replica target; they must be > 0."""
_QUOTA_KEYS: Final[Mapping[str, tuple[str, str, Callable[[str], int]]]] = {
    "requests.cpu": ("requests", "cpu", cpu_millicores),
    "cpu": ("requests", "cpu", cpu_millicores),
    "requests.memory": ("requests", "memory", memory_bytes),
    "memory": ("requests", "memory", memory_bytes),
    "limits.cpu": ("limits", "cpu", cpu_millicores),
    "limits.memory": ("limits", "memory", memory_bytes),
}


def _number(value: Any) -> Decimal | None:
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        return None
    try:
        number = Decimal(str(value).strip())
    except InvalidOperation:
        return None
    return number if number.is_finite() else None


def _per_pod(workload: Workload, section: str, resource: str, parse: Callable[[str], int]) -> int:
    total = 0
    for container in workload.containers():
        if container.field != "containers":
            continue
        amount = dig(container.spec, "resources", section, resource)
        if amount is not None:
            try:
                total += parse(str(amount))
            except ValueError:
                continue  # reported by the workload guardrail
    return total


@dataclass(frozen=True)
class KedaCritic:
    name: str = POLICY
    min_polling_interval: int = 5
    """Below this many seconds, polling is flagged as too aggressive (metric flapping)."""

    def evaluate(self, documents: Sequence[Mapping[str, Any]]) -> list[PolicyViolation]:
        scaled = [d for d in documents if d.get("kind") == "ScaledObject"]
        violations: list[PolicyViolation] = []
        for document in scaled:
            violations += self._timing_and_bounds(document)
            violations += self._triggers(document)
            violations += self._target(document, documents)
        violations += self._conflicts(documents)
        violations += self._quotas(scaled, documents)
        return violations

    def _violation(
        self,
        code: str,
        target: ObjectRef,
        path: str,
        message: str,
        advice: RemediationAdvice,
    ) -> PolicyViolation:
        return violation(
            code, policy=self.name, target=target, path=path, message=message, remediation=advice
        )

    @staticmethod
    def _manual(summary: str) -> RemediationAdvice:
        return RemediationAdvice(summary=summary, action="manual")

    def _timing_and_bounds(self, document: Mapping[str, Any]) -> list[PolicyViolation]:
        ref, spec = ObjectRef.of(document), mapping(document.get("spec"))
        values: dict[str, int] = {}
        violations: list[PolicyViolation] = []
        for key, default in KEDA_DEFAULTS.items():
            value = spec.get(key, default)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                values[key] = value
            else:
                violations.append(
                    self._violation(
                        "keda-invalid-field",
                        ref,
                        pointer("spec", key),
                        f"{key} must be a non-negative integer, got {value!r}",
                        self._manual(f"set {key} to a non-negative integer"),
                    )
                )
        if violations:
            return violations
        polling, cooldown = values["pollingInterval"], values["cooldownPeriod"]
        low, high = values["minReplicaCount"], values["maxReplicaCount"]
        if cooldown < polling:
            fixed = max(polling, KEDA_DEFAULTS["cooldownPeriod"])
            violations.append(
                self._violation(
                    "keda-cooldown-below-polling",
                    ref,
                    "/spec/cooldownPeriod",
                    f"cooldownPeriod {cooldown}s < pollingInterval {polling}s: scale-down acts "
                    "on unsampled metrics and the workload thrashes",
                    RemediationAdvice(
                        summary=f"set cooldownPeriod to {fixed}s",
                        action="patch",
                        patch=(JsonPatchOp(op="add", path="/spec/cooldownPeriod", value=fixed),),
                    ),
                )
            )
        if polling < self.min_polling_interval:
            violations.append(
                self._violation(
                    "keda-polling-too-aggressive",
                    ref,
                    "/spec/pollingInterval",
                    f"pollingInterval {polling}s is below {self.min_polling_interval}s",
                    self._manual(f"poll every {self.min_polling_interval}s or slower"),
                )
            )
        if low > high:
            violations.append(
                self._violation(
                    "keda-replica-bounds",
                    ref,
                    "/spec/minReplicaCount",
                    f"minReplicaCount {low} exceeds maxReplicaCount {high}",
                    self._manual("make minReplicaCount <= maxReplicaCount"),
                )
            )
        elif low == high:
            violations.append(
                self._violation(
                    "keda-no-scaling-range",
                    ref,
                    "/spec/maxReplicaCount",
                    f"minReplicaCount == maxReplicaCount == {low}: the scaler can never act",
                    self._manual("widen the replica range or remove the ScaledObject"),
                )
            )
        idle = spec.get("idleReplicaCount")
        if idle is not None and (
            not isinstance(idle, int) or isinstance(idle, bool) or idle >= low
        ):
            violations.append(
                self._violation(
                    "keda-idle-replicas",
                    ref,
                    "/spec/idleReplicaCount",
                    f"idleReplicaCount {idle!r} must be an integer below minReplicaCount {low}",
                    self._manual("lower idleReplicaCount below minReplicaCount (usually 0)"),
                )
            )
        return violations

    def _triggers(self, document: Mapping[str, Any]) -> list[PolicyViolation]:
        ref = ObjectRef.of(document)
        triggers = sequence(dig(document, "spec", "triggers"))
        if not triggers:
            return [
                self._violation(
                    "keda-no-triggers",
                    ref,
                    "/spec/triggers",
                    "ScaledObject has no triggers",
                    self._manual("add a trigger (e.g. redis listLength)"),
                )
            ]
        violations: list[PolicyViolation] = []
        for i, trigger in enumerate(triggers):
            for key, raw in mapping(mapping(trigger).get("metadata")).items():
                is_target, is_activation = key in TARGET_KEYS, str(key).startswith("activation")
                if not (is_target or is_activation):
                    continue
                path = pointer("spec", "triggers", i, "metadata", key)
                number = _number(raw)
                if number is None:
                    code, text = "keda-threshold-invalid", f"{key} {raw!r} is not a number"
                elif is_target and number <= 0:
                    code, text = "keda-threshold-not-positive", f"{key} {raw!r} must be > 0"
                elif is_activation and number < 0:
                    code, text = "keda-activation-negative", f"{key} {raw!r} must be >= 0"
                else:
                    continue
                advice = self._manual(f"set {key} to a positive per-replica target")
                violations.append(self._violation(code, ref, path, text, advice))
        return violations

    def _target(
        self, document: Mapping[str, Any], documents: Sequence[Mapping[str, Any]]
    ) -> list[PolicyViolation]:
        kind, name = _target_of(document)
        namespace = namespace_of(document)
        if any(
            d.get("kind") == kind
            and dig(d, "metadata", "name") == name
            and namespace_of(d) == namespace
            for d in documents
        ):
            return []
        return [
            self._violation(
                "keda-target-missing",
                ObjectRef.of(document),
                "/spec/scaleTargetRef",
                f"scale target {kind} {namespace}/{name} is not part of this manifest set",
                self._manual("deploy the target together with its ScaledObject"),
            )
        ]

    def _conflicts(self, documents: Sequence[Mapping[str, Any]]) -> list[PolicyViolation]:
        scalers: dict[tuple[str, str, str | None], list[Mapping[str, Any]]] = defaultdict(list)
        for document in documents:
            if document.get("kind") in {"ScaledObject", "HorizontalPodAutoscaler"}:
                kind, name = _target_of(document)
                scalers[(namespace_of(document), kind, name)].append(document)
        violations: list[PolicyViolation] = []
        for (namespace, kind, name), owners in scalers.items():
            if len(owners) < 2:  # noqa: PLR2004
                continue
            refs = [str(ObjectRef.of(o)) for o in owners]
            violations += [
                self._violation(
                    "keda-conflicting-scalers",
                    ObjectRef.of(owner),
                    "/spec/scaleTargetRef",
                    f"{kind} {namespace}/{name} is scaled by {refs}: they overwrite each other",
                    self._manual("keep exactly one autoscaler per workload"),
                )
                for owner in owners
            ]
        return violations

    def _quotas(
        self, scaled: Sequence[Mapping[str, Any]], documents: Sequence[Mapping[str, Any]]
    ) -> list[PolicyViolation]:
        violations: list[PolicyViolation] = []
        pods = workloads(documents)
        for quota in (d for d in documents if d.get("kind") == "ResourceQuota"):
            namespace = namespace_of(quota)
            local = [w for w in pods if w.namespace == namespace and w.ref.kind != "DaemonSet"]
            targets = {_target_of(s): s for s in scaled if namespace_of(s) == namespace}
            replicas = {
                w.ref: _max_replicas(targets[(w.ref.kind, w.ref.name)])
                if (w.ref.kind, w.ref.name) in targets
                else w.replicas()
                for w in local
            }
            for key, raw in mapping(dig(quota, "spec", "hard")).items():
                if key not in _QUOTA_KEYS:
                    continue
                section, resource, parse = _QUOTA_KEYS[key]
                try:
                    hard = parse(str(raw))
                except ValueError:
                    continue
                per_pod = {w.ref: _per_pod(w, section, resource, parse) for w in local}
                usage = sum(replicas[ref] * amount for ref, amount in per_pod.items())
                if usage <= hard:
                    continue
                for workload in local:
                    owner = targets.get((workload.ref.kind, workload.ref.name))
                    if owner is None or not per_pod[workload.ref]:
                        continue
                    others = usage - replicas[workload.ref] * per_pod[workload.ref]
                    fits = max(0, math.floor((hard - others) / per_pod[workload.ref]))
                    violations.append(
                        self._violation(
                            "keda-exceeds-quota",
                            ObjectRef.of(owner),
                            "/spec/maxReplicaCount",
                            f"at maxReplicaCount {replicas[workload.ref]} namespace {namespace} "
                            f"needs {key} {usage} but ResourceQuota {ObjectRef.of(quota).name} "
                            f"allows {hard} (units: millicores / bytes)",
                            self._manual(
                                f"lower maxReplicaCount to {fits} or raise the quota's {key}"
                            ),
                        )
                    )
        return violations


def _target_of(document: Mapping[str, Any]) -> tuple[str, str | None]:
    ref = mapping(dig(document, "spec", "scaleTargetRef"))
    name = ref.get("name")
    return str(ref.get("kind", "Deployment")), str(name) if name is not None else None


def _max_replicas(document: Mapping[str, Any]) -> int:
    value = dig(document, "spec", "maxReplicaCount")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return KEDA_DEFAULTS["maxReplicaCount"]
