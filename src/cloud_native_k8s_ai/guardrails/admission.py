"""Workload security guardrail: Kyverno/OPA restricted-profile parity in pure Python.

For every container (init and ephemeral included) of every pod-producing object:
non-root user, read-only root filesystem, no privilege escalation, no privileged mode,
``drop: [ALL]`` with only allow-listed capabilities added, explicit CPU and memory
requests *and* limits (no BestEffort pods), and an image pinned by tag or digest, never
``:latest``. Host namespaces are refused at pod level.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from cloud_native_k8s_ai.guardrails.catalog import WORKLOAD, violation
from cloud_native_k8s_ai.guardrails.models import (
    JsonPatchOp,
    PolicyViolation,
    RemediationAdvice,
)
from cloud_native_k8s_ai.guardrails.objects import (
    Container,
    Workload,
    mapping,
    pointer,
    selector,
    sequence,
    workloads,
)
from cloud_native_k8s_ai.schemas import cpu_millicores, memory_bytes

POLICY: Final = WORKLOAD
PLATFORM_UID: Final = 10001
"""UID substituted for an explicit root user (the images' unprivileged user)."""
HOST_NAMESPACES: Final = ("hostNetwork", "hostPID", "hostIPC")
_QUANTITY_PARSERS: Final[Mapping[str, Callable[[str], int]]] = {
    "cpu": cpu_millicores,
    "memory": memory_bytes,
}
_DIGEST_RE: Final = re.compile(r"^sha256:[a-f0-9]{64}$")
_RESOURCES_HINT: Final = (
    "declare resources.requests and resources.limits for cpu and memory "
    "(e.g. requests cpu 250m / memory 256Mi, limits cpu 1 / memory 512Mi)"
)


def image_problem(image: Any) -> str | None:
    """``image-untagged`` / ``image-latest-tag`` / ``image-invalid-digest``, or ``None``."""
    if not isinstance(image, str) or not image:
        return "image-untagged"
    reference, _, digest = image.partition("@")
    if digest:
        return None if _DIGEST_RE.match(digest) else "image-invalid-digest"
    _, _, tag = reference.rpartition("/")[2].partition(":")
    if not tag:
        return "image-untagged"
    return "image-latest-tag" if tag == "latest" else None


@dataclass(frozen=True)
class WorkloadGuardrail:
    name: str = POLICY
    allowed_capabilities: frozenset[str] = field(
        default_factory=lambda: frozenset({"NET_BIND_SERVICE"})
    )

    def evaluate(self, documents: Sequence[Mapping[str, Any]]) -> list[PolicyViolation]:
        violations: list[PolicyViolation] = []
        for workload in workloads(documents):
            violations += self._selector(workload)
            violations += self._host_namespaces(workload)
            for container in workload.containers():
                violations += self._security(workload, container)
                violations += self._resources(workload, container)
                violations += self._image(workload, container)
        return violations

    def _violation(
        self, workload: Workload, code: str, path: str, message: str, advice: RemediationAdvice
    ) -> PolicyViolation:
        return violation(
            code,
            policy=self.name,
            target=workload.ref,
            path=path,
            message=message,
            remediation=advice,
        )

    def _selector(self, workload: Workload) -> list[PolicyViolation]:
        """``spec.selector`` must select the pod template: the API server rejects a mismatch,
        and a typo'd label would silently drop every NetworkPolicy grant to those pods."""
        raw = mapping(workload.document.get("spec")).get("selector")
        if raw is None or workload.ref.kind in {"Pod", "Job", "CronJob"}:
            return []  # bare pods and jobs have no (or a generated) selector
        parsed = selector(raw)
        if parsed is not None and parsed.matches(workload.pod_labels):
            return []
        return [
            self._violation(
                workload,
                "selector-template-mismatch",
                "/spec/selector",
                f"selector {raw!r} does not match the pod template labels "
                f"{dict(workload.pod_labels)}",
                RemediationAdvice(
                    summary="make spec.selector.matchLabels a subset of the pod template labels",
                    action="manual",
                ),
            )
        ]

    def _host_namespaces(self, workload: Workload) -> list[PolicyViolation]:
        return [
            self._violation(
                workload,
                "host-namespace",
                f"{workload.pod_path}{pointer(key)}",
                f"pod shares the node's {key.removeprefix('host')} namespace",
                RemediationAdvice(
                    summary=f"remove {key} from the pod spec",
                    action="patch",
                    patch=(JsonPatchOp(op="remove", path=f"{workload.pod_path}{pointer(key)}"),),
                ),
            )
            for key in HOST_NAMESPACES
            if workload.pod_spec.get(key) is True
        ]

    # -- securityContext ----------------------------------------------------
    def _security(self, workload: Workload, container: Container) -> list[PolicyViolation]:
        pod_context = mapping(workload.pod_spec.get("securityContext"))
        context = mapping(container.spec.get("securityContext"))
        capabilities = mapping(context.get("capabilities"))
        user = context.get("runAsUser", pod_context.get("runAsUser"))
        extra_caps = sorted(
            str(c) for c in sequence(capabilities.get("add")) if c not in self.allowed_capabilities
        )
        base = f"{container.path}/securityContext"
        checks = [
            (user == 0, "run-as-root", "runAsUser", "runs as UID 0 (root)"),
            (
                context.get("runAsNonRoot", pod_context.get("runAsNonRoot")) is not True,
                "run-as-non-root-not-enforced",
                "runAsNonRoot",
                "runAsNonRoot is not true: the image may run as root",
            ),
            (
                context.get("readOnlyRootFilesystem") is not True,
                "writable-root-filesystem",
                "readOnlyRootFilesystem",
                "root filesystem is writable",
            ),
            (
                context.get("allowPrivilegeEscalation") is not False,
                "privilege-escalation-allowed",
                "allowPrivilegeEscalation",
                "allowPrivilegeEscalation is not false (setuid binaries can gain privileges)",
            ),
            (
                context.get("privileged") is True,
                "privileged-container",
                "privileged",
                "runs privileged (full access to the host)",
            ),
            (
                "ALL" not in sequence(capabilities.get("drop")),
                "capabilities-not-dropped",
                "capabilities/drop",
                "capabilities.drop does not contain ALL",
            ),
            (
                bool(extra_caps),
                "capabilities-added",
                "capabilities/add",
                f"adds capabilities {extra_caps}",
            ),
        ]
        failed = [(code, f"{base}/{key}", text) for broken, code, key, text in checks if broken]
        if not failed:
            return []
        advice = RemediationAdvice(
            summary=(
                f"harden container {container.name!r}: runAsNonRoot, read-only root filesystem, "
                "no privilege escalation, not privileged, drop ALL capabilities"
            ),
            action="patch",
            patch=(
                JsonPatchOp(
                    op="add", path=base, value=self._hardened(context, root_user=user == 0)
                ),
            ),
        )
        return [
            self._violation(workload, code, path, f"container {container.name!r}: {text}", advice)
            for code, path, text in failed
        ]

    def _hardened(self, context: Mapping[str, Any], *, root_user: bool) -> dict[str, Any]:
        capabilities = mapping(context.get("capabilities"))
        drop = [str(c) for c in sequence(capabilities.get("drop"))]
        hardened: dict[str, Any] = {
            **context,
            "runAsNonRoot": True,
            "readOnlyRootFilesystem": True,
            "allowPrivilegeEscalation": False,
            "privileged": False,
            "capabilities": {
                **capabilities,
                "drop": drop if "ALL" in drop else [*drop, "ALL"],
                "add": [
                    str(c)
                    for c in sequence(capabilities.get("add"))
                    if c in self.allowed_capabilities
                ],
            },
        }
        if root_user:
            hardened["runAsUser"] = PLATFORM_UID
        return hardened

    # -- resources ------------------------------------------------------------
    def _resources(self, workload: Workload, container: Container) -> list[PolicyViolation]:
        if container.field == "ephemeralContainers":
            return []  # the API server forbids resources on ephemeral containers
        resources = mapping(container.spec.get("resources"))
        requests, limits = mapping(resources.get("requests")), mapping(resources.get("limits"))
        path = f"{container.path}/resources"
        manual = RemediationAdvice(summary=_RESOURCES_HINT, action="manual")
        label = f"container {container.name!r}"
        if not requests and not limits:
            return [
                self._violation(
                    workload,
                    "best-effort-container",
                    path,
                    f"{label} has no requests or limits (BestEffort)",
                    manual,
                )
            ]
        violations: list[PolicyViolation] = []
        for section, values, code in (
            ("requests", requests, "missing-resource-requests"),
            ("limits", limits, "missing-resource-limits"),
        ):
            if missing := [r for r in ("cpu", "memory") if r not in values]:
                violations.append(
                    self._violation(
                        workload,
                        code,
                        f"{path}/{section}",
                        f"{label} has no {section} for {missing}",
                        manual,
                    )
                )
        for resource, parse in _QUANTITY_PARSERS.items():
            amounts: dict[str, int] = {}
            for section, values in (("requests", requests), ("limits", limits)):
                if resource in values:
                    try:
                        amounts[section] = parse(str(values[resource]))
                    except ValueError:
                        violations.append(
                            self._violation(
                                workload,
                                "invalid-resource-quantity",
                                f"{path}/{section}/{resource}",
                                f"{label}: {values[resource]!r} is not a valid {resource} quantity",
                                manual,
                            )
                        )
            if len(amounts) == 2 and amounts["requests"] > amounts["limits"]:  # noqa: PLR2004
                violations.append(
                    self._violation(
                        workload,
                        "requests-exceed-limits",
                        f"{path}/requests/{resource}",
                        f"{label}: {resource} request {requests[resource]} "
                        f"exceeds limit {limits[resource]}",
                        manual,
                    )
                )
        return violations

    # -- image ----------------------------------------------------------------
    def _image(self, workload: Workload, container: Container) -> list[PolicyViolation]:
        image = container.spec.get("image")
        problem = image_problem(image)
        if problem is None:
            return []
        text = {
            "image-untagged": "has no tag or digest (resolves to :latest)",
            "image-latest-tag": "uses the mutable :latest tag",
            "image-invalid-digest": "has a malformed digest (expected sha256:<64 hex>)",
        }[problem]
        return [
            self._violation(
                workload,
                problem,
                f"{container.path}/image",
                f"container {container.name!r} image {image!r} {text}",
                RemediationAdvice(
                    summary="pin the image to an immutable version tag or, better, a sha256 digest",
                    action="manual",
                ),
            )
        ]
