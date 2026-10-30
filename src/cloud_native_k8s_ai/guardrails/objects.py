"""Read raw (untyped, possibly non-compliant) manifests: pod templates, containers, selectors.

Every accessor tolerates missing or malformed fields: admission must judge whatever was
submitted, so nothing here assumes a document passed schema validation.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from pydantic import ValidationError

from cloud_native_k8s_ai.guardrails.models import ObjectRef
from cloud_native_k8s_ai.schemas import LabelSelector

DEFAULT_NAMESPACE: Final = "default"
"""Namespace Kubernetes assigns to namespaced objects submitted without one."""

_POD_SPEC_PATHS: Final[Mapping[str, tuple[str, ...]]] = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}
CONTAINER_LISTS: Final = ("initContainers", "containers", "ephemeralContainers")


def mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def sequence(value: Any) -> Sequence[Any]:
    return value if isinstance(value, list | tuple) else ()


def dig(document: Any, *keys: str) -> Any:
    for key in keys:
        document = mapping(document).get(key)
    return document


def namespace_of(document: Mapping[str, Any]) -> str:
    return str(dig(document, "metadata", "namespace") or DEFAULT_NAMESPACE)


def pointer(*parts: str | int) -> str:
    """RFC 6901 JSON pointer from path segments."""
    return "".join(f"/{str(p).replace('~', '~0').replace('/', '~1')}" for p in parts)


@dataclass(frozen=True, slots=True)
class Container:
    spec: Mapping[str, Any]
    path: str
    """JSON pointer of the container inside its document."""
    field: str
    """``containers``, ``initContainers`` or ``ephemeralContainers``."""

    @property
    def name(self) -> str:
        return str(self.spec.get("name", "?"))


@dataclass(frozen=True, slots=True)
class Workload:
    """A pod-producing object as admission sees it."""

    document: Mapping[str, Any]
    ref: ObjectRef
    namespace: str
    pod_path: str
    pod_spec: Mapping[str, Any]
    pod_labels: Mapping[str, str]
    selector_labels: Mapping[str, str]
    """``spec.selector.matchLabels`` (the pod labels themselves for a bare Pod)."""

    def containers(self) -> Iterator[Container]:
        for field in CONTAINER_LISTS:
            for index, spec in enumerate(sequence(self.pod_spec.get(field))):
                yield Container(mapping(spec), f"{self.pod_path}{pointer(field, index)}", field)

    def container_ports(self) -> dict[str | int, int]:
        """Port name and number -> number, for every declared container port."""
        ports: dict[str | int, int] = {}
        for container in self.containers():
            for port in sequence(container.spec.get("ports")):
                number = mapping(port).get("containerPort")
                if isinstance(number, int):
                    ports[number] = number
                    if isinstance(name := mapping(port).get("name"), str):
                        ports[name] = number
        return ports

    def replicas(self) -> int:
        value = dig(self.document, "spec", "replicas")
        return value if isinstance(value, int) and not isinstance(value, bool) else 1


def workload(document: Mapping[str, Any]) -> Workload | None:
    path = _POD_SPEC_PATHS.get(str(document.get("kind")))
    if path is None:
        return None
    template_path = path[:-1]
    labels = _string_map(
        dig(document, *template_path, "metadata", "labels")
        if template_path
        else dig(document, "metadata", "labels")
    )
    selector = (
        _string_map(dig(document, "spec", "selector", "matchLabels")) if template_path else labels
    )
    return Workload(
        document=document,
        ref=ObjectRef.of(document),
        namespace=namespace_of(document),
        pod_path=pointer(*path),
        pod_spec=mapping(dig(document, *path)),
        pod_labels=labels,
        selector_labels=selector,
    )


def workloads(documents: Sequence[Mapping[str, Any]]) -> list[Workload]:
    return [w for d in documents if (w := workload(d)) is not None]


def _string_map(value: Any) -> dict[str, str]:
    return {str(k): str(v) for k, v in mapping(value).items()}


def selector(raw: Any) -> LabelSelector | None:
    """A typed selector from raw input (``None`` if it is not a valid selector)."""
    if raw is None:
        return LabelSelector()
    try:
        return LabelSelector.from_wire(mapping(raw)) if isinstance(raw, Mapping) else None
    except ValidationError:
        return None


def selects_everything(raw: Any) -> bool:
    parsed = selector(raw)
    return parsed is not None and not parsed.match_labels and not parsed.match_expressions
