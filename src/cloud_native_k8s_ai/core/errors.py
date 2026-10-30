"""Domain error hierarchy for the infrastructure compilation engine.

Every failure raised by ``cloud_native_k8s_ai.core`` derives from ``K8sAiCoreError`` so
callers can catch the engine as a whole, or one failure class precisely.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Violation:
    """One broken zero-trust or binding rule, with a stable machine-readable code."""

    code: str
    message: str

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"


class K8sAiCoreError(Exception):
    """Base class for every error raised by the core engine."""


class ManifestRenderError(K8sAiCoreError):
    """A manifest could not be built, serialized or parsed back."""


class ResourceConstraintError(K8sAiCoreError):
    """Replica bounds, timing windows or resource budgets are inconsistent."""


class TopologyConflictError(K8sAiCoreError):
    """Workloads, services and network policies do not form a valid zero-trust topology."""

    def __init__(self, message: str, violations: Sequence[Violation] = ()) -> None:
        self.violations: tuple[Violation, ...] = tuple(violations)
        detail = "".join(f"\n  - {v}" for v in self.violations)
        super().__init__(f"{message}{detail}")
