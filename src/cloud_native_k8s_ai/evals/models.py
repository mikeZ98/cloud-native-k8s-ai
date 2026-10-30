"""Structured, deterministic evaluation reports (camelCase on the wire).

Ratios are vacuously perfect when there is nothing to measure (no positives to find and
none predicted), so a suite that only contains benign samples reports precision and
recall of 1.0 rather than dividing by zero.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from pydantic import Field, computed_field

from cloud_native_k8s_ai.schemas import K8sModel


class EvalError(Exception):
    """The evaluation cannot run, e.g. the pristine bundle is not admitted."""


def _ratio(numerator: int, denominator: int) -> float:
    return 1.0 if denominator == 0 else numerator / denominator


class ConfusionMatrix(K8sModel):
    true_positives: int = Field(default=0, ge=0)
    false_positives: int = Field(default=0, ge=0)
    true_negatives: int = Field(default=0, ge=0)
    false_negatives: int = Field(default=0, ge=0)

    def add(self, *, actual: bool, predicted: bool) -> ConfusionMatrix:
        key = {
            (True, True): "true_positives",
            (False, True): "false_positives",
            (False, False): "true_negatives",
            (True, False): "false_negatives",
        }[(actual, predicted)]
        return self.model_copy(update={key: getattr(self, key) + 1})

    def merge(self, other: ConfusionMatrix) -> ConfusionMatrix:
        return ConfusionMatrix(
            true_positives=self.true_positives + other.true_positives,
            false_positives=self.false_positives + other.false_positives,
            true_negatives=self.true_negatives + other.true_negatives,
            false_negatives=self.false_negatives + other.false_negatives,
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def precision(self) -> float:
        return _ratio(self.true_positives, self.true_positives + self.false_positives)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def recall(self) -> float:
        return _ratio(self.true_positives, self.true_positives + self.false_negatives)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 0.0 if p + r == 0 else 2 * p * r / (p + r)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def accuracy(self) -> float:
        total = (
            self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        )
        return _ratio(self.true_positives + self.true_negatives, total)


class BenchmarkMetric(K8sModel):
    name: str
    value: float
    description: str


class OperatorStats(K8sModel):
    """How often an operator's ground truth was met (caught, or benign left alone)."""

    name: str
    category: str
    applied: int = 0
    met: int = 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rate(self) -> float:
        return _ratio(self.met, self.applied)


class SampleResult(K8sModel):
    index: int
    malicious: bool
    applied: tuple[str, ...]
    expected: tuple[str, ...] = ()
    detected: tuple[str, ...] = ()
    decision: str
    converged: bool | None = None
    regression_free: bool | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def missed(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.expected) - set(self.detected)))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def spurious(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.detected) - set(self.expected)))


class SuiteReport(K8sModel):
    """One evaluated population: manifests (guardrails) or specs (contracts + compiler)."""

    samples: int
    malicious: int
    detection: ConfusionMatrix
    """Sample level: malicious vs benign against flagged (manifests) or rejected (specs)."""
    codes: ConfusionMatrix | None = None
    """Code level (manifests): expected vs detected violation codes, summed over samples."""
    operators: tuple[OperatorStats, ...] = ()
    failures: tuple[SampleResult, ...] = ()
    """Samples whose ground truth was not met exactly."""


class EvalConfig(K8sModel):
    seed: int = 0
    samples: int = Field(default=200, ge=1, le=100_000)
    spec_samples: int = Field(default=50, ge=0, le=100_000)
    epsilon: float = Field(default=0.3, ge=0.0, le=1.0)
    """Perturbation budget: operators composed per sample = 1 + floor(epsilon * 4)."""
    benign_ratio: float = Field(default=0.25, ge=0.0, le=1.0)
    remediate: bool = True


class EvalReport(K8sModel):
    config: EvalConfig
    manifests: SuiteReport
    spec: SuiteReport | None = None
    metrics: tuple[BenchmarkMetric, ...]

    def metric(self, name: str) -> float:
        for item in self.metrics:
            if item.name == name:
                return item.value
        raise KeyError(f"no metric {name!r}; known: {[m.name for m in self.metrics]}")

    def unmet(self, thresholds: Mapping[str, float]) -> list[str]:
        """``name value < minimum`` for every threshold the report misses."""
        return [
            f"{name} {self.metric(name):.4f} < {minimum:.4f}"
            for name, minimum in sorted(thresholds.items())
            if self.metric(name) < minimum
        ]

    def to_text(self) -> str:
        width = max(len(m.name) for m in self.metrics)
        lines = [
            f"k8s-ai eval: {self.manifests.samples} manifest samples "
            f"({self.manifests.malicious} perturbed), "
            f"{self.spec.samples if self.spec else 0} spec samples, "
            f"seed {self.config.seed}, epsilon {self.config.epsilon}",
            *(f"  {m.name.ljust(width)}  {m.value:.4f}" for m in self.metrics),
        ]
        failures = [*self.manifests.failures, *(self.spec.failures if self.spec else ())]
        lines.append(f"  failures: {len(failures)}")
        lines += [
            f"    #{f.index} {'+'.join(f.applied)}: missed {list(f.missed)}, "
            f"spurious {list(f.spurious)}, decision {f.decision}"
            for f in failures[:MAX_LISTED_FAILURES]
        ]
        return "\n".join(lines)


MAX_LISTED_FAILURES: Final = 10
