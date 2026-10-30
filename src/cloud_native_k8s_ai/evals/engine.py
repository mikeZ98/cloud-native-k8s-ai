"""Evaluator: score guardrails, the critic loop and the contracts against perturbations.

Manifest suite. Each sample perturbs the pristine compiled bundle (benign with probability
``benign_ratio``) and runs the admission engine on it:

* *detection* (sample level): perturbed samples must be flagged (not ALLOW), benign ones
  admitted;
* *codes* (violation level): expected vs detected codes, summed over samples, so a
  spurious or missing code costs precision or recall even when the sample was flagged;
* *remediation*: the critic loop must converge and never end with a code that was not
  there before (*regression free*); benign samples must not be touched at all;
* *robustness*: perturbed samples caught with every expected code whose remediation
  (when enabled) converged without regression, over all perturbed samples.

Spec suite. Perturbed ``AIStackSpec`` wire forms must be rejected by the contracts or the
compiler; benign ones must compile and be admitted.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from cloud_native_k8s_ai.core import AIStackSpec, K8sAiCoreError, compile_ai_stack
from cloud_native_k8s_ai.evals.models import (
    BenchmarkMetric,
    ConfusionMatrix,
    EvalConfig,
    EvalError,
    EvalReport,
    OperatorStats,
    SampleResult,
    SuiteReport,
)
from cloud_native_k8s_ai.evals.perturbation import (
    MANIFEST_PERTURBATIONS,
    SPEC_PERTURBATIONS,
    Perturbation,
    PerturbationEngine,
    SpecPerturbation,
    spec_sample,
)
from cloud_native_k8s_ai.evals.prng import Prng
from cloud_native_k8s_ai.guardrails import AdmissionEngine, GuardrailDecision
from cloud_native_k8s_ai.schemas import InfraSettings


@dataclass
class _Remediation:
    malicious: int = 0
    converged: int = 0
    regression_free: int = 0
    fully_remediated: int = 0
    robust: int = 0
    benign: int = 0
    false_remediations: int = 0


@dataclass
class _Tally:
    stats: dict[str, OperatorStats] = field(default_factory=dict)

    def count(self, applied: Sequence[str], categories: Mapping[str, str], *, met: bool) -> None:
        for entry in applied:
            name = entry.split("@", 1)[0]
            current = self.stats.get(name) or OperatorStats(name=name, category=categories[name])
            self.stats[name] = current.model_copy(
                update={"applied": current.applied + 1, "met": current.met + int(met)}
            )

    def sorted(self) -> tuple[OperatorStats, ...]:
        return tuple(self.stats[name] for name in sorted(self.stats))


def _ratio(numerator: int, denominator: int) -> float:
    return 1.0 if denominator == 0 else numerator / denominator


class Evaluator:
    """Evaluate one stack: its pristine bundle must be admitted before anything is scored."""

    def __init__(
        self,
        settings: InfraSettings,
        spec: AIStackSpec,
        *,
        engine: AdmissionEngine | None = None,
        operators: Sequence[Perturbation] = MANIFEST_PERTURBATIONS,
        spec_operators: Sequence[SpecPerturbation] = SPEC_PERTURBATIONS,
    ) -> None:
        self.settings = settings
        self.spec = spec
        self.engine = engine or AdmissionEngine.for_stack(settings, spec)
        self.operators = tuple(operators)
        self.spec_operators = tuple(spec_operators)
        self.pristine = compile_ai_stack(settings, spec).to_documents()
        baseline = self.engine.evaluate(self.pristine)
        if baseline.decision is not GuardrailDecision.ALLOW:
            raise EvalError(f"pristine bundle is not admitted: {sorted(baseline.codes())}")

    def run(self, config: EvalConfig) -> EvalReport:
        manifests, remediation = self._manifests(config)
        spec = self._specs(config) if config.spec_samples else None
        return EvalReport(
            config=config,
            manifests=manifests,
            spec=spec,
            metrics=self._metrics(manifests, remediation, spec, config),
        )

    # -- manifests --------------------------------------------------------------
    def _manifests(self, config: EvalConfig) -> tuple[SuiteReport, _Remediation]:
        perturber = PerturbationEngine(self.operators, config.epsilon)
        categories = {op.name: op.category for op in self.operators}
        detection, codes = ConfusionMatrix(), ConfusionMatrix()
        tally, remediation = _Tally(), _Remediation()
        failures: list[SampleResult] = []
        malicious_count = 0
        for index in range(config.samples):
            prng = Prng(config.seed, "manifest", index)
            malicious = prng.random() >= config.benign_ratio
            malicious_count += malicious
            sample = perturber.sample(self.pristine, prng, malicious=malicious)
            report = self.engine.evaluate(sample.documents)
            detected = report.codes()
            flagged = report.decision is not GuardrailDecision.ALLOW
            detection = detection.add(actual=malicious, predicted=flagged)
            codes = codes.merge(
                ConfusionMatrix(
                    true_positives=len(sample.expected & detected),
                    false_positives=len(detected - sample.expected),
                    false_negatives=len(sample.expected - detected),
                )
            )
            met = detected == sample.expected and flagged == malicious
            result = SampleResult(
                index=index,
                malicious=malicious,
                applied=sample.applied,
                expected=tuple(sorted(sample.expected)),
                detected=tuple(sorted(detected)),
                decision=report.decision.value,
            )
            if config.remediate:
                outcome = self.engine.remediate(sample.documents)
                if malicious:
                    converged = outcome.converged
                    clean = outcome.final.codes() <= outcome.initial.codes()
                    remediation.malicious += 1
                    remediation.converged += converged
                    remediation.regression_free += clean
                    remediation.fully_remediated += (
                        outcome.final.decision is GuardrailDecision.ALLOW
                    )
                    remediation.robust += sample.expected <= detected and converged and clean
                    result = result.model_copy(
                        update={"converged": converged, "regression_free": clean}
                    )
                    met = met and converged and clean
                else:
                    remediation.benign += 1
                    remediation.false_remediations += bool(outcome.rounds)
                    met = met and not outcome.rounds
            elif malicious:
                remediation.malicious += 1
                remediation.robust += sample.expected <= detected
            tally.count(sample.applied, categories, met=met)
            if not met:
                failures.append(result)
        suite = SuiteReport(
            samples=config.samples,
            malicious=malicious_count,
            detection=detection,
            codes=codes,
            operators=tally.sorted(),
            failures=tuple(failures),
        )
        return suite, remediation

    # -- specs ----------------------------------------------------------------------
    def _specs(self, config: EvalConfig) -> SuiteReport:
        base = self.spec.to_wire()
        budget = PerturbationEngine(self.operators, config.epsilon).budget
        categories = {op.name: "spec" for op in self.spec_operators}
        detection, tally = ConfusionMatrix(), _Tally()
        failures: list[SampleResult] = []
        malicious_count = 0
        for index in range(config.spec_samples):
            prng = Prng(config.seed, "spec", index)
            malicious = prng.random() >= config.benign_ratio
            malicious_count += malicious
            wire, applied = spec_sample(
                base, prng, self.spec_operators, malicious=malicious, budget=budget
            )
            verdict = self._judge_spec(wire)
            refused = verdict != "admitted"
            detection = detection.add(actual=malicious, predicted=refused)
            met = refused == malicious
            tally.count(applied, categories, met=met)
            if not met:
                failures.append(
                    SampleResult(
                        index=index, malicious=malicious, applied=applied, decision=verdict
                    )
                )
        return SuiteReport(
            samples=config.spec_samples,
            malicious=malicious_count,
            detection=detection,
            operators=tally.sorted(),
            failures=tuple(failures),
        )

    def _judge_spec(self, wire: dict[str, Any]) -> str:
        """``rejected:<Error>``, ``denied`` (compiled but not admitted) or ``admitted``."""
        try:
            spec = AIStackSpec.from_wire(wire)
            bundle = compile_ai_stack(self.settings, spec)
        except (ValidationError, K8sAiCoreError) as exc:
            return f"rejected:{type(exc).__name__}"
        report = AdmissionEngine.for_stack(self.settings, spec).evaluate(bundle)
        return "admitted" if report.decision is GuardrailDecision.ALLOW else "denied"

    # -- metrics --------------------------------------------------------------------
    @staticmethod
    def _metrics(
        manifests: SuiteReport,
        remediation: _Remediation,
        spec: SuiteReport | None,
        config: EvalConfig,
    ) -> tuple[BenchmarkMetric, ...]:
        metrics: list[tuple[str, float, str]] = []
        for prefix, matrix, what in (
            ("detection", manifests.detection, "perturbed manifests flagged, benign admitted"),
            ("codes", manifests.codes, "expected violation codes reported exactly"),
            ("spec", spec.detection if spec else None, "perturbed specs rejected, benign admitted"),
        ):
            if matrix is None:
                continue
            metrics += [
                (f"{prefix}.precision", matrix.precision, f"precision: {what}"),
                (f"{prefix}.recall", matrix.recall, f"recall: {what}"),
                (f"{prefix}.f1", matrix.f1, f"F1: {what}"),
                (f"{prefix}.accuracy", matrix.accuracy, f"accuracy: {what}"),
            ]
        if config.remediate:
            untouched = _ratio(
                remediation.benign - remediation.false_remediations, remediation.benign
            )
            metrics += [
                ("remediation.convergence_rate",
                 _ratio(remediation.converged, remediation.malicious),
                 "critic loop left no automatic remediation pending"),
                ("remediation.regression_free_rate",
                 _ratio(remediation.regression_free, remediation.malicious),
                 "critic loop never ended with a code absent before it ran"),
                ("remediation.full_remediation_rate",
                 _ratio(remediation.fully_remediated, remediation.malicious),
                 "perturbed samples fully admitted after the critic loop (no manual items)"),
                ("benign.false_remediation_rate",
                 1.0 - untouched,
                 "benign samples the critic loop changed (should be 0)"),
            ]  # fmt: skip
        metrics.append(
            (
                "robustness",
                _ratio(remediation.robust, remediation.malicious),
                "perturbed samples caught with every expected code"
                + (" and neutralized without regression" if config.remediate else ""),
            )
        )
        return tuple(BenchmarkMetric(name=n, value=v, description=d) for n, v, d in metrics)
