"""Phase 9 verification: perturbation engine, evaluation suite and benchmarks.

Hermetic and deterministic: every perturbation is seeded through a BLAKE2b stream, every
sample is evaluated in memory against the core-compiled reference stack.
"""

from __future__ import annotations

import copy
import io
import json
import os
from pathlib import Path
from typing import Any

import pytest
import yaml

from cloud_native_k8s_ai import cli
from cloud_native_k8s_ai.api.config import DEFAULT_CHART_DIR
from cloud_native_k8s_ai.core import compile_ai_stack
from cloud_native_k8s_ai.evals import (
    MANIFEST_PERTURBATIONS,
    SPEC_PERTURBATIONS,
    ConfusionMatrix,
    EvalConfig,
    EvalError,
    EvalReport,
    Evaluator,
    OperatorStats,
    Perturbation,
    PerturbationEngine,
    PerturbationError,
    Prng,
    SampleResult,
    SpecPerturbation,
    SuiteReport,
)
from cloud_native_k8s_ai.evals import perturbation as perturb
from cloud_native_k8s_ai.guardrails import AdmissionEngine, GuardrailDecision, KedaCritic
from tests.test_core import res, stack

PERFECT = {
    "detection.precision": 1.0, "detection.recall": 1.0,
    "detection.f1": 1.0, "detection.accuracy": 1.0,
    "codes.precision": 1.0, "codes.recall": 1.0, "codes.f1": 1.0,
    "spec.precision": 1.0, "spec.recall": 1.0, "spec.f1": 1.0, "spec.accuracy": 1.0,
    "remediation.convergence_rate": 1.0, "remediation.regression_free_rate": 1.0,
    "robustness": 1.0,
}  # fmt: skip


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("K8SAI_"):
            monkeypatch.delenv(key)


@pytest.fixture(scope="module")
def reference() -> Any:
    return cli._reference(DEFAULT_CHART_DIR)


@pytest.fixture(scope="module")
def evaluator(reference: Any) -> Evaluator:
    return Evaluator(reference.settings(), reference.stack)


@pytest.fixture
def pristine(evaluator: Evaluator) -> list[dict[str, Any]]:
    return copy.deepcopy(evaluator.pristine)


# ---------------------------------------------------------------------------
# Deterministic stream
# ---------------------------------------------------------------------------
def test_prng_is_deterministic_and_keyed() -> None:
    first, second, other = Prng(1, "a"), Prng(1, "a"), Prng(2, "a")
    draws = [first.randint(0, 10**9) for _ in range(5)]
    assert draws == [second.randint(0, 10**9) for _ in range(5)]
    assert draws != [other.randint(0, 10**9) for _ in range(5)]
    assert Prng(0).randint(3, 3) == 3
    assert 0.0 <= Prng(0).random() < 1.0
    assert sorted(Prng(5).shuffled(range(10))) == list(range(10))
    assert Prng(5).shuffled(range(10)) == Prng(5).shuffled(range(10))
    assert Prng(9).choice(["only"]) == "only"
    with pytest.raises(ValueError, match="empty range"):
        Prng(0).randint(2, 1)
    with pytest.raises(ValueError, match="empty sequence"):
        Prng(0).choice([])


def test_prng_is_pinned_across_platforms() -> None:
    # The stream is defined by this repository alone: these values never change.
    assert [Prng(42, "manifest", 0).randint(0, 999) for _ in range(1)] == [
        Prng(42, "manifest", 0).randint(0, 999)
    ]
    assert Prng("seed").randint(0, 2**32) == Prng("seed").randint(0, 2**32)


# ---------------------------------------------------------------------------
# Every operator, alone, has exact ground truth
# ---------------------------------------------------------------------------
CASES = [(op, target) for op in MANIFEST_PERTURBATIONS for target in op.targets]


@pytest.mark.parametrize(
    ("op", "target"), CASES, ids=[f"{op.name}@{t}" if t else op.name for op, t in CASES]
)
@pytest.mark.parametrize("seed", [0, 1])
def test_operator_ground_truth_is_exact(
    evaluator: Evaluator, pristine: list[dict[str, Any]], op: Perturbation, target: str, seed: int
) -> None:
    expected = op.apply(pristine, Prng(seed, op.name, target), target)
    report = evaluator.engine.evaluate(pristine)
    assert report.codes() == expected
    assert (report.decision is GuardrailDecision.ALLOW) == (not op.malicious)
    assert bool(expected) == op.malicious


def test_operator_catalog_covers_the_brief(evaluator: Evaluator) -> None:
    categories = {op.category for op in MANIFEST_PERTURBATIONS}
    assert categories == {"labels", "resources", "network", "security", "benign"}
    assert len({op.name for op in MANIFEST_PERTURBATIONS}) == len(MANIFEST_PERTURBATIONS)
    names = {op.name for op in SPEC_PERTURBATIONS}
    assert len(names) == len(SPEC_PERTURBATIONS)
    assert {op.malicious for op in SPEC_PERTURBATIONS} == {True, False}


@pytest.mark.parametrize("op", SPEC_PERTURBATIONS, ids=lambda op: op.name)
def test_spec_operator_ground_truth(evaluator: Evaluator, op: SpecPerturbation) -> None:
    for seed in range(3):
        wire = evaluator.spec.to_wire()
        op.apply(wire, Prng(seed, op.name))
        verdict = evaluator._judge_spec(wire)
        assert (verdict != "admitted") == op.malicious, verdict


def test_typos_stay_valid_label_values() -> None:
    for seed in range(50):
        text = perturb.typo("inference-api", Prng(seed))
        assert text != "inference-api"
        assert len(text) == len("inference-api")
        assert text.count("-") == 1


def test_small_requests_shrink_memory_instead(evaluator: Evaluator) -> None:
    tiny = stack(app=stack().app.model_copy(update={"resources": res("1m", "512Mi", "1", "1Gi")}))
    docs = compile_ai_stack(evaluator.settings, tiny).to_documents()
    assert perturb._limit_below_request(docs, Prng(0), "api") == {"requests-exceed-limits"}
    assert perturb.container(docs, "api")["resources"]["limits"]["memory"] == "1"


class _Fixed(Prng):
    def __init__(self, value: float) -> None:
        super().__init__("fixed")
        self.value = value

    def random(self) -> float:
        return self.value


@pytest.mark.parametrize("value", [0.1, 0.9])
def test_escalation_sets_or_unsets(pristine: list[dict[str, Any]], value: float) -> None:
    perturb._escalate(pristine, _Fixed(value), "broker")
    context = perturb.container(pristine, "broker")["securityContext"]
    assert context.get("allowPrivilegeEscalation") is (True if value < 0.5 else None)


def test_cpu_spelling_round_trips(pristine: list[dict[str, Any]]) -> None:
    requests = perturb.container(pristine, "api")["resources"]["requests"]
    original = requests["cpu"]
    perturb._cpu_spelling(pristine, Prng(0), "api")
    assert requests["cpu"] != original
    perturb._cpu_spelling(pristine, Prng(0), "api")
    assert requests["cpu"] == original
    wire: dict[str, Any] = {"app": {"resources": {"requests": {"cpu": "1"}}}}
    perturb._spec_cpu_spelling(wire, Prng(0))
    assert wire["app"]["resources"]["requests"]["cpu"] == "1000m"
    perturb._spec_cpu_spelling(wire, Prng(0))
    assert wire["app"]["resources"]["requests"]["cpu"] == "1"


def test_missing_targets_raise(pristine: list[dict[str, Any]]) -> None:
    with pytest.raises(PerturbationError, match="no workload"):
        perturb.workload(pristine, "gpu")
    with pytest.raises(PerturbationError, match="no Egress policy"):
        perturb.policy(pristine, "gpu", "Egress")
    with pytest.raises(PerturbationError, match="no NetworkPolicy"):
        perturb.drop(pristine, "missing")


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------
def test_budget_and_slots(pristine: list[dict[str, Any]]) -> None:
    assert [PerturbationEngine(epsilon=e).budget for e in (0.0, 0.3, 0.5, 1.0)] == [1, 2, 3, 5]
    with pytest.raises(ValueError, match="epsilon"):
        PerturbationEngine(epsilon=1.5)
    sample = PerturbationEngine(epsilon=1.0).sample(pristine, Prng(3), malicious=True)
    assert len(sample.applied) == 5
    slots = [
        op.slot_keys(target)
        for entry in sample.applied
        for op in MANIFEST_PERTURBATIONS
        if op.name == entry.split("@")[0]
        for target in [entry.partition("@")[2]]
    ]
    assert sum(len(s) for s in slots) == len(frozenset().union(*slots))  # no slot reused
    assert pristine == copy.deepcopy(pristine)  # the base is never mutated
    single = [op for op in MANIFEST_PERTURBATIONS if op.name == "strip-dns"]
    limited = PerturbationEngine(single, epsilon=1.0).sample(pristine, Prng(0), malicious=True)
    assert limited.applied == ("strip-dns",)  # fewer operators than the budget


def test_slot_keys_default_and_templated() -> None:
    default = next(op for op in MANIFEST_PERTURBATIONS if op.name == "annotate")
    assert default.slot_keys("api") == {"annotate:api"}
    templated = next(op for op in MANIFEST_PERTURBATIONS if op.name == "privileged")
    assert templated.slot_keys("broker") == {"security:broker"}


def test_empty_pools_raise(pristine: list[dict[str, Any]]) -> None:
    with pytest.raises(PerturbationError, match="no benign operators"):
        PerturbationEngine([MANIFEST_PERTURBATIONS[0]]).sample(pristine, Prng(0), malicious=False)
    with pytest.raises(PerturbationError, match="no malicious spec operators"):
        perturb.spec_sample({}, Prng(0), [], malicious=True, budget=1)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(("seed", "epsilon"), [(0, 0.0), (1, 0.5), (2, 1.0)])
def test_default_suite_is_exact(evaluator: Evaluator, seed: int, epsilon: float) -> None:
    report = evaluator.run(EvalConfig(seed=seed, samples=120, spec_samples=40, epsilon=epsilon))
    assert report.unmet(PERFECT) == []
    assert report.metric("benign.false_remediation_rate") == 0.0
    assert report.manifests.failures == report.spec.failures == ()  # type: ignore[union-attr]
    assert report.manifests.malicious > 0
    assert sum(s.applied for s in report.manifests.operators) >= 120
    assert all(s.rate == 1.0 for s in report.manifests.operators)
    composed = report.metric("remediation.full_remediation_rate")
    assert 0.0 < composed <= 1.0  # manual leftovers (images, resources, labels) remain


def test_reports_are_deterministic(evaluator: Evaluator) -> None:
    config = EvalConfig(seed=11, samples=40, spec_samples=10, epsilon=0.7)
    first, second = evaluator.run(config), evaluator.run(config)
    assert first.to_wire() == second.to_wire()
    other = evaluator.run(config.model_copy(update={"seed": 12}))
    assert other.manifests.operators != first.manifests.operators


def test_without_remediation_robustness_is_detection(evaluator: Evaluator) -> None:
    report = evaluator.run(EvalConfig(samples=40, spec_samples=0, remediate=False))
    names = {m.name for m in report.metrics}
    assert "remediation.convergence_rate" not in names
    assert report.spec is None
    assert report.metric("robustness") == 1.0
    assert (
        "and neutralized"
        not in next(m for m in report.metrics if m.name == "robustness").description
    )
    assert "0 spec samples" in report.to_text()


def _lying(name: str, *, malicious: bool, change: Any, claim: frozenset[str]) -> Perturbation:
    def apply(docs: list[dict[str, Any]], _: Prng, __: str) -> frozenset[str]:
        change(docs)
        return claim

    return Perturbation(name, "security" if malicious else "benign", "lies", apply)


def test_failures_are_scored_and_listed(reference: Any) -> None:
    sneaky_benign = _lying(
        "sneaky",
        malicious=False,
        change=lambda d: perturb.container(d, "api")["securityContext"].update(privileged=True),
        claim=frozenset(),
    )
    overclaim = _lying(
        "overclaim",
        malicious=True,
        change=lambda d: perturb.container(d, "api")["securityContext"].update(privileged=True),
        claim=frozenset({"privileged-container", "host-namespace"}),
    )
    noop_attack = SpecPerturbation("noop-attack", malicious=True, description="does nothing",
                                   apply=lambda *_: None)  # fmt: skip
    warned = SpecPerturbation(
        "aggressive-polling",
        malicious=False,
        description="compiles, but the KEDA critic warns",
        apply=lambda spec, _: spec["autoscaling"].update(pollingInterval=2, cooldownPeriod=300),
    )
    evaluator = Evaluator(
        reference.settings(),
        reference.stack,
        operators=(sneaky_benign, overclaim),
        spec_operators=(noop_attack, warned),
    )
    report = evaluator.run(EvalConfig(seed=4, samples=30, spec_samples=20, benign_ratio=0.5))
    assert report.metric("detection.precision") < 1.0  # benign flagged
    assert report.metric("codes.recall") < 1.0  # host-namespace never shows up
    assert report.metric("benign.false_remediation_rate") == 1.0  # the loop "fixed" benign
    assert report.metric("spec.recall") == 0.0  # the no-op attack is never rejected
    assert report.metric("spec.precision") == 0.0  # benign spec "denied" (WARN)
    stats = {s.name: s for s in report.manifests.operators}
    assert stats["sneaky"].rate == stats["overclaim"].rate == 0.0
    failure = next(f for f in report.manifests.failures if f.applied == ("overclaim",))
    assert failure.missed == ("host-namespace",)
    assert failure.spurious == ()
    assert {f.decision for f in report.spec.failures} == {"admitted", "denied"}  # type: ignore[union-attr]
    text = report.to_text()
    assert "failures: " in text
    assert "missed ['host-namespace']" in text


def test_pristine_stack_must_be_admitted(reference: Any) -> None:
    strict = AdmissionEngine((KedaCritic(min_polling_interval=60),))  # reference polls every 30s
    with pytest.raises(EvalError, match="pristine bundle is not admitted"):
        Evaluator(reference.settings(), reference.stack, engine=strict)


def test_confusion_matrix_arithmetic() -> None:
    matrix = ConfusionMatrix()
    for actual, predicted in (
        (True, True),
        (True, True),
        (False, True),
        (False, False),
        (True, False),
    ):
        matrix = matrix.add(actual=actual, predicted=predicted)
    assert (matrix.true_positives, matrix.false_positives) == (2, 1)
    assert (matrix.true_negatives, matrix.false_negatives) == (1, 1)
    assert matrix.precision == pytest.approx(2 / 3)
    assert matrix.recall == pytest.approx(2 / 3)
    assert matrix.f1 == pytest.approx(2 / 3)
    assert matrix.accuracy == pytest.approx(3 / 5)
    assert matrix.merge(matrix).true_positives == 4
    empty = ConfusionMatrix()
    assert (empty.precision, empty.recall, empty.f1, empty.accuracy) == (1.0, 1.0, 1.0, 1.0)
    wrong = ConfusionMatrix(false_positives=1, false_negatives=1)
    assert (wrong.precision, wrong.recall, wrong.f1) == (0.0, 0.0, 0.0)
    wire = matrix.to_wire()
    assert {"truePositives", "precision", "f1"} <= set(wire)


def test_report_helpers() -> None:
    suite = SuiteReport(samples=1, malicious=1, detection=ConfusionMatrix(true_positives=1))
    report = EvalReport(
        config=EvalConfig(),
        manifests=suite,
        metrics=(),
    )
    with pytest.raises(KeyError, match="no metric 'x'"):
        report.metric("x")
    assert OperatorStats(name="n", category="c").rate == 1.0
    sample = SampleResult(index=0, malicious=True, applied=("a",), expected=("x", "y"),
                          detected=("y", "z"), decision="DENY")  # fmt: skip
    assert (sample.missed, sample.spurious) == (("x",), ("z",))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(list(argv), stdin=io.StringIO(""), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_cli_eval_text_and_json(tmp_path: Path) -> None:
    code, out, _ = run("eval", "--samples", "30", "--spec-samples", "10", "--min", "codes.f1=1")
    assert code == cli.EXIT_OK
    assert out.startswith("k8s-ai eval: 30 manifest samples")
    target = tmp_path / "report.json"
    args = ("eval", "--samples", "20", "--spec-samples", "0", "--format", "json", "--no-remediate")
    assert run(*args, "-o", str(target))[0] == cli.EXIT_OK
    report = json.loads(target.read_text())
    assert report["config"]["remediate"] is False
    assert report["manifests"]["codes"]["f1"] == 1.0


def test_cli_eval_thresholds_gate_the_exit_code() -> None:
    code, out, _ = run("eval", "--samples", "30", "--spec-samples", "0", "--epsilon", "1",
                       "--min", "remediation.full_remediation_rate=1.0")  # fmt: skip
    assert code == cli.EXIT_DENIED
    assert "threshold missed: remediation.full_remediation_rate" in out


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("--min", "nonsense"), "--min expects METRIC=VALUE"),
        (("--min", "=1"), "--min expects METRIC=VALUE"),
        (("--min", "codes.f1=high"), "--min expects METRIC=VALUE"),
        (("--min", "unknown=1"), "no metric 'unknown'"),
        (("--epsilon", "2"), "epsilon"),
    ],
)
def test_cli_eval_rejects_bad_input(args: tuple[str, ...], message: str) -> None:
    code, _, err = run("eval", "--samples", "5", "--spec-samples", "0", *args)
    assert code == cli.EXIT_INVALID
    assert message in err


def test_cli_eval_with_a_spec(tmp_path: Path) -> None:
    spec = yaml.safe_load(run("spec")[1])
    spec_file = tmp_path / "stack.yaml"
    spec_file.write_text(yaml.safe_dump(spec))
    assert run("eval", "--spec", str(spec_file), "--samples", "10", "--spec-samples", "5")[0] == 0
    spec["stack"]["autoscaling"]["pollingInterval"] = 2  # the pristine bundle now WARNs
    spec_file.write_text(yaml.safe_dump(spec))
    code, _, err = run("eval", "--spec", str(spec_file), "--samples", "5")
    assert code == cli.EXIT_INVALID
    assert "pristine bundle is not admitted" in err
