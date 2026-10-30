"""Phase 6 verification: admission guardrails, zero-trust network critic, autoscaling
safety and the auto-remediation critic loop.

Hermetic and deterministic: every scenario starts from a core-compiled bundle, mutates
its raw documents in memory and runs the guardrails; nothing touches a cluster.
"""

from __future__ import annotations

import copy
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import pytest

from cloud_native_k8s_ai.core import (
    AIStackGenerator,
    ManifestBundle,
    ManifestRenderError,
    TopologySolver,
    compile_ai_stack,
    render_yaml,
)
from cloud_native_k8s_ai.guardrails import (
    DEFAULT_GUARDRAILS,
    AdmissionDeniedError,
    AdmissionEngine,
    AdmissionReport,
    GuardrailDecision,
    GuardrailError,
    JsonPatchOp,
    KedaCritic,
    NetworkCritic,
    ObjectRef,
    PolicyViolation,
    RemediationAdvice,
    WorkloadGuardrail,
    apply_patch,
    apply_remediations,
    critic_loop,
    evaluate_manifests,
    image_problem,
    load_documents,
)
from cloud_native_k8s_ai.schemas import InfraSettings
from tests.test_core import stack

NS = "ai-system"
API, QDRANT, REDIS = "inference-api", "qdrant", "redis"
DIGEST = "sha256:" + "a" * 64
type Docs = list[dict[str, Any]]


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("K8SAI_"):
            monkeypatch.delenv(key)


@pytest.fixture(scope="module")
def bundle() -> ManifestBundle:
    return compile_ai_stack(InfraSettings(), stack())


@pytest.fixture
def docs(bundle: ManifestBundle) -> Docs:
    return copy.deepcopy(bundle.to_documents())


def find(docs: Docs, kind: str, name: str) -> dict[str, Any]:
    return next(d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name)


def without(docs: Docs, *names: str) -> Docs:
    return [d for d in docs if d["metadata"]["name"] not in names or d["kind"] != "NetworkPolicy"]


def pod(docs: Docs, kind: str = "Deployment", name: str = API) -> dict[str, Any]:
    spec: dict[str, Any] = find(docs, kind, name)["spec"]["template"]["spec"]
    return spec


def container(docs: Docs, kind: str = "Deployment", name: str = API) -> dict[str, Any]:
    first: dict[str, Any] = pod(docs, kind, name)["containers"][0]
    return first


def codes(violations: Sequence[PolicyViolation]) -> set[str]:
    return {v.code for v in violations}


def zero_trust_ok(docs: Docs) -> bool:
    """Cross-check with the core topology solver on the typed bundle."""
    generator = AIStackGenerator(InfraSettings(), stack())
    typed = ManifestBundle.from_yaml(render_yaml(docs))
    return TopologySolver(generator.topology(typed)).verify(generator.intent()).ok


# ---------------------------------------------------------------------------
# Models and patches
# ---------------------------------------------------------------------------
def test_decision_ordering() -> None:
    assert GuardrailDecision.worst([]) is GuardrailDecision.ALLOW
    assert (
        GuardrailDecision.worst([GuardrailDecision.WARN, GuardrailDecision.ALLOW])
        is GuardrailDecision.WARN
    )
    assert GuardrailDecision.worst(list(GuardrailDecision)) is GuardrailDecision.DENY
    assert [d.rank for d in GuardrailDecision] == [0, 1, 2]


def test_object_ref_tolerates_malformed_documents() -> None:
    assert ObjectRef.of({"kind": "Pod", "metadata": []}) == ObjectRef(kind="Pod", name="?")
    assert str(ObjectRef.of({})) == "? -/?"
    assert str(ObjectRef(kind="Service", namespace="n", name="a")) == "Service n/a"


def _violation(
    decision: GuardrailDecision, advice: RemediationAdvice | None = None
) -> PolicyViolation:
    return PolicyViolation(
        code="x",
        policy="test",
        decision=decision,  # type: ignore[arg-type]
        target=ObjectRef(kind="Pod", namespace="n", name="p"),
        message="m",
        remediation=advice or RemediationAdvice(summary="s", action="manual"),
    )


def test_report_aggregation_and_denial() -> None:
    documents = [
        {"kind": "Pod", "metadata": {"name": "p", "namespace": "n"}},
        {"kind": "Pod", "metadata": {"name": "q"}},
    ]
    warn = AdmissionReport.build(documents, [_violation(GuardrailDecision.WARN)])
    assert (warn.decision, warn.allowed) == (GuardrailDecision.WARN, True)
    assert [o.decision for o in warn.objects] == [GuardrailDecision.WARN, GuardrailDecision.ALLOW]
    warn.raise_for_denial()
    deny = AdmissionReport.build(
        documents, [_violation(GuardrailDecision.DENY), _violation(GuardrailDecision.WARN)]
    )
    assert deny.codes() == {"x"}
    with pytest.raises(AdmissionDeniedError, match=r"1 blocking violation\(s\)") as info:
        deny.raise_for_denial()
    assert info.value.report is deny
    assert info.value.remediation is None
    assert str(deny.violations[0]) == "[DENY] x Pod n/p: m"


def test_apply_patch_operations() -> None:
    document = {"a": {"b": [1, 2]}, "x/y": {"~": 1}}
    patched = apply_patch(
        document,
        [
            JsonPatchOp(op="add", path="/a/b/-", value=3),
            JsonPatchOp(op="add", path="/a/b/0", value=0),
            JsonPatchOp(op="replace", path="/a/b/1", value=9),
            JsonPatchOp(op="remove", path="/a/b/2"),
            JsonPatchOp(op="add", path="/a/c", value={"d": True}),
            JsonPatchOp(op="replace", path="/x~1y/~0", value=2),
            JsonPatchOp(op="remove", path="/a/c"),
        ],
    )
    assert patched == {"a": {"b": [0, 9, 3]}, "x/y": {"~": 2}}
    assert document == {"a": {"b": [1, 2]}, "x/y": {"~": 1}}  # never mutated
    assert apply_patch(document, [JsonPatchOp(op="replace", path="", value={"z": 1})]) == {"z": 1}


@pytest.mark.parametrize(
    ("op", "message"),
    [
        (JsonPatchOp(op="add", path="a"), "invalid JSON pointer"),
        (JsonPatchOp(op="replace", path="/missing", value=1), "does not exist"),
        (JsonPatchOp(op="remove", path="/missing"), "does not exist"),
        (JsonPatchOp(op="add", path="/missing/x", value=1), "does not exist"),
        (JsonPatchOp(op="remove", path="/list/5"), "out of range"),
        (JsonPatchOp(op="add", path="/list/x", value=1), "out of range"),
        (JsonPatchOp(op="add", path="/scalar/x", value=1), "not a container"),
        (JsonPatchOp(op="remove", path=""), "cannot remove the whole document"),
        (JsonPatchOp(op="replace", path="", value=[1]), "non-object"),
    ],
)
def test_apply_patch_errors(op: JsonPatchOp, message: str) -> None:
    with pytest.raises(GuardrailError, match=message):
        apply_patch({"list": [1], "scalar": 3}, [op])


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
def test_clean_bundle_is_allowed_from_every_input_form(bundle: ManifestBundle) -> None:
    engine = AdmissionEngine()
    for manifests in (bundle, bundle.to_yaml(), bundle.to_documents()):
        report = engine.evaluate(manifests)
        assert report.decision is GuardrailDecision.ALLOW
        assert report.violations == ()
        assert len(report.objects) == 15
        assert {o.decision for o in report.objects} == {GuardrailDecision.ALLOW}
    assert engine.admit(bundle).allowed
    assert evaluate_manifests(bundle).allowed
    assert [g.name for g in DEFAULT_GUARDRAILS] == [
        "workload-security",
        "network-zero-trust",
        "autoscaling",
    ]


def test_load_documents_rejects_bad_input(docs: Docs) -> None:
    with pytest.raises(GuardrailError, match="must be a mapping"):
        load_documents([docs[0], ["not", "a", "mapping"]])  # type: ignore[list-item]
    with pytest.raises(ManifestRenderError, match="anchors and aliases"):
        load_documents("a: &x 1\nb: *x\n")
    loaded = load_documents(docs)
    loaded[0]["kind"] = "Changed"
    assert docs[0]["kind"] == "NetworkPolicy"


def regressed(docs: Docs) -> Docs:
    """One regression per policy family: workload, network, autoscaling."""
    broken = without(copy.deepcopy(docs), "default-deny-all")
    find(broken, "NetworkPolicy", "qdrant-allow-from-app")["spec"]["ingress"][0]["from"] = [
        {"podSelector": {}}
    ]
    api = container(broken)
    del api["securityContext"]
    api["image"] = "ghcr.io/x/api:latest"
    del api["resources"]["limits"]
    scaled = find(broken, "ScaledObject", API)["spec"]
    scaled["cooldownPeriod"] = 10
    scaled["triggers"][0]["metadata"]["listLength"] = "0"
    egress = find(broken, "NetworkPolicy", f"{API}-allow-egress")["spec"]["egress"]
    egress.append({"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]})
    find(broken, "NetworkPolicy", f"{REDIS}-allow-ingress")["spec"]["ingress"][0]["from"].append(
        {"namespaceSelector": {}}
    )
    return broken


def test_multi_policy_regressions_are_consolidated(docs: Docs) -> None:
    report = AdmissionEngine().evaluate(regressed(docs))
    assert report.decision is GuardrailDecision.DENY
    assert {v.policy for v in report.violations} == {
        "workload-security",
        "network-zero-trust",
        "autoscaling",
    }
    assert report.codes() == {
        "writable-root-filesystem",  # runAsNonRoot is still inherited from the pod
        "privilege-escalation-allowed",
        "capabilities-not-dropped",
        "missing-resource-limits",
        "image-latest-tag",
        "qdrant-ingress-not-exclusive",
        "external-egress",
        "cross-namespace-ingress",
        "missing-default-deny-ingress",
        "missing-default-deny-egress",
        "keda-cooldown-below-polling",
        "keda-threshold-not-positive",
    }
    decisions = {(o.target.kind, o.target.name): o.decision for o in report.objects}
    assert decisions[("Deployment", API)] is GuardrailDecision.DENY
    assert decisions[("Service", QDRANT)] is GuardrailDecision.ALLOW
    with pytest.raises(AdmissionDeniedError, match="admission denied"):
        AdmissionEngine().admit(regressed(docs))


def test_remediation_loop_fixes_everything_automatic(docs: Docs) -> None:
    broken = regressed(docs)
    result = AdmissionEngine().remediate(broken)
    assert result.initial.decision is GuardrailDecision.DENY
    assert result.converged
    assert len(result.rounds) == 1
    assert result.final.codes() == {
        "missing-resource-limits",
        "image-latest-tag",
        "keda-threshold-not-positive",
    }
    assert all(not v.remediation.automatic for v in result.final.violations)
    fixed = list(result.documents)
    assert container(fixed)["securityContext"]["readOnlyRootFilesystem"] is True
    assert find(fixed, "NetworkPolicy", "default-deny-all")["spec"]["policyTypes"] == [
        "Ingress",
        "Egress",
    ]
    assert find(fixed, "ScaledObject", API)["spec"]["cooldownPeriod"] == 300
    assert broken == regressed(docs)  # inputs untouched
    # Once the manual items are fixed, the remediated set compiles back into zero trust.
    for document in fixed:
        if document["kind"] == "Deployment" and document["metadata"]["name"] == API:
            api = document["spec"]["template"]["spec"]["containers"][0]
            api["image"] = "ghcr.io/x/api:1.0.0"
            api["resources"]["limits"] = {"cpu": "1", "memory": "1Gi"}
    find(fixed, "ScaledObject", API)["spec"]["triggers"][0]["metadata"]["listLength"] = "5"
    assert AdmissionEngine().evaluate(fixed).decision is GuardrailDecision.ALLOW
    assert zero_trust_ok(fixed)
    assert result.to_yaml().startswith("---\n")


def test_remediation_is_idempotent_and_bounded(docs: Docs) -> None:
    clean = AdmissionEngine().remediate(docs)
    assert (clean.rounds, clean.converged) == ((), True)
    two_rules = find(docs, "NetworkPolicy", f"{API}-allow-egress")["spec"]["egress"]
    two_rules += [{"ports": [{"port": 1}]}, {"ports": [{"port": 2}]}]
    partial = AdmissionEngine().remediate(docs, max_rounds=1)
    assert (len(partial.rounds), partial.converged) == (1, False)
    full = AdmissionEngine().remediate(docs)
    assert (len(full.rounds), full.converged) == (2, True)


@dataclass(frozen=True)
class _Stubborn:
    """A guardrail whose fix never sticks (or never applies)."""

    patch: tuple[JsonPatchOp, ...]
    name: str = "stubborn"

    def evaluate(self, documents: Sequence[Mapping[str, Any]]) -> list[PolicyViolation]:
        return [
            PolicyViolation(
                code="stubborn",
                policy=self.name,
                decision=GuardrailDecision.DENY,
                target=ObjectRef.of(documents[0]),
                message="never satisfied",
                remediation=RemediationAdvice(summary="noop", action="patch", patch=self.patch),
            )
        ]


@pytest.mark.parametrize(
    "patch",
    [
        (JsonPatchOp(op="replace", path="/kind", value="NetworkPolicy"),),  # no-op: loop stops
        (JsonPatchOp(op="remove", path="/does/not/exist"),),  # fails: never applied
    ],
)
def test_loop_stops_when_fixes_do_not_help(docs: Docs, patch: tuple[JsonPatchOp, ...]) -> None:
    result = critic_loop((_Stubborn(patch),), docs)
    assert result.rounds == ()
    assert not result.converged


def test_apply_remediations_one_patch_per_object_and_unique_creates() -> None:
    target = {"kind": "Pod", "metadata": {"name": "p", "namespace": "n"}, "spec": {"a": 1}}
    ref = ObjectRef.of(target)

    def patch(value: int) -> RemediationAdvice:
        op = JsonPatchOp(op="replace", path="/spec/a", value=value)
        return RemediationAdvice(summary="s", action="patch", patch=(op,))

    created = {"kind": "ConfigMap", "metadata": {"name": "c", "namespace": "n"}}
    create = RemediationAdvice(summary="s", action="create", document=created)
    violations = [
        _violation(GuardrailDecision.DENY, patch(2)).model_copy(update={"target": ref}),
        _violation(GuardrailDecision.DENY, patch(3)).model_copy(update={"target": ref}),
        _violation(GuardrailDecision.DENY, create),
        _violation(GuardrailDecision.DENY, create),
        _violation(GuardrailDecision.DENY, RemediationAdvice(summary="s", action="create")),
    ]
    documents, applied = apply_remediations([target], violations)
    assert documents == [{**target, "spec": {"a": 2}}, created]
    assert len(applied) == 2


# ---------------------------------------------------------------------------
# Workload security guardrail
# ---------------------------------------------------------------------------
Mutation = Callable[[Docs], None]


def _sc(docs: Docs) -> dict[str, Any]:
    context: dict[str, Any] = container(docs)["securityContext"]
    return context


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda d: _sc(d).update(runAsUser=0), {"run-as-root"}),
        (lambda d: _sc(d).update(runAsNonRoot=False), {"run-as-non-root-not-enforced"}),
        (
            lambda d: pod(d)["securityContext"].update(runAsUser=0) or _sc(d).pop("runAsUser"),
            {"run-as-root"},
        ),
        (lambda d: _sc(d).update(readOnlyRootFilesystem=False), {"writable-root-filesystem"}),
        (lambda d: _sc(d).pop("allowPrivilegeEscalation"), {"privilege-escalation-allowed"}),
        (lambda d: _sc(d).update(allowPrivilegeEscalation=True), {"privilege-escalation-allowed"}),
        (lambda d: _sc(d).update(privileged=True), {"privileged-container"}),
        (lambda d: _sc(d)["capabilities"].update(drop=["NET_RAW"]), {"capabilities-not-dropped"}),
        (lambda d: _sc(d)["capabilities"].update(add=["SYS_ADMIN"]), {"capabilities-added"}),
        (
            lambda d: container(d).pop("securityContext") and pod(d).pop("securityContext"),
            {
                "run-as-non-root-not-enforced",
                "writable-root-filesystem",
                "privilege-escalation-allowed",
                "capabilities-not-dropped",
            },
        ),
        (lambda d: pod(d).update(hostNetwork=True, hostPID=True), {"host-namespace"}),
        (lambda d: container(d).pop("resources"), {"best-effort-container"}),
        (lambda d: container(d)["resources"].pop("limits"), {"missing-resource-limits"}),
        (
            lambda d: container(d)["resources"]["requests"].pop("memory"),
            {"missing-resource-requests"},
        ),
        (
            lambda d: container(d)["resources"]["requests"].update(cpu="2"),
            {"requests-exceed-limits"},
        ),
        (
            lambda d: container(d)["resources"]["limits"].update(memory="lots"),
            {"invalid-resource-quantity"},
        ),
        (lambda d: container(d).update(image="ghcr.io/x/api:latest"), {"image-latest-tag"}),
        (lambda d: container(d).update(image="localhost:5000/api"), {"image-untagged"}),
        (lambda d: container(d).update(image="api@sha256:abc"), {"image-invalid-digest"}),
        (
            lambda d: pod(d)["containers"].append(
                {**container(d), "name": "sidecar", "image": "envoy"}
            ),
            {"image-untagged"},
        ),
    ],
)
def test_workload_guardrail_rejects(docs: Docs, mutate: Mutation, expected: set[str]) -> None:
    mutate(docs)
    violations = WorkloadGuardrail().evaluate(docs)
    assert codes(violations) == expected
    assert all(
        v.decision is GuardrailDecision.DENY and v.policy == "workload-security" for v in violations
    )
    assert all(v.target == ObjectRef(kind="Deployment", namespace=NS, name=API) for v in violations)
    assert all(
        v.path.startswith("/spec/template/spec") and v.remediation.summary for v in violations
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: _sc(d).pop("runAsNonRoot"),  # inherited from the pod securityContext
        lambda d: _sc(d)["capabilities"].update(add=["NET_BIND_SERVICE"]),
        lambda d: container(d).update(image=f"ghcr.io/x/api:latest@{DIGEST}"),  # digest wins
        lambda d: container(d).update(image=f"registry:5000/team/api@{DIGEST}"),
        lambda d: container(d)["resources"]["limits"].update(cpu=2),  # YAML int quantity
    ],
)
def test_workload_guardrail_accepts(docs: Docs, mutate: Mutation) -> None:
    mutate(docs)
    assert WorkloadGuardrail().evaluate(docs) == []


def test_security_remediation_hardens_in_one_patch(docs: Docs) -> None:
    context = _sc(docs)
    context.update(
        runAsUser=0, allowPrivilegeEscalation=True, privileged=True, readOnlyRootFilesystem=False
    )
    context["capabilities"] = {"add": ["SYS_ADMIN", "NET_BIND_SERVICE"], "drop": ["NET_RAW"]}
    violations = WorkloadGuardrail().evaluate(docs)
    assert all(v.remediation == violations[0].remediation for v in violations)
    (patch,) = violations[0].remediation.patch
    fixed = apply_patch(find(docs, "Deployment", API), [patch])
    hardened = fixed["spec"]["template"]["spec"]["containers"][0]["securityContext"]
    assert hardened["runAsUser"] == 10001
    assert hardened["capabilities"] == {"add": ["NET_BIND_SERVICE"], "drop": ["NET_RAW", "ALL"]}
    assert WorkloadGuardrail().evaluate([fixed]) == []


def test_host_namespace_remediation_removes_the_flag(docs: Docs) -> None:
    pod(docs)["hostNetwork"] = True
    result = critic_loop((WorkloadGuardrail(),), docs)
    assert "hostNetwork" not in pod(list(result.documents))
    assert result.converged


def test_all_pod_producers_and_container_kinds_are_checked() -> None:
    def spec(**extra: Any) -> dict[str, Any]:
        return {"containers": [{"name": "c", "image": "busybox"}], **extra}

    documents = [
        {"kind": "Pod", "metadata": {"name": "p"}, "spec": spec()},
        {
            "kind": "CronJob",
            "metadata": {"name": "cj", "namespace": "batch"},
            "spec": {
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": spec(
                                initContainers=[{"name": "init", "image": "busybox:1.36"}],
                                ephemeralContainers=[{"name": "debug", "image": "busybox:1.36"}],
                            )
                        }
                    }
                }
            },
        },
        {"kind": "ConfigMap", "metadata": {"name": "ignored"}, "data": {}},
    ]
    violations = WorkloadGuardrail().evaluate(documents)
    by_target = {(v.target.kind, v.code) for v in violations}
    assert ("Pod", "image-untagged") in by_target
    assert ("CronJob", "best-effort-container") in by_target
    paths = {v.path for v in violations if v.target.kind == "CronJob"}
    assert "/spec/jobTemplate/spec/template/spec/initContainers/0/resources" in paths
    assert not any("ephemeralContainers/0/resources" in p for p in paths)
    assert any("ephemeralContainers/0/securityContext" in p for p in paths)
    assert ObjectRef.of(documents[0]).namespace is None


@pytest.mark.parametrize(
    ("image", "problem"),
    [
        ("nginx", "image-untagged"),
        ("nginx:latest", "image-latest-tag"),
        ("localhost:5000/team/app", "image-untagged"),
        ("localhost:5000/team/app:1.2", None),
        (f"app@{DIGEST}", None),
        ("app@sha256:XYZ", "image-invalid-digest"),
        ("", "image-untagged"),
        (None, "image-untagged"),
        ("app:", "image-untagged"),
    ],
)
def test_image_problem(image: Any, problem: str | None) -> None:
    assert image_problem(image) == problem


# ---------------------------------------------------------------------------
# Zero-trust network critic
# ---------------------------------------------------------------------------
def network(docs: Docs, critic: NetworkCritic | None = None) -> list[PolicyViolation]:
    return (critic or NetworkCritic()).evaluate(docs)


def test_network_critic_accepts_the_compiled_policies(docs: Docs) -> None:
    assert network(docs) == []


def test_missing_default_deny_is_flagged_and_remediated(docs: Docs) -> None:
    open_ns = without(docs, "default-deny-all")
    violations = network(open_ns)
    assert codes(violations) == {"missing-default-deny-ingress", "missing-default-deny-egress"}
    assert {v.target for v in violations} == {ObjectRef(kind="Namespace", name=NS)}
    advice = violations[0].remediation
    assert advice.action == "create"
    assert advice.document is not None
    assert advice.document["metadata"] == {"name": "default-deny-all", "namespace": NS}
    result = NetworkCritic().loop(open_ns)
    assert result.converged
    assert result.final.violations == ()
    assert zero_trust_ok(list(result.documents))


def test_default_deny_may_be_split_and_names_never_clash(docs: Docs) -> None:
    split = without(docs, "default-deny-all")
    for direction in ("Ingress", "Egress"):
        split.append(
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"name": f"deny-{direction.lower()}", "namespace": NS},
                "spec": {"podSelector": {}, "policyTypes": [direction]},
            }
        )
    assert network(split) == []
    clash = [
        *without(docs, "default-deny-all"),
        {
            "kind": "NetworkPolicy",
            "metadata": {"name": "default-deny-all", "namespace": NS},
            "spec": {
                "podSelector": {"matchLabels": {"unrelated": "x"}},
                "policyTypes": ["Ingress"],
            },
        },
    ]
    created = network(clash)[0].remediation.document
    assert created is not None
    assert created["metadata"]["name"] == "guardrail-default-deny-all"


def _qdrant_rule(docs: Docs) -> dict[str, Any]:
    rule: dict[str, Any] = find(docs, "NetworkPolicy", "qdrant-allow-from-app")["spec"]["ingress"][
        0
    ]
    return rule


API_SELECTOR = {"app.kubernetes.io/component": "api", "app.kubernetes.io/name": API}


@pytest.mark.parametrize(
    ("mutate", "extra"),
    [
        (lambda d: _qdrant_rule(d).update({"from": [{"podSelector": {}}]}), set()),
        (
            lambda d: _qdrant_rule(d).update(
                {"from": [{"podSelector": {"matchLabels": {"app.kubernetes.io/component": "api"}}}]}
            ),
            set(),
        ),
        (
            lambda d: _qdrant_rule(d)["from"].append(
                {"podSelector": {"matchLabels": {"app.kubernetes.io/name": REDIS}}}
            ),
            set(),
        ),
        (
            lambda d: _qdrant_rule(d)["from"][0].update({"namespaceSelector": {}}),
            {"cross-namespace-ingress"},
        ),
        (
            lambda d: _qdrant_rule(d)["from"].append({"ipBlock": {"cidr": "10.0.0.0/8"}}),
            {"external-ingress"},
        ),
        (lambda d: _qdrant_rule(d).pop("ports"), set()),
        (lambda d: _qdrant_rule(d)["ports"].append({"port": 6335}), set()),
        (lambda d: _qdrant_rule(d)["ports"].append({"port": 6000, "endPort": 7000}), set()),
        (lambda d: _qdrant_rule(d)["ports"][0].update(protocol="UDP"), set()),
        (lambda d: _qdrant_rule(d).pop("from"), {"ingress-from-anywhere"}),
    ],
)
def test_qdrant_admits_only_the_api(docs: Docs, mutate: Mutation, extra: set[str]) -> None:
    mutate(docs)
    violations = network(docs)
    assert codes(violations) == {"qdrant-ingress-not-exclusive", *extra}
    flagged = next(v for v in violations if v.code == "qdrant-ingress-not-exclusive")
    assert flagged.target == ObjectRef(
        kind="NetworkPolicy", namespace=NS, name="qdrant-allow-from-app"
    )
    assert flagged.remediation.patch[0].value == [
        {
            "from": [{"podSelector": {"matchLabels": API_SELECTOR}}],
            "ports": [{"protocol": "TCP", "port": 6333}, {"protocol": "TCP", "port": 6334}],
        }
    ]
    result = NetworkCritic().loop(docs)
    assert result.converged
    assert result.final.violations == ()
    assert zero_trust_ok(list(result.documents))


def test_rogue_pods_impersonating_the_api_selector_are_refused(docs: Docs) -> None:
    critic = NetworkCritic(api_labels={"tier": "frontend"})
    find(docs, "Deployment", API)["spec"]["template"]["metadata"]["labels"]["tier"] = "frontend"
    assert network(docs, critic) == []
    rogue = copy.deepcopy(find(docs, "Deployment", REDIS))
    rogue["metadata"]["name"] = "rogue"
    rogue["spec"]["template"]["metadata"]["labels"] = dict(API_SELECTOR)  # same selector, no tier
    assert codes(network([*docs, rogue], critic)) == {
        "qdrant-ingress-not-exclusive",
        "workload-selector-overlap",
    }


def test_container_ports_skip_malformed_entries() -> None:
    from cloud_native_k8s_ai.guardrails.objects import workload  # noqa: PLC0415

    ports = [{"containerPort": "6333"}, {"containerPort": 80}, {"containerPort": 81, "name": "web"}]
    raw = {"kind": "Pod", "metadata": {"name": "p"}, "spec": {"containers": [{"ports": ports}]}}
    parsed = workload(raw)
    assert parsed is not None
    assert parsed.container_ports() == {80: 80, 81: 81, "web": 81}
    assert parsed.replicas() == 1


def test_qdrant_named_ports_are_exclusive(docs: Docs) -> None:
    _qdrant_rule(docs)["ports"] = [{"port": "rest"}, {"protocol": "TCP", "port": "grpc"}]
    assert network(docs) == []


def test_qdrant_isolation_is_restored(docs: Docs) -> None:
    unreachable = without(docs, "qdrant-allow-from-app")
    (warning,) = network(unreachable)
    assert (warning.code, warning.decision) == (
        "qdrant-unreachable-from-api",
        GuardrailDecision.WARN,
    )
    assert warning.target == ObjectRef(kind="StatefulSet", namespace=NS, name=QDRANT)
    exposed = without(docs, "qdrant-allow-from-app", "default-deny-all")
    assert {"qdrant-not-isolated", "missing-default-deny-ingress"} <= codes(network(exposed))
    for broken in (unreachable, exposed):
        result = NetworkCritic().loop(broken)
        assert result.converged
        assert zero_trust_ok(list(result.documents))
        assert any(d["metadata"]["name"] == f"{QDRANT}-allow-from-api" for d in result.documents)


def test_qdrant_isolation_policy_name_never_clashes(docs: Docs) -> None:
    clash = {
        "kind": "NetworkPolicy",
        "metadata": {"name": f"{QDRANT}-allow-from-api", "namespace": NS},
        "spec": {"podSelector": {"matchLabels": {"unrelated": "x"}}, "policyTypes": ["Ingress"]},
    }
    (warning,) = network([*without(docs, "qdrant-allow-from-app"), clash])
    assert warning.remediation.document is not None
    assert warning.remediation.document["metadata"]["name"] == f"guardrail-{QDRANT}-allow-from-api"


def test_qdrant_without_api_pods_is_simply_isolated(docs: Docs) -> None:
    lonely = [d for d in docs if d["metadata"]["name"] != API or d["kind"] != "Deployment"]
    lonely = [d for d in lonely if d["kind"] != "ScaledObject"]
    violations = network(lonely)
    flagged = next(v for v in violations if v.code == "qdrant-ingress-not-exclusive")
    assert flagged.remediation.patch[0].value == []


@pytest.mark.parametrize(
    ("policy", "rule_key", "rule", "code"),
    [
        (f"{API}-allow-ingress", "ingress", {"ports": [{"port": 8000}]}, "ingress-from-anywhere"),
        (f"{API}-allow-egress", "egress", {"ports": [{"port": 443}]}, "egress-to-anywhere"),
        (
            f"{API}-allow-egress",
            "egress",
            {"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]},
            "external-egress",
        ),
        (
            f"{API}-allow-egress",
            "egress",
            {"to": [{"ipBlock": {"cidr": "not-a-cidr"}}]},
            "external-egress",
        ),
        (
            f"{API}-allow-ingress",
            "ingress",
            {"from": [{"ipBlock": {"cidr": "203.0.113.0/24"}}]},
            "external-ingress",
        ),
        (
            f"{API}-allow-ingress",
            "ingress",
            {"from": [{"namespaceSelector": {}}]},
            "cross-namespace-ingress",
        ),
        (
            f"{API}-allow-ingress",
            "ingress",
            {
                "from": [
                    {
                        "namespaceSelector": {
                            "matchLabels": {"kubernetes.io/metadata.name": "untrusted"}
                        }
                    }
                ]
            },
            "cross-namespace-ingress",
        ),
        (
            f"{API}-allow-ingress",
            "ingress",
            {"from": [{"namespaceSelector": {"matchLabels": {"team": "ml"}}}]},
            "cross-namespace-ingress",
        ),
        (
            f"{API}-allow-egress",
            "egress",
            {
                "to": [
                    {
                        "namespaceSelector": {
                            "matchExpressions": [
                                {"key": "kubernetes.io/metadata.name", "operator": "Exists"}
                            ]
                        }
                    }
                ]
            },
            "cross-namespace-egress",
        ),
        (f"{API}-allow-ingress", "ingress", {"from": [{}]}, "invalid-peer"),
        (
            f"{API}-allow-ingress",
            "ingress",
            {"from": [{"podSelector": {"matchLabels": {"bad key!": "x"}}}]},
            "invalid-peer",
        ),
    ],
)
def test_permissive_rules_are_intercepted(
    docs: Docs, *, policy: str, rule_key: str, rule: dict[str, Any], code: str
) -> None:
    find(docs, "NetworkPolicy", policy)["spec"][rule_key].append(rule)
    violations = network(docs)
    assert codes(violations) == {code}
    (violation,) = violations
    assert violation.decision is GuardrailDecision.DENY
    assert violation.remediation.action == "patch"
    result = NetworkCritic().loop(docs)
    assert result.converged
    assert result.final.violations == ()
    assert zero_trust_ok(list(result.documents))


def test_trusted_peers_and_allow_lists_pass(docs: Docs) -> None:
    ingress = find(docs, "NetworkPolicy", f"{API}-allow-ingress")["spec"]["ingress"]
    ingress.append(
        {"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": NS}}}]}
    )
    egress = find(docs, "NetworkPolicy", f"{API}-allow-egress")["spec"]["egress"]
    egress.append({"to": [{"ipBlock": {"cidr": "10.1.0.0/16"}}], "ports": [{"port": 443}]})
    assert codes(network(docs)) == {"external-egress"}
    critic = NetworkCritic(allowed_egress_cidrs=("10.0.0.0/8", "fd00::/8"))
    assert network(docs, critic) == []


def test_only_the_offending_peer_is_removed(docs: Docs) -> None:
    peers = find(docs, "NetworkPolicy", f"{REDIS}-allow-ingress")["spec"]["ingress"][0]["from"]
    peers.insert(0, {"namespaceSelector": {}})
    (violation,) = network(docs)
    assert violation.remediation.patch == (JsonPatchOp(op="remove", path="/spec/ingress/0/from/0"),)
    fixed = list(NetworkCritic().loop(docs).documents)
    assert (
        len(find(fixed, "NetworkPolicy", f"{REDIS}-allow-ingress")["spec"]["ingress"][0]["from"])
        == 2
    )


def test_invalid_policy_selector_is_reported(docs: Docs) -> None:
    find(docs, "NetworkPolicy", f"{API}-allow-ingress")["spec"]["podSelector"] = {
        "matchLabels": "nope"
    }
    violations = network(docs)
    assert "invalid-pod-selector" in codes(violations)
    assert (
        next(v for v in violations if v.code == "invalid-pod-selector").remediation.action
        == "manual"
    )


def test_dns_egress_is_required_once_egress_is_isolated(docs: Docs) -> None:
    stranded = without(docs, "allow-dns-egress")
    (warning,) = network(stranded)
    assert (warning.code, warning.decision) == ("missing-dns-egress", GuardrailDecision.WARN)
    assert API in warning.message
    result = NetworkCritic().loop(stranded)
    assert result.final.violations == ()
    assert zero_trust_ok(list(result.documents))


def test_policy_types_default_like_kubernetes(docs: Docs) -> None:
    dns = find(docs, "NetworkPolicy", "allow-dns-egress")["spec"]
    del dns["policyTypes"]  # Kubernetes infers Ingress + Egress from the egress rules
    deny = find(docs, "NetworkPolicy", "default-deny-all")["spec"]
    deny["policyTypes"] = ["Ingress"]
    assert codes(network(docs)) == {"missing-default-deny-egress"}


# ---------------------------------------------------------------------------
# Autoscaling safety (KEDA)
# ---------------------------------------------------------------------------
def scaled(docs: Docs) -> dict[str, Any]:
    spec: dict[str, Any] = find(docs, "ScaledObject", API)["spec"]
    return spec


def keda(docs: Docs) -> list[PolicyViolation]:
    return KedaCritic().evaluate(docs)


def test_keda_critic_accepts_the_compiled_scaler(docs: Docs) -> None:
    assert keda(docs) == []
    for key in ("pollingInterval", "cooldownPeriod"):
        scaled(docs).pop(key)  # KEDA defaults: 30s polling, 300s cooldown
    assert keda(docs) == []


@pytest.mark.parametrize(
    ("polling", "cooldown", "fixed"), [(30, 10, 300), (600, 300, 600), (60, 0, 300)]
)
def test_cooldown_shorter_than_polling_thrashes(
    docs: Docs, polling: int, cooldown: int, fixed: int
) -> None:
    scaled(docs).update(pollingInterval=polling, cooldownPeriod=cooldown)
    (violation,) = keda(docs)
    assert (violation.code, violation.decision) == (
        "keda-cooldown-below-polling",
        GuardrailDecision.DENY,
    )
    assert violation.remediation.patch == (
        JsonPatchOp(op="add", path="/spec/cooldownPeriod", value=fixed),
    )
    result = critic_loop((KedaCritic(),), docs)
    assert result.final.violations == ()


@pytest.mark.parametrize(
    ("update", "code", "decision"),
    [
        (
            {"pollingInterval": 2, "cooldownPeriod": 300},
            "keda-polling-too-aggressive",
            GuardrailDecision.WARN,
        ),
        (
            {"minReplicaCount": 5, "maxReplicaCount": 3},
            "keda-replica-bounds",
            GuardrailDecision.DENY,
        ),
        (
            {"minReplicaCount": 4, "maxReplicaCount": 4},
            "keda-no-scaling-range",
            GuardrailDecision.WARN,
        ),
        ({"idleReplicaCount": 1}, "keda-idle-replicas", GuardrailDecision.DENY),
        ({"idleReplicaCount": True}, "keda-idle-replicas", GuardrailDecision.DENY),
        ({"pollingInterval": "30"}, "keda-invalid-field", GuardrailDecision.DENY),
        ({"maxReplicaCount": -1}, "keda-invalid-field", GuardrailDecision.DENY),
        ({"triggers": []}, "keda-no-triggers", GuardrailDecision.DENY),
    ],
)
def test_keda_bounds_and_timing(
    docs: Docs, update: dict[str, Any], code: str, decision: GuardrailDecision
) -> None:
    scaled(docs).update(update)
    (violation,) = keda(docs)
    assert (violation.code, violation.decision) == (code, decision)
    assert not violation.remediation.automatic


@pytest.mark.parametrize(
    ("metadata", "code"),
    [
        ({"listLength": "0"}, "keda-threshold-not-positive"),
        ({"listLength": "-5"}, "keda-threshold-not-positive"),
        ({"listLength": "five"}, "keda-threshold-invalid"),
        ({"listLength": True}, "keda-threshold-invalid"),
        ({"listLength": "NaN"}, "keda-threshold-invalid"),
        ({"activationListLength": "-1"}, "keda-activation-negative"),
        ({"targetValue": 0}, "keda-threshold-not-positive"),
        ({"activationThreshold": "x"}, "keda-threshold-invalid"),
    ],
)
def test_keda_thresholds_must_be_positive(docs: Docs, metadata: dict[str, Any], code: str) -> None:
    scaled(docs)["triggers"][0]["metadata"].update(metadata)
    (violation,) = keda(docs)
    assert violation.code == code
    assert violation.path.startswith("/spec/triggers/0/metadata/")


def test_keda_accepts_fractional_and_numeric_thresholds(docs: Docs) -> None:
    scaled(docs)["triggers"].append(
        {
            "type": "prometheus",
            "metadata": {"threshold": "0.5", "activationThreshold": 0, "query": "up"},
        }
    )
    assert keda(docs) == []


def test_keda_target_must_be_deployed_alongside(docs: Docs) -> None:
    scaled(docs)["scaleTargetRef"]["name"] = "ghost"
    (warning,) = keda(docs)
    assert (warning.code, warning.decision) == ("keda-target-missing", GuardrailDecision.WARN)


def test_competing_autoscalers_are_refused(docs: Docs) -> None:
    twin = copy.deepcopy(find(docs, "ScaledObject", API))
    twin["metadata"]["name"] = "second"
    hpa = {
        "apiVersion": "autoscaling/v2",
        "kind": "HorizontalPodAutoscaler",
        "metadata": {"name": "hpa", "namespace": NS},
        "spec": {"scaleTargetRef": {"kind": "Deployment", "name": API}},
    }
    violations = keda([*docs, twin, hpa])
    conflicts = [v for v in violations if v.code == "keda-conflicting-scalers"]
    assert {v.target.name for v in conflicts} == {API, "second", "hpa"}


def quota(**hard: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "ResourceQuota",
        "metadata": {"name": "compute", "namespace": NS},
        "spec": {"hard": hard},
    }


def test_max_scale_out_must_fit_the_resource_quota(docs: Docs) -> None:
    # api 10 x 1 CPU + qdrant 2 + redis 0.5 = 12.5 CPU of limits at full scale-out.
    (violation,) = keda([*docs, quota(**{"limits.cpu": "8", "pods": "50"})])
    assert violation.code == "keda-exceeds-quota"
    assert "needs limits.cpu 12500" in violation.message
    assert violation.remediation.summary.startswith("lower maxReplicaCount to 5")
    assert keda([*docs, quota(**{"limits.cpu": "13", "requests.memory": "64Gi"})]) == []
    (memory,) = keda([*docs, quota(memory="4Gi")])  # requests: 10 x 512Mi + 1Gi + 256Mi
    assert "lower maxReplicaCount to 5" in memory.remediation.summary
    assert keda([*docs, quota(**{"limits.cpu": "a lot"})]) == []


def test_quota_uses_keda_default_max_replicas(docs: Docs) -> None:
    scaled(docs).pop("maxReplicaCount")  # KEDA default: 100
    (violation,) = keda([*docs, quota(**{"limits.cpu": "50"})])
    assert "at maxReplicaCount 100" in violation.message
    assert violation.remediation.summary.startswith("lower maxReplicaCount to 47")


def test_quota_counts_only_app_containers(docs: Docs) -> None:
    pod(docs)["initContainers"] = [
        {"name": "migrate", "image": "m:1", "resources": {"limits": {"cpu": "50"}}}
    ]
    container(docs, "Deployment", REDIS)["resources"]["limits"].pop("cpu")
    # api 10 x 1 + qdrant 2 (+ redis without a cpu limit, init containers not summed)
    assert keda([*docs, quota(**{"limits.cpu": "12"})]) == []


def test_quota_ignores_daemonsets_and_unparseable_requests(docs: Docs) -> None:
    agent = {
        "kind": "DaemonSet",
        "metadata": {"name": "agent", "namespace": NS},
        "spec": {"template": {"spec": {"containers": [
            {"name": "a", "image": "a:1", "resources": {"limits": {"cpu": "100"}}}]}}},
    }  # fmt: skip
    container(docs)["resources"]["limits"]["cpu"] = "bogus"
    assert keda([*docs, agent, quota(**{"limits.cpu": "3"})]) == []


def test_workload_selector_overlap_is_label_spoofing(docs: Docs) -> None:
    rogue = copy.deepcopy(find(docs, "Deployment", REDIS))
    rogue["metadata"]["name"] = "rogue"
    rogue["spec"]["selector"]["matchLabels"] = {"rogue": "yes"}
    rogue["spec"]["template"]["metadata"]["labels"] = {**API_SELECTOR, "rogue": "yes"}
    (violation,) = network([*docs, rogue])
    assert violation.code == "workload-selector-overlap"
    assert violation.target == ObjectRef(kind="Deployment", namespace=NS, name="rogue")
    assert violation.path == "/spec/template/metadata/labels"
    assert not violation.remediation.automatic
    elsewhere = copy.deepcopy(rogue)
    elsewhere["metadata"]["namespace"] = "sandbox"  # policies only select their own namespace
    assert "workload-selector-overlap" not in codes(network([*docs, elsewhere]))
    expressions = copy.deepcopy(rogue)
    expressions["spec"]["selector"] = {"matchExpressions": [{"key": "rogue", "operator": "Exists"}]}
    expressions["spec"]["template"]["metadata"]["labels"] = {"rogue": "yes"}
    assert network([*docs, expressions]) == []


def test_engine_for_stack_trusts_the_stack_not_generic_defaults() -> None:
    spec = stack(ingress_namespace="gateway", keda_namespace="autoscalers")
    custom = compile_ai_stack(InfraSettings(), spec)
    generic = AdmissionEngine().evaluate(custom)
    assert codes(list(generic.violations)) == {"cross-namespace-ingress"}  # gateway, autoscalers
    scoped = AdmissionEngine.for_stack(InfraSettings(), spec)
    assert scoped.evaluate(custom).decision is GuardrailDecision.ALLOW
    # Pinned to the exact API selector, a look-alike "component: api" workload is not the API:
    docs = copy.deepcopy(custom.to_documents())
    lookalike = copy.deepcopy(find(docs, "Deployment", REDIS))
    lookalike["metadata"]["name"] = "lookalike"
    lookalike["spec"]["selector"]["matchLabels"] = {"app.kubernetes.io/name": "lookalike"}
    lookalike["spec"]["template"]["metadata"]["labels"] = {
        "app.kubernetes.io/name": "lookalike",
        "app.kubernetes.io/component": "api",
    }
    _qdrant_rule(docs)["from"].append(
        {"podSelector": {"matchLabels": {"app.kubernetes.io/name": "lookalike"}}}
    )
    label_based = NetworkCritic(
        trusted_namespaces=frozenset({"kube-system", "gateway", "autoscalers"})
    )
    generic_identity = AdmissionEngine((WorkloadGuardrail(), label_based, KedaCritic()))
    assert generic_identity.evaluate([*docs, lookalike]).allowed  # any "component: api" pod
    report = scoped.evaluate([*docs, lookalike])
    assert report.codes() == {"qdrant-ingress-not-exclusive"}


def test_shared_policies_never_receive_the_qdrant_rule(docs: Docs) -> None:
    # A default-deny that "allows all" selects every pod, Qdrant included.
    find(docs, "NetworkPolicy", "default-deny-all")["spec"]["ingress"] = [{}]
    flagged = next(v for v in network(docs) if v.code == "qdrant-ingress-not-exclusive")
    assert flagged.target.name == "default-deny-all"
    # Installing Qdrant's API-only rule here would open every pod to the API: only drop.
    assert flagged.remediation.patch[0].value == []
    assert flagged.remediation.summary.startswith("remove the rules")
    result = NetworkCritic().loop(docs)
    assert result.final.violations == ()
    assert (
        find(list(result.documents), "NetworkPolicy", "default-deny-all")["spec"]["ingress"] == []
    )
    assert zero_trust_ok(list(result.documents))


def test_catalog_has_no_dead_codes() -> None:
    """Every catalogued code is emitted by some guardrail (literal or f-string family).

    The reverse holds by construction: decisions are looked up in the catalog, so an
    unregistered code raises KeyError on a line the 100% branch coverage executes.
    """
    import ast  # noqa: PLC0415
    import re  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    from cloud_native_k8s_ai.guardrails import CATALOG  # noqa: PLC0415

    sources = Path(__file__).resolve().parent.parent / "src/cloud_native_k8s_ai/guardrails"
    literals: set[str] = set()
    families: list[re.Pattern[str]] = []
    for name in ("admission.py", "network_critic.py", "keda_critic.py"):
        for node in ast.walk(ast.parse((sources / name).read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                literals.add(node.value)
            elif isinstance(node, ast.JoinedStr):
                parts = [
                    re.escape(str(v.value)) if isinstance(v, ast.Constant) else "[a-z]+"
                    for v in node.values
                ]
                families.append(re.compile("".join(parts)))
    dead = {c for c in CATALOG if c not in literals and not any(f.fullmatch(c) for f in families)}
    assert dead == set()
    assert len(CATALOG) == 44


def test_catalog_refuses_inconsistent_violations() -> None:
    from cloud_native_k8s_ai.guardrails.catalog import violation  # noqa: PLC0415

    target = ObjectRef(kind="Pod", namespace="n", name="p")
    manual = RemediationAdvice(summary="s", action="manual")
    fields: dict[str, Any] = {"policy": "p", "target": target, "path": "", "message": "m"}
    built = violation("image-latest-tag", remediation=manual, **fields)
    assert built.decision is GuardrailDecision.DENY
    with pytest.raises(GuardrailError, match="contradicts the catalog's 'patch'"):
        violation("run-as-root", remediation=manual, **fields)
    with pytest.raises(KeyError):
        violation("made-up-code", remediation=manual, **fields)
