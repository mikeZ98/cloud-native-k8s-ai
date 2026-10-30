"""Phase 7 verification: adversarial manifests against the admission guardrails.

Every vector starts from a compliant, core-compiled bundle and is submitted as raw YAML,
the way an attacker would: privilege escalation, label spoofing to reach Qdrant, poisoned
or missing default-deny policies, CIDR wildcards, host namespaces and YAML bombs. Each
must be DENIED with exact violation codes, and its fallback remediation must behave:
automatic fixes apply cleanly and converge, the rest is explicitly manual.
"""

from __future__ import annotations

import copy
import io
import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
import yaml

from cloud_native_k8s_ai.api import API_PREFIX, ApiSettings, create_app
from cloud_native_k8s_ai.core import (
    AIStackGenerator,
    ManifestBundle,
    ManifestRenderError,
    TopologySolver,
    compile_ai_stack,
    parse_untrusted_yaml,
    render_yaml,
)
from cloud_native_k8s_ai.guardrails import (
    AdmissionEngine,
    GuardrailDecision,
    KedaCritic,
    NetworkCritic,
    WorkloadGuardrail,
    apply_patch,
    load_documents,
)
from cloud_native_k8s_ai.schemas import InfraSettings
from tests.test_core import stack

NS = "ai-system"
API, QDRANT, REDIS = "inference-api", "qdrant", "redis"
API_SELECTOR = {"app.kubernetes.io/component": "api", "app.kubernetes.io/name": API}
type Docs = list[dict[str, Any]]


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("K8SAI_"):
            monkeypatch.delenv(key)


def compiled() -> Docs:
    return copy.deepcopy(compile_ai_stack(InfraSettings(), stack()).to_documents())


def find(docs: Docs, kind: str, name: str) -> dict[str, Any]:
    return next(d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name)


def api_pod(docs: Docs) -> dict[str, Any]:
    spec: dict[str, Any] = find(docs, "Deployment", API)["spec"]["template"]["spec"]
    return spec


def api_container(docs: Docs) -> dict[str, Any]:
    first: dict[str, Any] = api_pod(docs)["containers"][0]
    return first


def api_context(docs: Docs) -> dict[str, Any]:
    context: dict[str, Any] = api_container(docs)["securityContext"]
    return context


def policy(docs: Docs, name: str) -> dict[str, Any]:
    spec: dict[str, Any] = find(docs, "NetworkPolicy", name)["spec"]
    return spec


def drop_policies(docs: Docs, *names: str) -> Docs:
    return [d for d in docs if d["kind"] != "NetworkPolicy" or d["metadata"]["name"] not in names]


def rogue(docs: Docs, name: str, labels: dict[str, str], namespace: str = NS) -> Docs:
    """A fully compliant Deployment (hardened, resourced, pinned) with attacker-chosen labels."""
    clone = copy.deepcopy(find(docs, "Deployment", REDIS))
    clone["metadata"] = {"name": name, "namespace": namespace}
    clone["spec"]["selector"] = {"matchLabels": {"rogue": name}}
    clone["spec"]["template"]["metadata"] = {"labels": {**labels, "rogue": name}}
    clone["spec"]["template"]["spec"]["volumes"] = [{"name": "data", "emptyDir": {}}]
    return [*docs, clone]


def zero_trust_ok(docs: Docs) -> bool:
    """The core topology solver on the typed bundle; sets the (stricter) typed models
    cannot represent, such as a ``command`` override, count as checked by admission."""
    generator = AIStackGenerator(InfraSettings(), stack())
    try:
        typed = ManifestBundle.from_yaml(render_yaml(docs))
    except ManifestRenderError:
        return True
    return TopologySolver(generator.topology(typed)).verify(generator.intent()).ok


@dataclass(frozen=True)
class Vector:
    name: str
    attack: Callable[[Docs], Docs]
    codes: frozenset[str]
    manual: frozenset[str] = field(default_factory=frozenset)
    """Codes that must remain after remediation (no safe automatic fix exists)."""
    engine: AdmissionEngine = field(
        default_factory=lambda: AdmissionEngine.for_stack(InfraSettings(), stack())
    )

    def __str__(self) -> str:
        return self.name


def mutate(change: Callable[[Docs], object]) -> Callable[[Docs], Docs]:
    def attack(docs: Docs) -> Docs:
        change(docs)
        return docs

    return attack


SECURITY = frozenset(
    {
        "run-as-root",
        "run-as-non-root-not-enforced",
        "writable-root-filesystem",
        "privilege-escalation-allowed",
        "privileged-container",
        "capabilities-not-dropped",
    }
)


def _init_container(privileged: bool) -> Callable[[Docs], object]:
    def change(docs: Docs) -> None:
        init = copy.deepcopy(api_container(docs))
        init["name"] = "init"
        init["securityContext"]["privileged"] = privileged
        api_pod(docs)["initContainers"] = [init]

    return change


def _debug_container(docs: Docs) -> None:
    api_pod(docs)["ephemeralContainers"] = [
        {"name": "debug", "image": "busybox:1.36", "securityContext": {"privileged": True}}
    ]


def _as_kind(kind: str) -> Callable[[Docs], Docs]:
    """Move the API pod template into another pod-producing kind, made root on the way."""

    def attack(docs: Docs) -> Docs:
        labels = {"rogue": kind.lower()}
        template = copy.deepcopy(find(docs, "Deployment", API)["spec"]["template"])
        template["metadata"] = {"labels": labels}
        template["spec"]["containers"][0]["securityContext"]["runAsUser"] = 0
        selector = {"matchLabels": labels}
        spec: dict[str, Any] = {
            "Pod": template["spec"],
            "DaemonSet": {"selector": selector, "template": template},
            "Job": {"template": template},
            "CronJob": {"schedule": "* * * * *", "jobTemplate": {"spec": {"template": template}}},
            "ReplicaSet": {"selector": selector, "template": template},
        }[kind]
        metadata = {"name": "smuggled", "namespace": NS} | (
            {"labels": labels} if kind == "Pod" else {}
        )
        return [*docs, {"apiVersion": "v1", "kind": kind, "metadata": metadata, "spec": spec}]

    return attack


PRIVILEGE_ESCALATION = [
    Vector(
        "explicit-root-user",
        mutate(lambda d: api_context(d).update(runAsUser=0, runAsNonRoot=False)),
        frozenset({"run-as-root", "run-as-non-root-not-enforced"}),
    ),
    Vector(
        "root-inherited-from-pod",
        mutate(
            lambda d: (
                api_pod(d)["securityContext"].update(runAsUser=0),
                api_context(d).pop("runAsUser"),
            )
        ),
        frozenset({"run-as-root"}),
    ),
    Vector(
        "container-overrides-pod-nonroot",
        mutate(lambda d: api_context(d).update(runAsNonRoot=False)),
        frozenset({"run-as-non-root-not-enforced"}),
    ),
    Vector(
        "sudo-setuid-escape",
        mutate(
            lambda d: (
                api_container(d).update(command=["sudo", "sh"]),
                api_context(d).update(allowPrivilegeEscalation=True),
            )
        ),
        frozenset({"privilege-escalation-allowed"}),
    ),
    Vector(
        "escalation-left-to-default",
        mutate(lambda d: api_context(d).pop("allowPrivilegeEscalation")),
        frozenset({"privilege-escalation-allowed"}),
    ),
    Vector(
        "privileged-container",
        mutate(lambda d: api_context(d).update(privileged=True)),
        frozenset({"privileged-container"}),
    ),
    Vector(
        "cap-sys-admin",
        mutate(lambda d: api_context(d)["capabilities"].update(add=["SYS_ADMIN"])),
        frozenset({"capabilities-added"}),
    ),
    Vector(
        "cap-prefixed-spelling",
        mutate(lambda d: api_context(d)["capabilities"].update(add=["CAP_SYS_ADMIN", "NET_RAW"])),
        frozenset({"capabilities-added"}),
    ),
    Vector(
        "drop-lowercase-all",
        mutate(lambda d: api_context(d)["capabilities"].update(drop=["all"])),
        frozenset({"capabilities-not-dropped"}),
    ),
    Vector(
        "type-confused-booleans",
        mutate(
            lambda d: api_context(d).update(
                runAsNonRoot="true", readOnlyRootFilesystem="true", allowPrivilegeEscalation=0
            )
        ),
        frozenset(
            {
                "run-as-non-root-not-enforced",
                "writable-root-filesystem",
                "privilege-escalation-allowed",
            }
        ),
    ),
    Vector(
        "privileged-init-container",
        mutate(_init_container(privileged=True)),
        frozenset({"privileged-container"}),
    ),
    Vector(
        "debug-ephemeral-container",
        mutate(_debug_container),
        frozenset(
            {
                "writable-root-filesystem",
                "privilege-escalation-allowed",
                "privileged-container",
                "capabilities-not-dropped",
            }
        ),
    ),
    *(
        Vector(f"smuggled-as-{kind.lower()}", _as_kind(kind), frozenset({"run-as-root"}))
        for kind in ("Pod", "DaemonSet", "Job", "CronJob", "ReplicaSet")
    ),
]


def _loosen_qdrant(peer: dict[str, Any]) -> Callable[[Docs], object]:
    return lambda d: policy(d, "qdrant-allow-from-app")["ingress"][0].update({"from": [peer]})


LABEL_SPOOFING = [
    Vector(
        "rogue-clone-of-api-labels",
        lambda d: rogue(d, "rogue", dict(API_SELECTOR)),
        frozenset({"workload-selector-overlap"}),
        manual=frozenset({"workload-selector-overlap"}),
    ),
    Vector(
        "rogue-superset-of-api-labels",
        lambda d: rogue(d, "rogue", {**API_SELECTOR, "app.kubernetes.io/version": "evil"}),
        frozenset({"workload-selector-overlap"}),
        manual=frozenset({"workload-selector-overlap"}),
    ),
    Vector(
        "qdrant-opened-to-any-api-component",
        lambda d: rogue(
            mutate(
                _loosen_qdrant(
                    {"podSelector": {"matchLabels": {"app.kubernetes.io/component": "api"}}}
                )
            )(d),
            "lookalike",
            {"app.kubernetes.io/component": "api", "app.kubernetes.io/name": "lookalike"},
        ),
        frozenset({"qdrant-ingress-not-exclusive"}),
    ),
    Vector(
        "qdrant-widened-by-match-expressions",
        mutate(
            _loosen_qdrant(
                {
                    "podSelector": {
                        "matchExpressions": [
                            {
                                "key": "app.kubernetes.io/name",
                                "operator": "In",
                                "values": [API, "rogue"],
                            }
                        ]
                    }
                }
            )
        ),
        frozenset({"qdrant-ingress-not-exclusive"}),
    ),
    Vector(
        "qdrant-reached-from-any-namespace",
        mutate(
            _loosen_qdrant(
                {"podSelector": {"matchLabels": dict(API_SELECTOR)}, "namespaceSelector": {}}
            )
        ),
        frozenset({"qdrant-ingress-not-exclusive", "cross-namespace-ingress"}),
    ),
    Vector(
        "qdrant-opened-to-every-pod",
        mutate(_loosen_qdrant({"podSelector": {}})),
        frozenset({"qdrant-ingress-not-exclusive"}),
    ),
]


def _poison_default_deny(change: Callable[[dict[str, Any]], object]) -> Callable[[Docs], Docs]:
    return mutate(lambda d: change(policy(d, "default-deny-all")))


def _relocate_default_deny(docs: Docs) -> None:
    find(docs, "NetworkPolicy", "default-deny-all")["metadata"]["namespace"] = "default"


DEFAULT_DENY_POISONING = [
    Vector(
        "default-deny-deleted",
        lambda d: drop_policies(d, "default-deny-all"),
        frozenset({"missing-default-deny-ingress", "missing-default-deny-egress"}),
    ),
    Vector(
        "default-deny-selects-nobody",
        _poison_default_deny(lambda p: p.update(podSelector={"matchLabels": {"nobody": "here"}})),
        frozenset({"missing-default-deny-ingress", "missing-default-deny-egress"}),
    ),
    Vector(
        "allow-all-rule-hidden-in-deny",
        _poison_default_deny(lambda p: p.update(ingress=[{}])),
        frozenset(
            {
                "missing-default-deny-ingress",
                "ingress-from-anywhere",
                "qdrant-ingress-not-exclusive",
            }
        ),
    ),
    Vector(
        "internet-egress-hidden-in-deny",
        _poison_default_deny(
            lambda p: p.update(egress=[{"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}])
        ),
        frozenset({"missing-default-deny-egress", "external-egress"}),
    ),
    Vector(
        "egress-silently-left-open",
        _poison_default_deny(lambda p: p.update(policyTypes=["Ingress"])),
        frozenset({"missing-default-deny-egress"}),
    ),
    Vector(
        "default-deny-in-wrong-namespace",
        mutate(_relocate_default_deny),
        frozenset({"missing-default-deny-ingress", "missing-default-deny-egress"}),
    ),
]


def _egress_to(*cidrs: str, **block: Any) -> Callable[[Docs], Docs]:
    peers = [{"ipBlock": {"cidr": c, **block}} for c in cidrs]
    return mutate(lambda d: policy(d, f"{API}-allow-egress")["egress"].append({"to": peers}))


def _allowing(cidr: str) -> AdmissionEngine:
    base = AdmissionEngine.for_stack(InfraSettings(), stack())
    network = next(g for g in base.guardrails if isinstance(g, NetworkCritic))
    critic = NetworkCritic(
        trusted_namespaces=network.trusted_namespaces,
        allowed_egress_cidrs=(cidr,),
        vector_store_labels=network.vector_store_labels,
        api_labels=network.api_labels,
    )
    return AdmissionEngine((WorkloadGuardrail(), critic, KedaCritic()))


CIDR_WILDCARDS = [
    Vector(
        f"egress-{name}",
        _egress_to(*cidrs, **block),
        frozenset({"external-egress"}),
        engine=_allowing("10.1.0.0/16"),
    )
    for name, cidrs, block in (
        ("ipv4-everything", ("0.0.0.0/0",), {}),
        ("ipv6-everything", ("::/0",), {}),
        ("internet-split-in-halves", ("0.0.0.0/1", "128.0.0.0/1"), {}),
        ("broader-than-allowed", ("10.0.0.0/8",), {}),
        ("everything-except-private", ("0.0.0.0/0",), {"except": ["10.0.0.0/8"]}),
        ("wildcard-string", ("*",), {}),
        ("host-bits-trick", ("10.1.0.0/15",), {}),
    )
] + [
    Vector(
        "ingress-from-internet",
        mutate(
            lambda d: policy(d, f"{API}-allow-ingress")["ingress"].append(
                {"from": [{"ipBlock": {"cidr": "0.0.0.0/0"}}], "ports": [{"port": 8000}]}
            )
        ),
        frozenset({"external-ingress"}),
    ),
]


def _host(key: str) -> Callable[[Docs], object]:
    return lambda d: api_pod(d).update({key: True})


HOST_NAMESPACES = [
    *(
        Vector(f"{key}-escape", mutate(_host(key)), frozenset({"host-namespace"}))
        for key in ("hostNetwork", "hostPID", "hostIPC")
    ),
    Vector(
        "all-host-namespaces",
        mutate(lambda d: api_pod(d).update(hostNetwork=True, hostPID=True, hostIPC=True)),
        frozenset({"host-namespace"}),
    ),
]

VECTORS = [
    *PRIVILEGE_ESCALATION,
    *LABEL_SPOOFING,
    *DEFAULT_DENY_POISONING,
    *CIDR_WILDCARDS,
    *HOST_NAMESPACES,
]


@pytest.mark.parametrize("vector", VECTORS, ids=str)
def test_attack_is_denied_with_exact_codes(vector: Vector) -> None:
    manifests = render_yaml(vector.attack(compiled()))  # submitted as raw YAML
    report = vector.engine.evaluate(manifests)
    assert report.decision is GuardrailDecision.DENY
    assert report.codes() == vector.codes, [str(v) for v in report.violations]
    denied = [o for o in report.objects if o.decision is GuardrailDecision.DENY]
    assert denied or all(v.target.kind == "Namespace" for v in report.violations)
    for violation in report.violations:
        assert violation.remediation.summary
        assert violation.message
        assert violation.path == "" or violation.path.startswith("/")


@pytest.mark.parametrize("vector", VECTORS, ids=str)
def test_fallback_remediation_converges(vector: Vector) -> None:
    documents = vector.attack(compiled())
    report = vector.engine.evaluate(documents)
    by_ref = {
        (d["kind"], d["metadata"].get("namespace"), d["metadata"]["name"]): d for d in documents
    }
    for violation in report.violations:
        advice = violation.remediation
        if advice.action == "patch":
            target = by_ref[
                (violation.target.kind, violation.target.namespace, violation.target.name)
            ]
            apply_patch(target, advice.patch)  # every automatic patch applies as issued
        elif advice.action == "create":
            assert advice.document is not None
            assert advice.document["kind"] == "NetworkPolicy"
    result = vector.engine.remediate(documents)
    assert result.converged
    assert result.final.codes() == vector.manual
    assert all(not v.remediation.automatic for v in result.final.violations)
    added = {(d["kind"], d["metadata"]["name"]) for d in documents} - {
        (d["kind"], d["metadata"]["name"]) for d in compiled()
    }
    if not vector.manual and not added:  # pure tampering: the fixed set is clean zero trust
        assert result.final.decision is GuardrailDecision.ALLOW
        assert zero_trust_ok(list(result.documents))


def test_cross_namespace_lookalikes_are_not_a_threat() -> None:
    """Policies select pods in their own namespace only: API look-alikes elsewhere gain nothing."""
    docs = rogue(compiled(), "lookalike", dict(API_SELECTOR), namespace="attacker")
    report = AdmissionEngine.for_stack(InfraSettings(), stack()).evaluate(docs)
    assert not report.codes() & {"workload-selector-overlap", "qdrant-ingress-not-exclusive"}
    assert report.codes() == {"missing-default-deny-ingress", "missing-default-deny-egress"}
    assert {v.target.name for v in report.violations} == {"attacker"}  # only their namespace


def test_duplicate_key_smuggling_is_judged_on_the_effective_value() -> None:
    manifests = render_yaml(compiled()).replace(
        "            runAsNonRoot: true\n            runAsUser: 10001\n",
        "            runAsNonRoot: true\n"
        "            runAsNonRoot: false\n"
        "            runAsUser: 10001\n",
        1,
    )
    assert "runAsNonRoot: false" in manifests
    report = AdmissionEngine().evaluate(manifests)
    assert report.codes() == {"run-as-non-root-not-enforced"}


def test_hardened_sudo_is_contained() -> None:
    """``sudo`` in the command is harmless once no_new_privs (no escalation) is enforced."""
    docs = compiled()
    api_container(docs)["command"] = ["sudo", "-n", "id"]
    assert AdmissionEngine().evaluate(docs).decision is GuardrailDecision.ALLOW


def test_host_namespaces_are_all_removed() -> None:
    docs = compiled()
    api_pod(docs).update(hostNetwork=True, hostPID=True, hostIPC=True)
    result = AdmissionEngine().remediate(docs)
    assert len(result.rounds) == 3  # one patch per object per round
    assert not {"hostNetwork", "hostPID", "hostIPC"} & set(api_pod(list(result.documents)))
    assert result.final.decision is GuardrailDecision.ALLOW


# ---------------------------------------------------------------------------
# YAML bombs: rejected while screening, before PyYAML constructs a single object
# ---------------------------------------------------------------------------
def billion_laughs(levels: int = 9, width: int = 9) -> str:
    lines = ["---", 'l0: &l0 "lol"']
    for level in range(1, levels + 1):
        refs = ", ".join([f"*l{level - 1}"] * width)
        lines.append(f"l{level}: &l{level} [{refs}]")
    return "\n".join(lines) + "\n"


BOMBS = {
    "billion-laughs": billion_laughs(),
    "quadratic-blowup": "---\na: &a "
    + "x" * 10_000
    + "\nb: ["
    + ", ".join(["*a"] * 10_000)
    + "]\n",
    "anchor-only": "---\nkind: &k Pod\n",
    "alias-as-key": "---\nbase: &b k\n*b : v\n",
    "merge-key": "---\nbase: &base {runAsUser: 0}\ncontext:\n  <<: *base\n",
    "alias-deep-in-list": "---\na: &x 1\nspec: {containers: [{env: [{value: *x}]}]}\n",
    "flow-nesting": "[" * 100_000 + "]" * 100_000,
    "block-nesting": "".join("  " * i + "k:\n" for i in range(5_000)),
    "mapping-nesting": "{a: " * 1_000 + "1" + "}" * 1_000,
}


@pytest.fixture
def construction_forbidden(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_: Any, **__: Any) -> Any:
        raise AssertionError("PyYAML construction reached for a bomb")

    monkeypatch.setattr(yaml, "safe_load_all", refuse)


@pytest.mark.parametrize("bomb", list(BOMBS.values()), ids=list(BOMBS))
@pytest.mark.usefixtures("construction_forbidden")
def test_yaml_bombs_are_rejected_before_construction(bomb: str) -> None:
    started = time.perf_counter()
    with pytest.raises(ManifestRenderError, match=r"anchors and aliases|nesting deeper than"):
        parse_untrusted_yaml(bomb)
    with pytest.raises(ManifestRenderError):
        AdmissionEngine().evaluate(bomb)
    with pytest.raises(ManifestRenderError):
        load_documents(bomb)
    assert time.perf_counter() - started < 5


def test_unsafe_tags_never_execute() -> None:
    for payload in (
        "--- !!python/object/apply:os.system ['true']\n",
        "---\nkind: !!python/name:os.system\n",
    ):
        with pytest.raises(ManifestRenderError):
            parse_untrusted_yaml(payload)


def test_plain_manifests_still_parse_after_screening() -> None:
    text = render_yaml(compiled())
    assert parse_untrusted_yaml(text) == compiled()
    assert AdmissionEngine().evaluate(text).allowed


# ---------------------------------------------------------------------------
# The same attacks through the HTTP control plane
# ---------------------------------------------------------------------------
@pytest.fixture
async def client() -> Any:
    app = create_app(ApiSettings(), log_stream=io.StringIO())
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://control-plane"
        ) as http,
    ):
        yield http


ADMISSION = f"{API_PREFIX}/validate/admission"


@pytest.mark.parametrize("bomb", ["billion-laughs", "flow-nesting", "merge-key"])
async def test_bombs_over_http_are_clean_400s(client: httpx.AsyncClient, bomb: str) -> None:
    response = await client.post(
        ADMISSION, content=BOMBS[bomb], headers={"content-type": "application/yaml"}
    )
    assert response.status_code == 400
    assert response.json()["type"].endswith(":manifest-render")


async def test_deep_json_bodies_are_refused(client: httpx.AsyncClient) -> None:
    body = '{"values": ' + '{"a": ' * 5_000 + "1" + "}" * 5_000 + "}"
    response = await client.post(
        f"{API_PREFIX}/validate/chart", content=body, headers={"content-type": "application/json"}
    )
    assert response.status_code == 422
    assert response.json()["type"].endswith(":invalid-request")


async def test_oversized_payloads_are_refused(client: httpx.AsyncClient) -> None:
    payload = "---\n" + "a: " + "x" * (2 << 20) + "\n"
    response = await client.post(
        ADMISSION, content=payload, headers={"content-type": "application/yaml"}
    )
    assert response.status_code == 413


@pytest.mark.parametrize(
    "vector", [PRIVILEGE_ESCALATION[0], LABEL_SPOOFING[0], DEFAULT_DENY_POISONING[0]], ids=str
)
async def test_attacks_over_http_are_structured_denials(
    client: httpx.AsyncClient, vector: Vector
) -> None:
    manifests = render_yaml(vector.attack(compiled()))
    response = await client.post(
        ADMISSION, params={"remediate": "true"}, json={"manifests": manifests}
    )
    if vector.manual:
        assert response.status_code == 422
        problem = response.json()
        assert {v["code"] for v in problem["violations"]} == set(vector.manual)
        assert json.loads(json.dumps(problem["remediation"]))["converged"] is True
    else:
        assert response.status_code == 200
        body = response.json()
        assert body["remediation"]["initialDecision"] == "DENY"
        assert body["report"]["decision"] == "ALLOW"
        assert list(yaml.safe_load_all(body["remediation"]["manifests"]))
