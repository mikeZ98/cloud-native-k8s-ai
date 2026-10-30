"""Phase 3 verification: manifest generator, YAML engine, zero-trust topology solver and
autoscaling resolver.

Hermetic: everything is computed in memory; the generated YAML is linted through the
yamllint Python API and parsed back with ``yaml.safe_load_all``. No cluster, no network.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from yamllint import linter
from yamllint.config import YamlLintConfig

from cloud_native_k8s_ai.core import (
    SCRATCH_PATH,
    AIStackGenerator,
    AIStackSpec,
    AutoscalingPolicy,
    AutoscalingResolver,
    Endpoint,
    ExclusiveIngress,
    Flow,
    K8sAiCoreError,
    ManifestBundle,
    ManifestRenderError,
    NetworkTopology,
    ResourceBudget,
    ResourceConstraintError,
    TopologyConflictError,
    TopologySolver,
    Violation,
    ZeroTrustIntent,
    build_ai_stack,
    canonical,
    check_policy,
    compile_ai_stack,
    desired_replicas,
    parse_yaml,
    render_yaml,
    service_host,
)
from cloud_native_k8s_ai.schemas import (
    Container,
    ContainerPort,
    Deployment,
    DeploymentSpec,
    EnvVar,
    FastAPIAppSpec,
    HTTPGetAction,
    InfraSettings,
    K8sModel,
    LabelSelector,
    NetworkPolicy,
    ObjectMeta,
    PersistentVolumeClaim,
    PodSpec,
    PodTemplateSpec,
    Probe,
    QdrantSpec,
    RedisPersistence,
    RedisSpec,
    ResourceList,
    ResourceRequirements,
    ScaledObject,
    Service,
    ServicePort,
    ServiceSpec,
    StatefulSet,
)

ROOT = Path(__file__).resolve().parent.parent
NS = "ai-system"
APP, QDRANT, REDIS = "inference-api", "qdrant", "redis"


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("K8SAI_"):
            monkeypatch.delenv(key)


def res(rc: str, rm: str, lc: str, lm: str) -> ResourceRequirements:
    return ResourceRequirements(
        requests=ResourceList(cpu=rc, memory=rm), limits=ResourceList(cpu=lc, memory=lm)
    )


def stack(**overrides: Any) -> AIStackSpec:
    fields: dict[str, Any] = {
        "app": FastAPIAppSpec(
            image="ghcr.io/mikez98/inference-api:0.1.0", resources=res("250m", "512Mi", "1", "1Gi")
        ),
        "qdrant": QdrantSpec(
            image="docker.io/qdrant/qdrant:v1.15.4", resources=res("500m", "1Gi", "2", "4Gi")
        ),
        "redis": RedisSpec(
            image="docker.io/library/redis:7.4.2-alpine",
            resources=res("100m", "256Mi", "500m", "1Gi"),
            maxmemory="768Mi",
        ),
    }
    fields.update(overrides)
    return AIStackSpec(**fields)


def generator(**overrides: Any) -> AIStackGenerator:
    return AIStackGenerator(InfraSettings(), stack(**overrides))


@pytest.fixture(scope="module")
def bundle() -> ManifestBundle:
    return compile_ai_stack(InfraSettings(), stack())


@pytest.fixture(scope="module")
def rendered(bundle: ManifestBundle) -> str:
    return bundle.to_yaml()


@pytest.fixture(scope="module")
def docs(rendered: str) -> list[dict[str, Any]]:
    return [d for d in yaml.safe_load_all(rendered) if d is not None]


def find(docs: list[dict[str, Any]], kind: str, name: str) -> dict[str, Any]:
    matches = [d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name]
    assert len(matches) == 1, f"{kind}/{name}"
    return matches[0]


def policy(name: str, spec: dict[str, Any]) -> NetworkPolicy:
    return NetworkPolicy.from_wire(
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": NS},
            "spec": spec,
        }
    )


SEL = {
    APP: {"app.kubernetes.io/name": APP, "app.kubernetes.io/component": "api"},
    QDRANT: {"app.kubernetes.io/name": QDRANT, "app.kubernetes.io/component": "vector-store"},
    REDIS: {"app.kubernetes.io/name": REDIS, "app.kubernetes.io/component": "broker"},
}


def verify(bundle: ManifestBundle, gen: AIStackGenerator | None = None) -> Any:
    gen = gen or generator()
    return TopologySolver(gen.topology(bundle)).verify(gen.intent())


def without(bundle: ManifestBundle, kind: type[Any], name: str) -> ManifestBundle:
    return ManifestBundle(
        tuple(r for r in bundle.resources if not (isinstance(r, kind) and r.metadata.name == name))
    )


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "error", [ManifestRenderError, ResourceConstraintError, TopologyConflictError]
)
def test_error_hierarchy(error: type[Exception]) -> None:
    assert issubclass(error, K8sAiCoreError)
    assert not issubclass(error, ValueError)


def test_topology_conflict_carries_violations() -> None:
    violations = (Violation("blocked-flow", "a -> b TCP/1"), Violation("x", "y"))
    err = TopologyConflictError("broken", violations)
    assert err.violations == violations
    assert str(err) == "broken\n  - [blocked-flow] a -> b TCP/1\n  - [x] y"


# ---------------------------------------------------------------------------
# YAML engine
# ---------------------------------------------------------------------------
def test_generated_yaml_passes_yamllint(rendered: str) -> None:
    config = YamlLintConfig(file=str(ROOT / ".yamllint.yaml"))
    problems = [f"{p.line}:{p.column} {p.rule} {p.message}" for p in linter.run(rendered, config)]
    assert problems == []


def test_multi_document_roundtrip(bundle: ManifestBundle, rendered: str, docs: list[Any]) -> None:
    assert docs == bundle.to_documents()
    assert rendered.count("\n---\n") + rendered.startswith("---\n") == len(bundle) == len(docs)
    reparsed = ManifestBundle.from_yaml(rendered)
    assert reparsed.ordered() == bundle.ordered()
    assert reparsed.to_yaml() == rendered


def test_every_document_validates_against_schema(docs: list[dict[str, Any]]) -> None:
    kinds: dict[str, type[K8sModel]] = {
        m.model_fields["kind"].default: m
        for m in (Deployment, Service, StatefulSet, NetworkPolicy, ScaledObject)
    }
    kinds["PersistentVolumeClaim"] = PersistentVolumeClaim
    for doc in docs:
        assert kinds[doc["kind"]].from_wire(doc).to_k8s() == doc


def test_output_is_deterministic(rendered: str) -> None:
    assert compile_ai_stack(InfraSettings(), stack()).to_yaml() == rendered
    assert build_ai_stack(InfraSettings(), stack()).to_yaml() == rendered


def test_yaml_is_plain(rendered: str) -> None:
    assert "!!" not in rendered
    assert "!python" not in rendered
    assert not re.search(r"[&*]id\d+", rendered), "anchors/aliases leaked"
    assert "'" not in rendered, "single-quoted scalars"
    assert "null" not in rendered
    assert "~" not in rendered


def test_ambiguous_strings_are_double_quoted(rendered: str, docs: list[Any]) -> None:
    trigger = find(docs, "ScaledObject", APP)["spec"]["triggers"][0]["metadata"]
    assert trigger["listLength"] == "5"
    assert trigger["enableTLS"] == "false"
    assert '        listLength: "5"\n' in rendered
    assert '        enableTLS: "false"\n' in rendered
    assert '            - "6379"\n' in rendered
    assert 'medium: ""' in rendered


def test_top_level_key_order(docs: list[dict[str, Any]]) -> None:
    for doc in docs:
        assert list(doc) == ["apiVersion", "kind", "metadata", "spec"]


def test_canonical_ordering() -> None:
    doc = {"status": {}, "data": {"k": "v"}, "spec": {}, "zz": 1, "kind": "X", "apiVersion": "v1"}
    assert list(canonical(doc)) == ["apiVersion", "kind", "spec", "data", "status", "zz"]
    labels = canonical({"metadata": {"labels": {"b": "2", "a": "1"}, "name": "x"}})
    assert list(labels["metadata"]["labels"]) == ["a", "b"]
    assert list(labels["metadata"]) == ["labels", "name"]  # only string maps are sorted
    nested = canonical({"spec": {"selector": {"matchLabels": {"z": "1", "a": "2"}}}})
    assert list(nested["spec"]["selector"]["matchLabels"]) == ["a", "z"]


def test_kind_apply_order(bundle: ManifestBundle) -> None:
    kinds = [r.kind for r in bundle]
    assert kinds == sorted(
        kinds,
        key=[
            "NetworkPolicy",
            "PersistentVolumeClaim",
            "Service",
            "Deployment",
            "StatefulSet",
            "ScaledObject",
        ].index,
    )
    assert kinds[0] == "NetworkPolicy"
    assert kinds[-1] == "ScaledObject"


def test_render_rejects_non_plain_objects() -> None:
    with pytest.raises(ManifestRenderError, match="cannot serialize"):
        render_yaml([{"apiVersion": "v1", "spec": {"x": object()}}])


def test_render_empty_bundle() -> None:
    assert ManifestBundle().to_yaml() == ""


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("---\nkey: [unclosed\n", "invalid YAML"),
        ("---\n- a\n- b\n", "not a mapping"),
        ("---\n!!python/object:os.system {}\n", "invalid YAML"),
        ("---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n", "unsupported manifest"),
        ("---\napiVersion: v1\nkind: Service\nmetadata:\n  name: x\nspec: {}\n", "Service x"),
    ],
)
def test_parse_errors(text: str, message: str) -> None:
    with pytest.raises(ManifestRenderError, match=message):
        ManifestBundle.from_yaml(text)


def test_parse_skips_empty_documents() -> None:
    assert parse_yaml("---\n---\na: 1\n---\n") == [{"a": 1}]


# ---------------------------------------------------------------------------
# Bundle
# ---------------------------------------------------------------------------
def test_bundle_rejects_duplicates(bundle: ManifestBundle) -> None:
    with pytest.raises(ManifestRenderError, match=f"duplicate Service {NS}/{APP}"):
        bundle.add(bundle.get(Service, APP))


def test_bundle_is_immutable_and_queryable(bundle: ManifestBundle) -> None:
    extra = Service(
        metadata=ObjectMeta(name="extra", namespace=NS),
        spec=ServiceSpec(selector=SEL[APP], ports=(ServicePort(name="h", port=1, target_port=1),)),
    )
    bigger = bundle.add(extra)
    assert len(bigger) == len(bundle) + 1
    assert extra not in bundle.of_kind(Service)
    assert [s.metadata.name for s in bundle.of_kind(Service)] == [
        APP,
        QDRANT,
        f"{QDRANT}-headless",
        REDIS,
    ]
    assert [w.metadata.name for w in bundle.workloads()] == [APP, REDIS, QDRANT]
    with pytest.raises(ManifestRenderError, match="no Deployment named 'nope'"):
        bundle.get(Deployment, "nope")


# ---------------------------------------------------------------------------
# Structure of the generated manifests
# ---------------------------------------------------------------------------
def test_common_metadata_and_labels(docs: list[dict[str, Any]]) -> None:
    for doc in docs:
        meta = doc["metadata"]
        assert meta["namespace"] == NS
        if doc["kind"] != "NetworkPolicy":
            assert meta["labels"]["app.kubernetes.io/part-of"] == "cloud-native-k8s-ai"
            assert meta["labels"]["environment"] == "dev"


def test_selectors_match_their_pods(docs: list[dict[str, Any]]) -> None:
    workloads = [d for d in docs if d["kind"] in {"Deployment", "StatefulSet"}]
    for workload in workloads:
        match = workload["spec"]["selector"]["matchLabels"]
        labels = workload["spec"]["template"]["metadata"]["labels"]
        assert match.items() <= labels.items()
        assert match == SEL[workload["metadata"]["name"]]
    for service in (d for d in docs if d["kind"] == "Service"):
        backends = [
            w
            for w in workloads
            if service["spec"]["selector"].items()
            <= w["spec"]["template"]["metadata"]["labels"].items()
        ]
        assert len(backends) == 1, service["metadata"]["name"]


def test_fastapi_deployment(docs: list[dict[str, Any]]) -> None:
    dep = find(docs, "Deployment", APP)
    pod = dep["spec"]["template"]["spec"]
    (api,) = pod["containers"]
    assert dep["spec"]["replicas"] == 2
    assert api["ports"] == [{"name": "http", "containerPort": 8000, "protocol": "TCP"}]
    assert api["readinessProbe"]["httpGet"] == {"path": "/readyz", "port": "http", "scheme": "HTTP"}
    assert api["livenessProbe"]["httpGet"]["path"] == "/healthz"
    assert api["startupProbe"]["httpGet"]["path"] == "/healthz"
    assert api["startupProbe"]["failureThreshold"] * api["startupProbe"]["periodSeconds"] == 300
    assert api["resources"] == {
        "requests": {"cpu": "250m", "memory": "512Mi"},
        "limits": {"cpu": "1", "memory": "1Gi"},
    }
    env = {e["name"]: e["value"] for e in api["env"]}
    assert env == {
        "QDRANT_HOST": f"qdrant.{NS}.svc.cluster.local",
        "QDRANT_HTTP_PORT": "6333",
        "QDRANT_GRPC_PORT": "6334",
        "REDIS_URL": f"redis://redis.{NS}.svc.cluster.local:6379/0",
        "REDIS_QUEUE": "inference-jobs",
        "TMPDIR": SCRATCH_PATH,
    }
    assert api["volumeMounts"] == [{"name": "scratch", "mountPath": "/scratch", "readOnly": False}]
    assert pod["automountServiceAccountToken"] is False


def test_every_container_is_restricted(docs: list[dict[str, Any]]) -> None:
    containers = [
        c
        for d in docs
        if d["kind"] in {"Deployment", "StatefulSet"}
        for c in d["spec"]["template"]["spec"]["containers"]
    ]
    assert len(containers) == 3
    for c in containers:
        ctx = c["securityContext"]
        assert ctx["runAsNonRoot"] is True
        assert ctx["readOnlyRootFilesystem"] is True
        assert ctx["allowPrivilegeEscalation"] is False
        assert ctx["capabilities"]["drop"] == ["ALL"]
        assert ctx["seccompProfile"] == {"type": "RuntimeDefault"}
        assert {"readinessProbe", "livenessProbe", "resources"} <= c.keys()
        assert not c["image"].endswith(":latest")


def test_fastapi_service(docs: list[dict[str, Any]]) -> None:
    assert find(docs, "Service", APP)["spec"] == {
        "type": "ClusterIP",
        "selector": SEL[APP],
        "ports": [{"name": "http", "port": 80, "targetPort": "http", "protocol": "TCP"}],
    }


def test_qdrant_statefulset_and_services(docs: list[dict[str, Any]]) -> None:
    sts = find(docs, "StatefulSet", QDRANT)["spec"]
    assert sts["serviceName"] == "qdrant-headless"
    assert sts["replicas"] == 1
    (qd,) = sts["template"]["spec"]["containers"]
    assert [(p["name"], p["containerPort"]) for p in qd["ports"]] == [
        ("rest", 6333),
        ("grpc", 6334),
    ]
    assert qd["readinessProbe"]["httpGet"]["path"] == "/readyz"
    assert qd["livenessProbe"]["httpGet"]["path"] == "/livez"
    assert {m["name"]: m["mountPath"] for m in qd["volumeMounts"]} == {
        "storage": "/qdrant/storage",
        "snapshots": "/qdrant/snapshots",
        "scratch": SCRATCH_PATH,
    }
    claims = {c["metadata"]["name"]: c["spec"] for c in sts["volumeClaimTemplates"]}
    assert claims["storage"]["resources"] == {"requests": {"storage": "20Gi"}}
    assert claims["snapshots"]["resources"] == {"requests": {"storage": "10Gi"}}
    headless = find(docs, "Service", "qdrant-headless")["spec"]
    client = find(docs, "Service", QDRANT)["spec"]
    assert headless["clusterIP"] == "None"
    assert "clusterIP" not in client
    for svc in (headless, client):
        assert [(p["name"], p["port"]) for p in svc["ports"]] == [("rest", 6333), ("grpc", 6334)]


def test_redis_deployment_with_persistence(docs: list[dict[str, Any]]) -> None:
    dep = find(docs, "Deployment", REDIS)["spec"]
    assert dep["replicas"] == 1
    assert dep["strategy"] == {"type": "Recreate"}
    (redis,) = dep["template"]["spec"]["containers"]
    args = redis["args"]
    assert args[args.index("--maxmemory") + 1] == str(768 * 2**20)
    assert args[args.index("--appendonly") + 1] == "yes"
    assert redis["readinessProbe"]["tcpSocket"] == {"port": "redis"}
    (data,) = dep["template"]["spec"]["volumes"]
    assert data == {
        "name": "data",
        "persistentVolumeClaim": {"claimName": "redis-data", "readOnly": False},
    }
    pvc = find(docs, "PersistentVolumeClaim", "redis-data")
    assert pvc["spec"]["resources"] == {"requests": {"storage": "8Gi"}}
    assert find(docs, "Service", REDIS)["spec"]["ports"][0]["port"] == 6379


def test_redis_without_persistence_uses_empty_dir() -> None:
    redis = RedisSpec(
        image="docker.io/library/redis:7.4.2-alpine",
        resources=res("100m", "256Mi", "500m", "1Gi"),
        maxmemory="512Mi",
        persistence=RedisPersistence(mode="none", volume_size=None),
    )
    built = compile_ai_stack(InfraSettings(), stack(redis=redis))
    assert not built.of_kind(PersistentVolumeClaim)
    volumes = built.get(Deployment, REDIS).spec.template.spec.volumes
    assert volumes[0].empty_dir is not None


def test_network_policy_set(docs: list[dict[str, Any]]) -> None:
    names = [d["metadata"]["name"] for d in docs if d["kind"] == "NetworkPolicy"]
    assert names == [
        "allow-dns-egress",
        "default-deny-all",
        "inference-api-allow-egress",
        "inference-api-allow-ingress",
        "qdrant-allow-from-app",
        "redis-allow-ingress",
    ]
    qdrant = find(docs, "NetworkPolicy", "qdrant-allow-from-app")["spec"]
    assert qdrant["podSelector"] == {"matchLabels": SEL[QDRANT]}
    assert qdrant["ingress"] == [
        {
            "from": [{"podSelector": {"matchLabels": SEL[APP]}}],
            "ports": [{"protocol": "TCP", "port": 6333}, {"protocol": "TCP", "port": 6334}],
        }
    ]
    deny = find(docs, "NetworkPolicy", "default-deny-all")["spec"]
    assert deny["podSelector"] == {}
    assert deny["policyTypes"] == ["Ingress", "Egress"]


def test_settings_drive_namespace_and_labels(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("K8SAI_NAMESPACE", "ai-prod")
    monkeypatch.setenv("K8SAI_ENVIRONMENT", "prod")
    built = compile_ai_stack(InfraSettings(), stack())
    assert {r.metadata.namespace for r in built} == {"ai-prod"}
    labels = built.get(Deployment, APP).metadata.labels
    assert labels is not None
    assert labels["environment"] == "prod"
    trigger = built.get(ScaledObject, APP).spec.triggers[0]
    assert trigger.metadata.address == "redis.ai-prod.svc.cluster.local:6379"


def test_custom_labels_are_merged() -> None:
    app = stack().app.model_copy(update={"labels": {"team": "ml-platform"}})
    built = compile_ai_stack(InfraSettings(), stack(app=app))
    labels = built.get(Deployment, APP).spec.template.metadata.labels
    assert labels is not None
    assert labels["team"] == "ml-platform"
    assert built.get(Deployment, APP).spec.selector.match_labels == SEL[APP]


def test_tls_broker_settings() -> None:
    built = compile_ai_stack(InfraSettings(), stack(autoscaling=AutoscalingPolicy(enable_tls=True)))
    env = {e.name: e.value for e in built.get(Deployment, APP).spec.template.spec.containers[0].env}
    assert env["REDIS_URL"] is not None
    assert env["REDIS_URL"].startswith("rediss://")
    assert (
        built.get(ScaledObject, APP).to_k8s()["spec"]["triggers"][0]["metadata"]["enableTLS"]
        == "true"
    )


@pytest.mark.parametrize(
    ("build", "error", "message"),
    [
        (
            lambda: generator(app=stack().app.model_copy(update={"name": "redis"})),
            ManifestRenderError,
            "distinct",
        ),
        (
            lambda: generator(qdrant=stack().qdrant.model_copy(update={"replicas": 3})),
            ResourceConstraintError,
            "exactly 1 replica",
        ),
        (
            lambda: generator(
                app=stack().app.model_copy(update={"labels": {"app.kubernetes.io/name": "spoofed"}})
            ).build(),
            ManifestRenderError,
            "managed by the generator",
        ),
        (
            lambda: generator(
                app=stack().app.model_copy(
                    update={"env": (EnvVar(name="QDRANT_HOST", value="evil.example"),)}
                )
            ).build(),
            ManifestRenderError,
            "duplicate env vars",
        ),
        (
            lambda: generator(qdrant=stack().qdrant.model_copy(update={"name": "q" * 60})).build(),
            ManifestRenderError,
            "Services for",
        ),
    ],
)
def test_generator_rejects_inconsistent_specs(
    build: Any, error: type[Exception], message: str
) -> None:
    with pytest.raises(error, match=message):
        build()


# ---------------------------------------------------------------------------
# Zero-trust topology solver
# ---------------------------------------------------------------------------
def test_compiled_stack_is_zero_trust(bundle: ManifestBundle) -> None:
    report = verify(bundle)
    assert report.ok, report.violations
    report.raise_for_violations()
    dns = {
        Flow(src, "kube-dns", p, 53)
        for src in (APP, QDRANT, REDIS, "intruder")
        for p in ("UDP", "TCP")
    }
    assert report.reachable == dns | {
        Flow("ingress-controller", APP, "TCP", 8000),
        Flow(APP, QDRANT, "TCP", 6333),
        Flow(APP, QDRANT, "TCP", 6334),
        Flow(APP, REDIS, "TCP", 6379),
        Flow("keda-operator", REDIS, "TCP", 6379),
    }


def test_qdrant_only_reachable_from_app(bundle: ManifestBundle) -> None:
    topo = generator().topology(bundle)
    qdrant = topo.endpoint(QDRANT)
    for src in topo.endpoints.values():
        for port in (6333, 6334, 6335, 22, 8000):
            allowed = topo.ingress_allowed(src, qdrant, "TCP", port)
            assert allowed is (src.name == APP and port in {6333, 6334}), (src.name, port)


ATTACKS: dict[str, tuple[dict[str, Any], set[str], str]] = {
    "all-namespaces-to-qdrant": (
        {
            "podSelector": {"matchLabels": SEL[QDRANT]},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": [{"namespaceSelector": {}}]}],
        },
        {"exclusive-ingress", "unauthorized-flow"},
        "qdrant admits mimic-inference-api",
    ),
    "internet-to-qdrant": (
        {
            "podSelector": {"matchLabels": SEL[QDRANT]},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": [{"ipBlock": {"cidr": "0.0.0.0/0"}}], "ports": [{"port": 6333}]}],
        },
        {"exclusive-ingress", "unauthorized-flow"},
        "qdrant admits internet on TCP/6333",
    ),
    "same-namespace-wildcard-to-qdrant": (
        {
            "podSelector": {"matchLabels": SEL[QDRANT]},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": [{"podSelector": {}}], "ports": [{"port": 6334}]}],
        },
        {"exclusive-ingress"},
        "qdrant admits intruder on TCP/6334",
    ),
    "app-to-qdrant-any-port": (
        {
            "podSelector": {"matchLabels": SEL[QDRANT]},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": [{"podSelector": {"matchLabels": SEL[APP]}}]}],
        },
        {"exclusive-ingress"},
        "qdrant admits inference-api on TCP/22",
    ),
    "qdrant-to-redis-cross-pod": (
        {
            "podSelector": {"matchLabels": SEL[REDIS]},
            "policyTypes": ["Ingress"],
            "ingress": [
                {"from": [{"podSelector": {"matchLabels": SEL[QDRANT]}}], "ports": [{"port": 6379}]}
            ],
        },
        {"exclusive-ingress"},
        "redis admits qdrant on TCP/6379",
    ),
    "app-egress-anywhere": (
        {
            "podSelector": {"matchLabels": SEL[APP]},
            "policyTypes": ["Egress"],
            "egress": [{"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}],
        },
        {"unauthorized-flow"},
        "inference-api -> internet TCP/443 is reachable but not intended",
    ),
    "public-api": (
        {
            "podSelector": {"matchLabels": SEL[APP]},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": [{"ipBlock": {"cidr": "0.0.0.0/0"}}], "ports": [{"port": 8000}]}],
        },
        {"exclusive-ingress", "unauthorized-flow"},
        "internet -> inference-api TCP/8000",
    ),
}


@pytest.mark.parametrize("attack", list(ATTACKS))
def test_solver_catches_bypass(bundle: ManifestBundle, attack: str) -> None:
    spec, codes, message = ATTACKS[attack]
    report = verify(bundle.add(policy(f"attack-{attack}", spec)))
    assert codes <= report.codes(), report.violations
    assert any(message in v.message for v in report.violations), report.violations
    with pytest.raises(TopologyConflictError, match="zero-trust topology violated"):
        report.raise_for_violations()


def test_solver_catches_missing_default_deny(bundle: ManifestBundle) -> None:
    report = verify(without(bundle, NetworkPolicy, "default-deny-all"))
    assert {"missing-default-deny", "unauthorized-flow"} <= report.codes()
    assert f"namespace {NS} has no default-deny" in str(report.violations)
    # Without the namespace-wide deny, unselected pods (the intruder) accept anything.
    assert "internet -> intruder TCP/22 is reachable" in str(report.violations)
    assert "-> qdrant" not in str(report.violations)  # qdrant ingress is still isolated


def test_solver_reports_non_isolated_workloads(bundle: ManifestBundle) -> None:
    stripped = without(
        without(bundle, NetworkPolicy, "default-deny-all"), NetworkPolicy, "allow-dns-egress"
    )
    report = verify(stripped)
    assert "not-isolated" in report.codes()
    messages = {v.message for v in report.violations if v.code == "not-isolated"}
    assert messages == {"qdrant is not isolated for egress", "redis is not isolated for egress"}


def test_selective_deny_is_not_a_default_deny(bundle: ManifestBundle) -> None:
    narrowed = without(bundle, NetworkPolicy, "default-deny-all").add(
        policy(
            "default-deny-all",
            {"podSelector": {"matchLabels": SEL[QDRANT]}, "policyTypes": ["Ingress", "Egress"]},
        )
    )
    assert "missing-default-deny" in verify(narrowed).codes()


def test_solver_catches_missing_dns_egress(bundle: ManifestBundle) -> None:
    report = verify(without(bundle, NetworkPolicy, "allow-dns-egress"))
    assert report.codes() == {"missing-dns-egress"}
    assert [v.message for v in report.violations] == [
        "inference-api cannot resolve names (UDP/53)",
        "inference-api cannot resolve names (TCP/53)",
    ]


def test_solver_catches_over_restrictive_policies(bundle: ManifestBundle) -> None:
    report = verify(without(bundle, NetworkPolicy, "inference-api-allow-egress"))
    assert report.codes() == {"blocked-flow"}
    assert {v.message for v in report.violations} == {
        "inference-api -> qdrant TCP/6333 is required but blocked",
        "inference-api -> qdrant TCP/6334 is required but blocked",
        "inference-api -> redis TCP/6379 is required but blocked",
    }
    keda = verify(without(bundle, NetworkPolicy, "redis-allow-ingress"))
    assert "keda-operator -> redis TCP/6379 is required but blocked" in str(keda.violations)
    assert "redis does not admit keda-operator on TCP/6379" in str(keda.violations)


def test_compile_refuses_leaky_topology() -> None:
    class Leaky(AIStackGenerator):
        def network_policies(self) -> tuple[NetworkPolicy, ...]:
            return tuple(
                p for p in super().network_policies() if p.metadata.name != "default-deny-all"
            )

    with pytest.raises(TopologyConflictError) as excinfo:
        Leaky(InfraSettings(), stack()).compile()
    assert "missing-default-deny" in {v.code for v in excinfo.value.violations}


# -- NetworkPolicy semantics ---------------------------------------------------
def _pod(name: str, labels: dict[str, str], ns: str = NS, **kw: Any) -> Endpoint:
    return Endpoint(name=name, namespace=ns, labels=labels, **kw)


DB = _pod("db", {"app": "db"}, ports={"pg": ("TCP", 5432)})
WEB = _pod("web", {"app": "web"})
EXT = Endpoint(name="ext", ip="198.51.100.7")


def _ingress_to_db(ingress: list[dict[str, Any]]) -> NetworkTopology:
    pol = policy(
        "db",
        {
            "podSelector": {"matchLabels": {"app": "db"}},
            "policyTypes": ["Ingress"],
            "ingress": ingress,
        },
    )
    return NetworkTopology([pol], [DB, WEB, EXT])


@pytest.mark.parametrize(
    ("ports", "protocol", "port", "allowed"),
    [
        ([{"port": "pg"}], "TCP", 5432, True),
        ([{"port": "pg"}], "TCP", 5433, False),
        ([{"port": "missing"}], "TCP", 5432, False),
        ([{"port": 5000, "endPort": 6000}], "TCP", 5432, True),
        ([{"port": 5000, "endPort": 6000}], "TCP", 6001, False),
        ([{"protocol": "UDP", "port": 5432}], "TCP", 5432, False),
        ([{"protocol": "UDP"}], "UDP", 9999, True),
        ([], "SCTP", 1, True),
    ],
)
def test_port_matching(ports: list[Any], protocol: Any, port: int, allowed: bool) -> None:
    topo = _ingress_to_db(
        [{"from": [{"podSelector": {"matchLabels": {"app": "web"}}}], "ports": ports}]
    )
    assert topo.ingress_allowed(WEB, DB, protocol, port) is allowed


@pytest.mark.parametrize(
    ("block", "allowed"),
    [
        ({"cidr": "198.51.100.0/24"}, True),
        ({"cidr": "198.51.100.0/24", "except": ["198.51.100.0/29"]}, False),
        ({"cidr": "10.0.0.0/8"}, False),
        ({"cidr": "2001:db8::/32"}, False),
    ],
)
def test_ip_block_matching(block: dict[str, Any], allowed: bool) -> None:
    topo = _ingress_to_db([{"from": [{"ipBlock": block}]}])
    assert topo.ingress_allowed(EXT, DB, "TCP", 5432) is allowed
    assert topo.ingress_allowed(WEB, DB, "TCP", 5432) is False  # ipBlock never matches pods


def test_namespace_and_pod_selectors_combine() -> None:
    other = _pod("other-web", {"app": "web"}, ns="other", namespace_labels={"team": "a"})
    pol = policy(
        "db",
        {
            "podSelector": {"matchLabels": {"app": "db"}},
            "policyTypes": ["Ingress"],
            "ingress": [
                {
                    "from": [
                        {
                            "namespaceSelector": {"matchLabels": {"team": "a"}},
                            "podSelector": {"matchLabels": {"app": "web"}},
                        }
                    ]
                }
            ],
        },
    )
    topo = NetworkTopology([pol], [DB, WEB, other])
    assert topo.ingress_allowed(other, DB, "TCP", 5432)
    assert not topo.ingress_allowed(WEB, DB, "TCP", 5432)  # same ns lacks team=a
    assert other.namespace_labels["kubernetes.io/metadata.name"] == "other"
    assert not topo.ingress_allowed(EXT, DB, "TCP", 5432)


def test_unisolated_and_external_destinations_accept_all() -> None:
    topo = _ingress_to_db([])
    assert topo.ingress_allowed(DB, WEB, "TCP", 1)  # web has no policy
    assert topo.ingress_allowed(DB, EXT, "TCP", 1)  # external hosts are not governed
    assert not topo.ingress_allowed(WEB, DB, "TCP", 5432)  # isolated, no rules
    assert topo.egress_allowed(EXT, DB, "TCP", 5432)
    assert topo.allows(Flow("db", "web", "TCP", 80))
    assert not topo.allows(Flow("web", "db", "TCP", 5432))


def test_topology_input_validation(bundle: ManifestBundle) -> None:
    with pytest.raises(TopologyConflictError, match="namespace xor an IP"):
        Endpoint(name="x")
    with pytest.raises(TopologyConflictError, match="namespace xor an IP"):
        Endpoint(name="x", namespace=NS, ip="10.0.0.1")
    with pytest.raises(TopologyConflictError, match="unique"):
        NetworkTopology([], [DB, DB])
    unnamespaced = NetworkPolicy.from_wire(
        {"metadata": {"name": "p"}, "spec": {"podSelector": {}, "policyTypes": ["Ingress"]}}
    )
    with pytest.raises(TopologyConflictError, match="has no namespace"):
        NetworkTopology([unnamespaced], [])
    topo = NetworkTopology([], [DB])
    with pytest.raises(TopologyConflictError, match="unknown endpoint 'nope'"):
        topo.endpoint("nope")
    with pytest.raises(TopologyConflictError, match="unknown DNS clients"):
        NetworkTopology.from_bundle(bundle, dns_clients={"ghost"})


def test_from_bundle_requires_namespaced_workloads() -> None:
    dep = Deployment(
        metadata=ObjectMeta(name="w"),
        spec=DeploymentSpec(
            selector=LabelSelector(match_labels={"app": "w"}),
            template=PodTemplateSpec(
                metadata=ObjectMeta(name="w", labels={"app": "w"}),
                spec=PodSpec(containers=(_container(),)),
            ),
        ),
    )
    with pytest.raises(TopologyConflictError, match="has no namespace"):
        NetworkTopology.from_bundle(ManifestBundle((dep,)))


def test_solver_without_dns_clients_or_exclusive_rules() -> None:
    pol = policy("deny", {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]})
    topo = NetworkTopology(
        [pol], [_pod("a", {"x": "1"}, managed=True), _pod("b", {"x": "2"}, managed=True)]
    )
    report = TopologySolver(topo).verify(ZeroTrustIntent())
    assert report.ok
    assert report.reachable == frozenset()
    blocked = TopologySolver(topo).verify(
        ZeroTrustIntent(required=frozenset({Flow("a", "b", "TCP", 80)}))
    )
    assert blocked.codes() == {"blocked-flow"}
    exclusive = ExclusiveIngress(dst="b", sources=frozenset({"a"}), ports=frozenset({("TCP", 80)}))
    assert "b does not admit a on TCP/80" in str(
        TopologySolver(topo).verify(ZeroTrustIntent(exclusive_ingress=(exclusive,))).violations
    )


# ---------------------------------------------------------------------------
# Autoscaling resolver
# ---------------------------------------------------------------------------
def test_redis_queue_maps_to_scaled_object(bundle: ManifestBundle) -> None:
    scaled = bundle.get(ScaledObject, APP).to_k8s()
    assert scaled["spec"]["scaleTargetRef"] == {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "name": APP,
    }
    assert (scaled["spec"]["minReplicaCount"], scaled["spec"]["maxReplicaCount"]) == (1, 10)
    assert (scaled["spec"]["pollingInterval"], scaled["spec"]["cooldownPeriod"]) == (30, 300)
    (trigger,) = scaled["spec"]["triggers"]
    assert trigger["type"] == "redis"
    assert trigger["metadata"] == {
        "address": f"redis.{NS}.svc.cluster.local:6379",
        "databaseIndex": "0",
        "enableTLS": "false",
        "listName": "inference-jobs",
        "listLength": "5",
        "activationListLength": "0",
    }


def test_custom_queue_policy_is_bound() -> None:
    policy_ = AutoscalingPolicy(
        list_name="embeddings:pending",
        list_length=20,
        activation_list_length=3,
        min_replicas=1,
        idle_replicas=0,
        max_replicas=40,
        cooldown_period=120,
        polling_interval=15,
        database_index=2,
        authentication_ref="redis-auth",
    )
    built = compile_ai_stack(InfraSettings(), stack(autoscaling=policy_))
    scaled = built.get(ScaledObject, APP).to_k8s()
    assert scaled["spec"]["idleReplicaCount"] == 0
    (trigger,) = scaled["spec"]["triggers"]
    assert trigger["metadata"]["listName"] == "embeddings:pending"
    assert (trigger["metadata"]["listLength"], trigger["metadata"]["activationListLength"]) == (
        "20",
        "3",
    )
    assert trigger["metadata"]["databaseIndex"] == "2"
    assert trigger["authenticationRef"] == {"name": "redis-auth", "kind": "TriggerAuthentication"}
    env = {e.name: e.value for e in built.get(Deployment, APP).spec.template.spec.containers[0].env}
    assert env["REDIS_QUEUE"] == "embeddings:pending"
    assert env["REDIS_URL"] is not None
    assert env["REDIS_URL"].endswith(":6379/2")


@pytest.mark.parametrize(
    ("kwargs", "queue", "replicas"),
    [
        ({}, 0, 1),
        ({}, 1, 1),
        ({}, 5, 1),
        ({}, 6, 2),
        ({}, 23, 5),
        ({}, 10_000, 10),
        ({"min_replicas": 0}, 0, 0),
        ({"min_replicas": 0}, 1, 1),
        ({"min_replicas": 3}, 1, 3),
        ({"activation_list_length": 10}, 10, 1),
        ({"activation_list_length": 10}, 11, 3),
        ({"min_replicas": 2, "idle_replicas": 0, "activation_list_length": 4}, 4, 0),
        ({"min_replicas": 2, "idle_replicas": 0, "activation_list_length": 4}, 5, 2),
    ],
)
def test_desired_replicas(kwargs: dict[str, Any], queue: int, replicas: int) -> None:
    assert desired_replicas(AutoscalingPolicy(**kwargs), queue) == replicas


def test_desired_replicas_rejects_negative_queue() -> None:
    with pytest.raises(ValueError, match="negative"):
        desired_replicas(AutoscalingPolicy(), -1)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"min_replicas": 5, "max_replicas": 2}, "min_replicas 5 exceeds max_replicas 2"),
        ({"idle_replicas": 1, "min_replicas": 1}, "idle_replicas 1 must be lower"),
        ({"cooldown_period": 10, "polling_interval": 30}, "shorter than polling_interval"),
    ],
)
def test_policy_bounds(kwargs: dict[str, Any], message: str) -> None:
    with pytest.raises(ResourceConstraintError, match=message):
        check_policy(AutoscalingPolicy(**kwargs))
    with pytest.raises(ResourceConstraintError, match=message):
        compile_ai_stack(InfraSettings(), stack(autoscaling=AutoscalingPolicy(**kwargs)))


def _resolver() -> AutoscalingResolver:
    return AutoscalingResolver(generator().workloads_bundle())


@pytest.mark.parametrize(
    ("target", "broker", "message"),
    [
        ("nope", REDIS, "target 'nope' is not a Deployment/StatefulSet"),
        (APP, "nope", "broker service 'nope' not found"),
        (APP, APP, "routes to the target itself"),
    ],
)
def test_resolver_binding_errors(target: str, broker: str, message: str) -> None:
    with pytest.raises(TopologyConflictError, match=message):
        _resolver().resolve(AutoscalingPolicy(), target=target, broker=broker)


def test_resolver_rejects_broker_without_backends() -> None:
    orphan = Service(
        metadata=ObjectMeta(name="orphan", namespace=NS),
        spec=ServiceSpec(
            selector={"app": "ghost"},
            ports=(ServicePort(name="redis", port=6379, target_port=6379),),
        ),
    )
    resolver = AutoscalingResolver(generator().workloads_bundle().add(orphan))
    with pytest.raises(TopologyConflictError, match="selects no workload"):
        resolver.resolve(AutoscalingPolicy(), target=APP, broker="orphan")


def test_resolver_ignores_workloads_in_other_namespaces() -> None:
    # Same labels, other namespace: a Service never routes across namespaces.
    foreign = (
        generator()
        .redis_deployment()
        .model_copy(
            update={
                "metadata": ObjectMeta(name="redis-foreign", namespace="other", labels=SEL[REDIS])
            }
        )
    )
    base = without(generator().workloads_bundle(), Deployment, REDIS).add(foreign)
    with pytest.raises(TopologyConflictError, match="selects no workload"):
        AutoscalingResolver(base).resolve(AutoscalingPolicy(), target=APP, broker=REDIS)


def test_resolver_rejects_initial_replicas_outside_bounds() -> None:
    with pytest.raises(
        ResourceConstraintError, match="starts with 2 replicas, outside \\[3, 10\\]"
    ):
        _resolver().resolve(AutoscalingPolicy(min_replicas=3), target=APP, broker=REDIS)


@pytest.mark.parametrize(
    ("budget", "message"),
    [
        (ResourceBudget(cpu="8", memory="64Gi"), "need 10000m CPU, budget is 8"),
        (ResourceBudget(cpu="16", memory="8Gi"), "need 10737418240 bytes of memory"),
    ],
)
def test_resource_budget_enforced(budget: ResourceBudget, message: str) -> None:
    with pytest.raises(ResourceConstraintError, match=message):
        compile_ai_stack(InfraSettings(), stack(budget=budget))


def test_resource_budget_fits() -> None:
    built = compile_ai_stack(InfraSettings(), stack(budget=ResourceBudget(cpu="10", memory="10Gi")))
    assert built.get(ScaledObject, APP).spec.max_replica_count == 10


def _broker_bundle(ports: tuple[ServicePort, ...]) -> AutoscalingResolver:
    base = without(generator().workloads_bundle(), Service, REDIS)
    svc = Service(
        metadata=ObjectMeta(name=REDIS, namespace=NS),
        spec=ServiceSpec(selector=SEL[REDIS], ports=ports),
    )
    return AutoscalingResolver(base.add(svc))


@pytest.mark.parametrize(
    ("ports", "address_port"),
    [
        ((ServicePort(name="cache", port=7000, target_port=6379),), 7000),
        (
            (
                ServicePort(name="metrics", port=9121, target_port=9121),
                ServicePort(name="redis", port=7001, target_port=6379),
            ),
            7001,
        ),
        (
            (
                ServicePort(name="metrics", port=9121, target_port=9121),
                ServicePort(name="main", port=6379, target_port=6379),
            ),
            6379,
        ),
    ],
)
def test_broker_port_selection(ports: tuple[ServicePort, ...], address_port: int) -> None:
    scaled = _broker_bundle(ports).resolve(AutoscalingPolicy(), target=APP, broker=REDIS)
    assert scaled.spec.triggers[0].metadata.address.endswith(f":{address_port}")


def test_broker_port_ambiguous() -> None:
    ports = (
        ServicePort(name="a", port=7000, target_port=6379),
        ServicePort(name="b", port=7001, target_port=6379),
    )
    with pytest.raises(TopologyConflictError, match="which port"):
        _broker_bundle(ports).resolve(AutoscalingPolicy(), target=APP, broker=REDIS)


def test_statefulset_target_and_bind() -> None:
    resolver = _resolver()
    scaled = resolver.resolve(AutoscalingPolicy(), target=QDRANT, broker=REDIS)
    assert scaled.spec.scale_target_ref.kind == "StatefulSet"
    bound = resolver.bind(AutoscalingPolicy(), target=APP, broker=REDIS)
    assert bound.get(ScaledObject, APP).spec.scale_target_ref.name == APP


def test_resolver_requires_namespaced_objects() -> None:
    dep = Deployment(
        metadata=ObjectMeta(name="w"),
        spec=DeploymentSpec(
            selector=LabelSelector(match_labels={"app": "w"}),
            template=PodTemplateSpec(
                metadata=ObjectMeta(name="w", labels={"app": "w"}),
                spec=PodSpec(containers=(_container(),)),
            ),
        ),
    )
    broker_pod = dep.model_copy(
        update={
            "metadata": ObjectMeta(name="b"),
            "spec": dep.spec.model_copy(
                update={
                    "selector": LabelSelector(match_labels={"app": "b"}),
                    "template": PodTemplateSpec(
                        metadata=ObjectMeta(name="b", labels={"app": "b"}),
                        spec=PodSpec(containers=(_container(),)),
                    ),
                }
            ),
        }
    )
    svc = Service(
        metadata=ObjectMeta(name="b"),
        spec=ServiceSpec(
            selector={"app": "b"}, ports=(ServicePort(name="redis", port=6379, target_port=6379),)
        ),
    )
    with pytest.raises(TopologyConflictError, match="must be namespaced"):
        AutoscalingResolver(ManifestBundle((dep, broker_pod, svc))).resolve(
            AutoscalingPolicy(), target="w", broker="b"
        )


def test_service_host() -> None:
    assert service_host("redis", "ai-system") == "redis.ai-system.svc.cluster.local"


def _container() -> Container:
    probe = Probe(http_get=HTTPGetAction(path="/healthz", port="http"))
    return Container(
        name="c",
        image="ghcr.io/mikez98/w:1.0.0",
        ports=(ContainerPort(name="http", container_port=8080),),
        resources=res("100m", "128Mi", "200m", "256Mi"),
        readiness_probe=probe,
        liveness_probe=probe,
    )


def test_untrusted_yaml_nesting_is_bounded() -> None:
    from cloud_native_k8s_ai.core import MAX_YAML_DEPTH, parse_untrusted_yaml  # noqa: PLC0415

    def nested(depth: int) -> str:
        return "{a: " * depth + "1" + "}" * depth

    assert parse_untrusted_yaml(nested(MAX_YAML_DEPTH))[0]["a"]
    with pytest.raises(ManifestRenderError, match=f"deeper than {MAX_YAML_DEPTH} levels"):
        parse_untrusted_yaml(nested(MAX_YAML_DEPTH + 1))
    with pytest.raises(ManifestRenderError, match="deeper than"):
        parse_untrusted_yaml("[" * 50_000 + "]" * 50_000)  # would exhaust the stack
