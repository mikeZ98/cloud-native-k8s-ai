"""Phase 7 verification: property-based invariants and concurrency stress.

Hypothesis generates whole AI stacks from the valid input space of the contracts
(replicas, CPU in millicores or cores, memory in Mi/Gi, every port in 1..65535, label
and env extras, every persistence mode) and checks the system-wide invariants on each:
the bundle is zero trust, the admission engine allows it, YAML round trips are exact and
the Helm chart renders the very same objects. The concurrency tests drive the control
plane with tens of parallel requests over ``httpx.AsyncClient``.
"""

from __future__ import annotations

import asyncio
import io
import os
import string
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from fastapi import FastAPI
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from cloud_native_k8s_ai.api import API_PREFIX, ApiSettings, create_app
from cloud_native_k8s_ai.core import (
    AIStackGenerator,
    AIStackSpec,
    AutoscalingPolicy,
    ManifestBundle,
    TopologySolver,
    compile_ai_stack,
)
from cloud_native_k8s_ai.guardrails import AdmissionEngine, GuardrailDecision
from cloud_native_k8s_ai.schemas import (
    ContainerPort,
    Deployment,
    EnvVar,
    FastAPIAppSpec,
    InfraSettings,
    PersistentVolumeClaim,
    QdrantSpec,
    QdrantVolume,
    RdbSavePoint,
    RedisListTriggerMetadata,
    RedisPersistence,
    RedisSpec,
    ResourceList,
    ResourceRequirements,
    ScaledObject,
    Service,
    StatefulSet,
    cpu_millicores,
    memory_bytes,
)
from cloud_native_k8s_ai.tools.helm import Chart, Release, lint_chart

ROOT = Path(__file__).resolve().parent.parent
CHART_DIR = ROOT / "deploy" / "helm" / "cloud-native-k8s-ai"


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("K8SAI_"):
            monkeypatch.delenv(key)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------
LABEL = st.from_regex(r"\A[a-z]([a-z0-9-]{0,14}[a-z0-9])?\Z")
PORT = st.integers(min_value=1, max_value=65535)
INJECTED_ENV = frozenset(
    {"QDRANT_HOST", "QDRANT_HTTP_PORT", "QDRANT_GRPC_PORT", "REDIS_URL", "REDIS_QUEUE", "TMPDIR"}
)


def cpu_text(millicores: int, *, cores: bool) -> str:
    """``250m`` or ``0.25``: both Kubernetes spellings of the same quantity."""
    if not cores:
        return f"{millicores}m"
    return format((Decimal(millicores) / 1000).normalize(), "f")


def memory_text(mebibytes: int, *, gibibytes: bool) -> str:
    if gibibytes and mebibytes % 1024 == 0:
        return f"{mebibytes // 1024}Gi"
    return f"{mebibytes}Mi"


@st.composite
def resources(draw: st.DrawFn, *, min_memory_mi: int = 1) -> ResourceRequirements:
    limit_cpu = draw(st.integers(1, 16_000))
    request_cpu = draw(st.integers(1, limit_cpu))
    limit_mi = draw(st.integers(min_memory_mi, 65_536))
    request_mi = draw(st.integers(1, limit_mi))

    def entry(cpu: int, mi: int) -> ResourceList:
        return ResourceList(
            cpu=cpu_text(cpu, cores=draw(st.booleans())),
            memory=memory_text(mi, gibibytes=draw(st.booleans())),
        )

    return ResourceRequirements(
        requests=entry(request_cpu, request_mi), limits=entry(limit_cpu, limit_mi)
    )


@st.composite
def images(draw: st.DrawFn) -> str:
    repository = draw(st.from_regex(r"\A[a-z][a-z0-9]{0,8}(-[a-z0-9]{1,6})?\Z"))
    tag = draw(st.from_regex(r"\A[a-z0-9][a-z0-9._-]{0,10}\Z").filter(lambda t: t != "latest"))
    image = f"ghcr.io/mikez98/{repository}:{tag}"
    if draw(st.booleans()):
        image += "@sha256:" + draw(st.text("0123456789abcdef", min_size=64, max_size=64))
    return image


@st.composite
def extra_labels(draw: st.DrawFn) -> dict[str, str]:
    keys = draw(st.lists(st.sampled_from(("team", "tier", "cost-center")), unique=True, max_size=3))
    return {k: draw(st.from_regex(r"\A[a-z0-9]([a-z0-9-]{0,8}[a-z0-9])?\Z")) for k in keys}


@st.composite
def extra_env(draw: st.DrawFn) -> tuple[EnvVar, ...]:
    names = draw(
        st.lists(
            st.from_regex(r"\A[A-Z][A-Z0-9_]{0,10}\Z").filter(lambda n: n not in INJECTED_ENV),
            unique=True,
            max_size=3,
        )
    )
    alphabet = string.ascii_letters + string.digits + " :/=.,-_#'\"{}[]"
    return tuple(EnvVar(name=n, value=draw(st.text(alphabet, max_size=20))) for n in names)


@st.composite
def autoscaling(draw: st.DrawFn, *, advisory: bool) -> AutoscalingPolicy:
    """Replica bounds and timings; ``advisory`` reaches the WARN-only corners
    (polling under 5s, a zero-width replica range) the critic flags but never denies."""
    low = draw(st.integers(0, 5))
    high = draw(st.integers(low if advisory else low + 1, low + 50))
    polling = draw(st.integers(1, 4)) if advisory else draw(st.integers(5, 3600))
    if advisory and draw(st.booleans()):
        high = max(low, 1)
    idle = draw(st.none() | st.integers(0, low - 1)) if low > 0 else None
    return AutoscalingPolicy(
        list_name=draw(st.from_regex(r"\A[a-z][a-z0-9:_-]{0,20}\Z")),
        list_length=draw(st.integers(1, 10_000)),
        activation_list_length=draw(st.integers(0, 100)),
        min_replicas=low,
        max_replicas=max(high, 1),
        idle_replicas=idle,
        polling_interval=polling,
        cooldown_period=draw(st.integers(polling, 86_400)),
        database_index=draw(st.integers(0, 15)),
        enable_tls=draw(st.booleans()),
    )


@st.composite
def ai_stacks(draw: st.DrawFn, *, advisory: bool = False) -> tuple[InfraSettings, AIStackSpec]:
    app, qdrant, redis, namespace, ingress, keda = draw(
        st.lists(LABEL, min_size=6, max_size=6, unique=True)
    )
    policy = draw(autoscaling(advisory=advisory))
    rest, grpc = draw(st.lists(PORT, min_size=2, max_size=2, unique=True))
    redis_resources = draw(resources(min_memory_mi=2))
    limit_mi = memory_bytes(redis_resources.limits.memory) // 2**20
    mode: Any = draw(st.sampled_from(("none", "rdb", "aof", "rdb+aof")))
    persistence = RedisPersistence(
        mode=mode,
        appendfsync=draw(st.sampled_from(("always", "everysec", "no"))),
        save_points=tuple(
            RdbSavePoint(seconds=s, changes=c)
            for s, c in draw(
                st.lists(
                    st.tuples(st.integers(1, 86_400), st.integers(1, 10**6)), min_size=1, max_size=3
                )
            )
        ),
        volume_size=None if mode == "none" else f"{draw(st.integers(1, 500))}Gi",
        storage_class_name=draw(st.none() | LABEL) if mode != "none" else None,
    )
    spec = AIStackSpec(
        app=FastAPIAppSpec(
            name=app,
            image=draw(images()),
            replicas=draw(st.integers(policy.min_replicas, policy.max_replicas)),
            container_port=draw(PORT),
            service_port=draw(PORT),
            resources=draw(resources()),
            env=draw(extra_env()),
            labels=draw(extra_labels()),
        ),
        qdrant=QdrantSpec(
            name=qdrant,
            image=draw(images()),
            rest_port=rest,
            grpc_port=grpc,
            resources=draw(resources()),
            storage=QdrantVolume(
                size=f"{draw(st.integers(1, 2000))}Gi",
                mount_path="/qdrant/storage",
                storage_class_name=draw(st.none() | LABEL),
            ),
            snapshots=QdrantVolume(
                size=f"{draw(st.integers(1, 500))}Gi", mount_path="/qdrant/snapshots"
            ),
            labels=draw(extra_labels()),
        ),
        redis=RedisSpec(
            name=redis,
            image=draw(images()),
            port=draw(PORT),
            resources=redis_resources,
            maxmemory=memory_text(
                draw(st.integers(1, limit_mi - 1)), gibibytes=draw(st.booleans())
            ),
            maxmemory_policy=draw(st.sampled_from(("noeviction", "allkeys-lru", "volatile-ttl"))),
            persistence=persistence,
            labels=draw(extra_labels()),
        ),
        autoscaling=policy,
        ingress_namespace=ingress,
        keda_namespace=keda,
    )
    settings_ = InfraSettings(
        environment=draw(st.sampled_from(("dev", "staging", "prod"))), namespace=namespace
    )
    return settings_, spec


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------
@given(ai_stacks())
def test_every_valid_stack_is_zero_trust_and_admitted(
    stack: tuple[InfraSettings, AIStackSpec],
) -> None:
    settings_, spec = stack
    bundle = compile_ai_stack(settings_, spec)
    generator = AIStackGenerator(settings_, spec)
    assert TopologySolver(generator.topology(bundle)).verify(generator.intent()).ok
    engine = AdmissionEngine.for_stack(settings_, spec)
    for manifests in (bundle, bundle.to_yaml()):
        report = engine.evaluate(manifests)
        assert report.decision is GuardrailDecision.ALLOW, [str(v) for v in report.violations]
        assert {o.decision for o in report.objects} == {GuardrailDecision.ALLOW}


@given(ai_stacks(advisory=True))
def test_advisory_corners_warn_but_never_deny(stack: tuple[InfraSettings, AIStackSpec]) -> None:
    settings_, spec = stack
    report = AdmissionEngine.for_stack(settings_, spec).evaluate(compile_ai_stack(settings_, spec))
    assert report.decision is not GuardrailDecision.DENY
    assert report.codes() <= {"keda-polling-too-aggressive", "keda-no-scaling-range"}
    assert (report.decision is GuardrailDecision.WARN) == bool(report.violations)


@given(ai_stacks())
def test_yaml_round_trip_is_exact_and_preserves_the_spec(
    stack: tuple[InfraSettings, AIStackSpec],
) -> None:
    settings_, spec = stack
    bundle = compile_ai_stack(settings_, spec)
    text = bundle.to_yaml()
    loaded = ManifestBundle.from_yaml(text)
    assert loaded.to_documents() == bundle.to_documents()
    assert loaded.to_yaml() == text  # byte-stable
    assert list(yaml.safe_load_all(text)) == bundle.to_documents()
    assert AIStackSpec.from_wire(spec.to_wire()) == spec
    assert {r.metadata.namespace for r in loaded} == {settings_.namespace}

    app, qdrant, redis, policy = spec.app, spec.qdrant, spec.redis, spec.autoscaling
    api = loaded.get(Deployment, app.name)
    container = api.spec.template.spec.containers[0]
    assert api.spec.replicas == app.replicas
    assert (container.image, container.resources) == (app.image, app.resources)
    assert container.ports[0].container_port == app.container_port
    assert {e.name: e.value for e in container.env}.items() >= {
        e.name: e.value for e in app.env
    }.items()
    assert loaded.get(Service, app.name).spec.ports[0].port == app.service_port
    store = loaded.get(StatefulSet, qdrant.name).spec
    assert [p.container_port for p in store.template.spec.containers[0].ports] == [
        qdrant.rest_port,
        qdrant.grpc_port,
    ]
    assert [c.spec.resources.requests.storage for c in store.volume_claim_templates] == [
        qdrant.storage.size,
        qdrant.snapshots.size,
    ]
    args = loaded.get(Deployment, redis.name).spec.template.spec.containers[0].args or ()
    assert args[args.index("--maxmemory") + 1] == str(memory_bytes(redis.maxmemory))
    assert args[args.index("--port") + 1] == str(redis.port)
    claims = loaded.of_kind(PersistentVolumeClaim)
    assert [c.spec.resources.requests.storage for c in claims] == (
        [redis.persistence.volume_size] if redis.persistence.volume_size else []
    )
    scaled = loaded.get(ScaledObject, app.name).spec
    assert (scaled.min_replica_count, scaled.max_replica_count) == (
        policy.min_replicas,
        policy.max_replicas,
    )
    assert (scaled.polling_interval, scaled.cooldown_period, scaled.idle_replica_count) == (
        policy.polling_interval,
        policy.cooldown_period,
        policy.idle_replicas,
    )
    trigger = scaled.triggers[0].metadata
    assert isinstance(trigger, RedisListTriggerMetadata)
    assert (trigger.list_name, trigger.list_length) == (policy.list_name, policy.list_length)
    assert trigger.address.endswith(f":{redis.port}")


def _image(reference: str) -> dict[str, str]:
    name, _, digest = reference.partition("@")
    repository, _, tag = name.rpartition(":")
    return {"repository": repository, "tag": tag} | ({"digest": digest} if digest else {})


def chart_values(settings_: InfraSettings, spec: AIStackSpec) -> dict[str, Any]:
    """The Helm values that describe ``spec`` (the inverse of ``tools.helm``'s mapping)."""
    app, qdrant, redis, policy = spec.app, spec.qdrant, spec.redis, spec.autoscaling
    persistence = redis.persistence

    def volume(v: QdrantVolume) -> dict[str, str]:
        return {
            "size": v.size,
            "mountPath": v.mount_path,
            "storageClassName": v.storage_class_name or "",
        }

    scaling: dict[str, Any] = {
        "enabled": True,
        "listName": policy.list_name,
        "listLength": policy.list_length,
        "activationListLength": policy.activation_list_length,
        "minReplicas": policy.min_replicas,
        "maxReplicas": policy.max_replicas,
        "cooldownPeriod": policy.cooldown_period,
        "pollingInterval": policy.polling_interval,
        "databaseIndex": policy.database_index,
        "enableTLS": policy.enable_tls,
    }
    if policy.idle_replicas is not None:
        scaling["idleReplicas"] = policy.idle_replicas
    return {
        "environment": settings_.environment,
        "api": {
            "name": app.name,
            "image": _image(app.image),
            "replicas": app.replicas,
            "containerPort": app.container_port,
            "service": {"port": app.service_port},
            "probes": {"livenessPath": app.liveness_path, "readinessPath": app.readiness_path},
            "resources": app.resources.to_wire(),
            "env": [e.to_wire() for e in app.env],
            "labels": dict(app.labels),
        },
        "qdrant": {
            "name": qdrant.name,
            "image": _image(qdrant.image),
            "ports": {"rest": qdrant.rest_port, "grpc": qdrant.grpc_port},
            "resources": qdrant.resources.to_wire(),
            "persistence": {
                "storage": volume(qdrant.storage),
                "snapshots": volume(qdrant.snapshots),
            },
            "labels": dict(qdrant.labels),
        },
        "redis": {
            "name": redis.name,
            "image": _image(redis.image),
            "port": redis.port,
            "resources": redis.resources.to_wire(),
            "maxmemory": redis.maxmemory,
            "maxmemoryPolicy": redis.maxmemory_policy,
            "dataMountPath": redis.data_mount_path,
            "persistence": {
                "mode": persistence.mode,
                "appendfsync": persistence.appendfsync,
                "savePoints": [p.to_wire() for p in persistence.save_points],
                "size": persistence.volume_size or "8Gi",
                "storageClassName": persistence.storage_class_name or "",
            },
            "labels": dict(redis.labels),
        },
        "autoscaling": scaling,
        "networkPolicy": {
            "ingressController": {"namespace": spec.ingress_namespace},
            "kedaOperator": {
                "namespace": spec.keda_namespace,
                "podLabels": dict(spec.keda_operator_labels),
            },
        },
    }


@pytest.fixture(scope="module")
def chart() -> Chart:
    return Chart.load(CHART_DIR)


@settings(max_examples=25)
@given(stack=ai_stacks())
def test_helm_chart_renders_exactly_the_core_bundle(
    chart: Chart, stack: tuple[InfraSettings, AIStackSpec]
) -> None:
    settings_, spec = stack
    release = Release(namespace=settings_.namespace)
    values = chart_values(settings_, spec)
    report = lint_chart(chart, {"generated": values}, release, include_defaults=False)
    assert report.ok, report.findings


@given(st.integers(1, 10**6), st.booleans())
def test_cpu_spellings_agree(millicores: int, cores: bool) -> None:
    assert cpu_millicores(cpu_text(millicores, cores=cores)) == millicores


@given(st.integers(1, 2**20), st.booleans())
def test_memory_spellings_agree(mebibytes: int, gibibytes: bool) -> None:
    assert memory_bytes(memory_text(mebibytes, gibibytes=gibibytes)) == mebibytes * 2**20


@given(PORT)
def test_every_port_in_range_is_accepted(port: int) -> None:
    assert ContainerPort(name="p", container_port=port).container_port == port


@given(st.integers().filter(lambda p: not 1 <= p <= 65535))
def test_every_port_out_of_range_is_rejected(port: int) -> None:
    with pytest.raises(ValidationError):
        ContainerPort(name="p", container_port=port)


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------
PARALLEL = 50
COMPILE = f"{API_PREFIX}/compile"
ADMISSION = f"{API_PREFIX}/validate/admission"
STREAM = f"{API_PREFIX}/stream/compile"


@pytest.fixture
def app() -> FastAPI:
    return create_app(ApiSettings(chart_dir=CHART_DIR), log_stream=io.StringIO())


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://control-plane") as http,
    ):
        yield http


def sample(app: FastAPI, name: str, labels: dict[str, str] | None = None) -> float:
    value = app.state.metrics.registry.get_sample_value(name, labels or {})
    return 0.0 if value is None else float(value)


async def gather_bounded(*calls: Any) -> list[httpx.Response]:
    """Run every request at once; a deadlock fails the test instead of hanging it."""
    return list(await asyncio.wait_for(asyncio.gather(*calls), timeout=120))


async def test_parallel_compile_and_admission(app: FastAPI, client: httpx.AsyncClient) -> None:
    spec = app.state.plane.reference.to_wire()
    manifests = (await client.post(COMPILE, params={"format": "yaml"}, json=spec)).text
    before = asyncio.all_tasks()
    responses = await gather_bounded(
        *(client.post(COMPILE, json=spec) for _ in range(PARALLEL // 2)),
        *(client.post(ADMISSION, json={"manifests": manifests}) for _ in range(PARALLEL // 2)),
    )
    assert [r.status_code for r in responses] == [200] * PARALLEL
    compiled, admitted = responses[: PARALLEL // 2], responses[PARALLEL // 2 :]
    assert len({r.content for r in compiled}) == 1  # deterministic under concurrency
    assert {r.json()["report"]["decision"] for r in admitted} == {"ALLOW"}
    assert len({r.headers["x-request-id"] for r in responses}) == PARALLEL
    await asyncio.sleep(0)
    assert {t for t in asyncio.all_tasks() - before if not t.done()} == set()

    route = {"method": "POST", "route": COMPILE, "status": "200"}
    assert sample(app, "http_requests_total", route) == PARALLEL // 2 + 1
    assert sample(
        app, "http_request_duration_seconds_count", {"method": "POST", "route": COMPILE}
    ) == (PARALLEL // 2 + 1)
    assert sample(app, "manifest_compilations_total", {"outcome": "success"}) == PARALLEL // 2 + 1
    assert sample(app, "manifest_documents_total", {"kind": "NetworkPolicy"}) == 6 * (
        PARALLEL // 2 + 1
    )
    assert (
        sample(app, "validations_total", {"target": "admission", "outcome": "allow"})
        == PARALLEL // 2
    )
    assert sample(app, "http_requests_in_flight") == 0


async def test_parallel_mixed_traffic_keeps_metrics_exact(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    spec = app.state.plane.reference.to_wire()
    invalid = {
        **spec,
        "stack": {**spec["stack"], "autoscaling": {"minReplicas": 5, "maxReplicas": 3}},
    }
    responses = await gather_bounded(
        *(client.post(COMPILE, json=spec) for _ in range(20)),
        *(client.post(COMPILE, json=invalid) for _ in range(20)),
        *(client.get(STREAM) for _ in range(10)),
    )
    statuses = [r.status_code for r in responses]
    assert statuses == [200] * 20 + [422] * 20 + [200] * 10
    assert {r.json()["type"].rsplit(":", 1)[1] for r in responses[20:40]} == {"resource-constraint"}
    assert all(r.text.count("event: manifest") == 15 for r in responses[40:])
    assert sample(app, "manifest_compilations_total", {"outcome": "success"}) == 30
    assert sample(app, "manifest_compilations_total", {"outcome": "failure"}) == 20
    assert sample(app, "manifest_streams_total", {"outcome": "completed"}) == 10
    failed = {"method": "POST", "route": COMPILE, "status": "422"}
    assert sample(app, "http_requests_total", failed) == 20
    assert sample(app, "http_requests_in_flight") == 0


async def test_parallel_chart_validation(app: FastAPI, client: httpx.AsyncClient) -> None:
    overlays = [{"values": {"api": {"replicas": 1 + i % 3}}} for i in range(10)]
    responses = await gather_bounded(
        *(client.post(f"{API_PREFIX}/validate/chart", json=o) for o in overlays)
    )
    assert [r.status_code for r in responses] == [200] * 10
    assert sample(app, "validations_total", {"target": "chart", "outcome": "pass"}) == 10


def test_guardrails_and_compiler_are_thread_safe() -> None:
    from tests.test_core import stack  # noqa: PLC0415

    settings_, spec = InfraSettings(), stack()
    expected_yaml = compile_ai_stack(settings_, spec).to_yaml()
    engine = AdmissionEngine.for_stack(settings_, spec)
    expected_report = engine.evaluate(expected_yaml)

    def work(_: int) -> tuple[str, Any]:
        text = compile_ai_stack(settings_, spec).to_yaml()
        return text, engine.evaluate(text)

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(work, range(64)))
    assert {text for text, _ in results} == {expected_yaml}
    assert all(report == expected_report for _, report in results)
