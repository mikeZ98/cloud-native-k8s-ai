"""Phase 5 verification: FastAPI control plane, telemetry and RFC 7807 problems.

Hermetic: every request goes through ``httpx.AsyncClient`` over ``ASGITransport`` (or
straight into the ASGI callable); the lifespan runs in-process; sockets stay disabled.
"""

from __future__ import annotations

import asyncio
import copy
import io
import json
import logging
import shutil
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from prometheus_client.parser import text_string_to_metric_families
from starlette.requests import Request
from starlette.types import Message

from cloud_native_k8s_ai.api import API_PREFIX, ApiSettings, InfraSpec, create_app
from cloud_native_k8s_ai.api import service as service_module
from cloud_native_k8s_ai.api.middleware import RequestContextMiddleware, route_template
from cloud_native_k8s_ai.api.problems import PROBLEM_JSON, _handle_core
from cloud_native_k8s_ai.api.routes.compile import sse, wants_yaml
from cloud_native_k8s_ai.api.telemetry import (
    LOGGER_NAME,
    REQUEST_ID,
    Metrics,
    accept_request_id,
    configure_logging,
)
from cloud_native_k8s_ai.core import (
    K8sAiCoreError,
    ManifestBundle,
    ManifestRenderError,
    TopologyConflictError,
    Violation,
    reject_yaml_aliases,
    render_yaml,
)
from cloud_native_k8s_ai.guardrails import GuardrailError
from cloud_native_k8s_ai.tools.helm import ChartValuesError

ROOT = Path(__file__).resolve().parent.parent
CHART_DIR = ROOT / "deploy" / "helm" / "cloud-native-k8s-ai"
BASE_URL = "http://control-plane"
COMPILE = f"{API_PREFIX}/compile"
STREAM = f"{API_PREFIX}/stream/compile"
VALIDATE_CHART = f"{API_PREFIX}/validate/chart"
VALIDATE_TOPOLOGY = f"{API_PREFIX}/validate/topology"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    import os  # noqa: PLC0415

    for key in list(os.environ):
        if key.startswith("K8SAI_"):
            monkeypatch.delenv(key)
    yield
    for handler in logging.getLogger(LOGGER_NAME).handlers[:]:
        logging.getLogger(LOGGER_NAME).removeHandler(handler)


@pytest.fixture
def log() -> io.StringIO:
    return io.StringIO()


@pytest.fixture
def app(log: io.StringIO) -> FastAPI:
    return create_app(ApiSettings(chart_dir=CHART_DIR), log_stream=log)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with app.router.lifespan_context(app), _client(app) as http:
        yield http


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL)


@pytest.fixture
def spec(app: FastAPI, client: httpx.AsyncClient) -> dict[str, Any]:
    """The reference stack (chart defaults) as a JSON request body."""
    reference: InfraSpec = app.state.plane.reference
    return reference.to_wire()


@pytest.fixture
async def manifests(client: httpx.AsyncClient, spec: dict[str, Any]) -> str:
    response = await client.post(COMPILE, params={"format": "yaml"}, json=spec)
    assert response.status_code == 200
    return response.text


def sample(app: FastAPI, name: str, labels: dict[str, str] | None = None) -> float:
    value = app.state.metrics.registry.get_sample_value(name, labels or {})
    return 0.0 if value is None else float(value)


def assert_problem(response: httpx.Response, status: int, slug: str) -> dict[str, Any]:
    assert response.status_code == status, response.text
    assert response.headers["content-type"] == PROBLEM_JSON
    body: dict[str, Any] = response.json()
    assert body["type"] == f"urn:cloud-native-k8s-ai:problem:{slug}"
    assert body["status"] == status
    assert body["requestId"] == response.headers["x-request-id"]
    assert body["instance"] == response.request.url.path
    return body


def parse_sse(text: str) -> list[dict[str, Any]]:
    events = []
    for frame in text.split("\n\n"):
        if not frame.strip():
            continue
        fields = dict(line.split(": ", 1) for line in frame.splitlines())
        events.append(
            {"id": int(fields["id"]), "event": fields["event"], "data": json.loads(fields["data"])}
        )
    return events


def broken_chart(tmp_path: Path, name: str, old: str, new: str) -> Path:
    target = tmp_path / "chart"
    shutil.copytree(CHART_DIR, target)
    path = target / name
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new), encoding="utf-8")
    return target


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------
async def test_healthz(client: httpx.AsyncClient) -> None:
    response = await client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"] == "0.1.0"
    assert body["uptimeSeconds"] >= 0
    assert len(response.headers["x-request-id"]) == 32


async def test_readyz_reports_every_self_check(client: httpx.AsyncClient) -> None:
    response = await client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "checks": {
            "chart": "ok",
            "schemas": "ok",
            "generator": "ok",
            "guardrails": "ok",
            "chartLint": "ok",
        },
    }


async def test_readyz_before_startup_and_while_draining(app: FastAPI) -> None:
    async with _client(app) as http:
        before = await http.get("/readyz")
        assert before.status_code == 503
        assert before.json()["checks"] == {"lifespan": "not started"}
        assert_problem(await http.post(COMPILE, json={}), 503, "unavailable")
        async with app.router.lifespan_context(app):
            assert (await http.get("/readyz")).status_code == 200
        after = await http.get("/readyz")
        assert after.status_code == 503
        assert after.json()["checks"]["lifespan"] == "draining"


async def test_missing_chart_is_not_ready_but_compile_still_works(
    tmp_path: Path, log: io.StringIO
) -> None:
    app = create_app(ApiSettings(chart_dir=tmp_path / "absent"), log_stream=log)
    reference = (
        InfraSpec.from_wire(
            json.loads((ROOT / "tests" / "data" / "reference-spec.json").read_text())
        ).to_wire()
        if (ROOT / "tests" / "data").exists()
        else None
    )
    async with app.router.lifespan_context(app), _client(app) as http:
        ready = await http.get("/readyz")
        assert ready.status_code == 503
        checks = ready.json()["checks"]
        assert checks["chart"].startswith("ChartError: ")
        assert {checks[k] for k in ("schemas", "generator", "guardrails", "chartLint")} == {
            "skipped"
        }
        body = assert_problem(await http.get(STREAM), 503, "unavailable")
        assert "K8SAI_API_CHART_DIR" in body["detail"]
        assert_problem(await http.post(VALIDATE_CHART, json={}), 503, "unavailable")
        assert_problem(
            await http.post(VALIDATE_TOPOLOGY, json={"manifests": "---\n{}\n"}), 503, "unavailable"
        )
    assert reference is None


@pytest.mark.parametrize(
    ("name", "old", "new", "check", "state"),
    [
        ("values.yaml", "maxmemory: 768Mi", "maxmemory: 4Gi", "schemas", "ChartValuesError: "),
        (
            "templates/service-api.yaml",
            "  type: ClusterIP",
            "  type: ClusterIP\n  sessionAffinity: None",
            "chartLint",
            "1 finding(s)",
        ),
    ],
)
async def test_failed_self_checks_keep_the_pod_unready(
    tmp_path: Path, log: io.StringIO, *, name: str, old: str, new: str, check: str, state: str
) -> None:
    app = create_app(ApiSettings(chart_dir=broken_chart(tmp_path, name, old, new)), log_stream=log)
    async with app.router.lifespan_context(app), _client(app) as http:
        response = await http.get("/readyz")
    assert response.status_code == 503
    assert response.json()["checks"][check].startswith(state)


@pytest.mark.parametrize("failure", ["round-trip", "empty-bundle"])
async def test_generator_self_check_failures(
    monkeypatch: pytest.MonkeyPatch, log: io.StringIO, failure: str
) -> None:
    if failure == "round-trip":
        monkeypatch.setattr(InfraSpec, "__eq__", lambda *_: False)
        check = "schemas"
    else:
        monkeypatch.setattr(service_module, "compile_ai_stack", lambda *_: ManifestBundle())
        check = "generator"
    app = create_app(ApiSettings(chart_dir=CHART_DIR), log_stream=log)
    async with app.router.lifespan_context(app):
        plane = app.state.plane
    assert plane.checks[check].startswith("ManifestRenderError: ")
    assert not plane.ready


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------
async def test_metrics_exposition(
    app: FastAPI, client: httpx.AsyncClient, spec: dict[str, Any]
) -> None:
    await client.post(COMPILE, json=spec)
    await client.get("/does-not-exist")
    response = await client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain; version=")
    families = {f.name: f for f in text_string_to_metric_families(response.text)}
    assert {
        "http_requests",
        "http_request_duration_seconds",
        "http_requests_in_flight",
        "manifest_compilations",
        "manifest_compile_duration_seconds",
        "manifest_documents",
        "validations",
        "manifest_streams",
        "control_plane_build_info",
        "python_info",
    } <= families.keys()
    requests = {
        (s.labels["method"], s.labels["route"], s.labels["status"]): s.value
        for s in families["http_requests"].samples
        if s.name == "http_requests_total"
    }
    assert requests[("POST", COMPILE, "200")] == 1
    assert requests[("GET", "<unmatched>", "404")] == 1
    assert sample(app, "manifest_compilations_total", {"outcome": "success"}) == 1
    assert sample(app, "manifest_documents_total", {"kind": "NetworkPolicy"}) == 6
    assert sample(app, "control_plane_build_info", {"version": "0.1.0"}) == 1


async def test_metrics_label_routes_by_template(app: FastAPI, client: httpx.AsyncClient) -> None:
    response = await client.get(COMPILE)
    body = assert_problem(response, 405, "http-405")
    assert body["title"] == "Method Not Allowed"
    assert response.headers["allow"] == "POST"
    assert (
        sample(app, "http_requests_total", {"method": "GET", "route": COMPILE, "status": "405"})
        == 1
    )


async def test_request_ids_and_access_logs(client: httpx.AsyncClient, log: io.StringIO) -> None:
    given = await client.get("/healthz", headers={"X-Request-ID": "trace-1.a:b"})
    assert given.headers["x-request-id"] == "trace-1.a:b"
    hostile = await client.get("/healthz", headers={"X-Request-ID": "x" * 200})
    assert hostile.headers["x-request-id"] != "x" * 200
    entries = [json.loads(line) for line in log.getvalue().splitlines()]
    access = [e for e in entries if e["message"] == "request completed"]
    assert access[0]["request_id"] == "trace-1.a:b"
    assert access[0] | {"duration_ms": 0} == {
        "ts": access[0]["ts"],
        "level": "INFO",
        "logger": LOGGER_NAME,
        "message": "request completed",
        "request_id": "trace-1.a:b",
        "method": "GET",
        "path": "/healthz",
        "route": "/healthz",
        "status": 200,
        "duration_ms": 0,
    }
    assert entries[0]["message"] == "control plane started"
    assert entries[0]["checks"]["chart"] == "ok"
    assert REQUEST_ID.get() is None


def test_accept_request_id() -> None:
    assert accept_request_id("abc-123") == "abc-123"
    for hostile in (None, "", "a b", "x\r\nSet-Cookie: y", "é"):
        minted = accept_request_id(hostile)
        assert len(minted) == 32
        assert minted.isalnum()


def test_configure_logging_is_idempotent() -> None:
    stream = io.StringIO()
    logger = configure_logging("DEBUG", stream)
    configure_logging("DEBUG", stream)
    assert sum(type(h).__name__ == "_JsonHandler" for h in logger.handlers) == 1
    assert logger.propagate is False
    try:
        raise ValueError("boom")  # noqa: TRY301
    except ValueError:
        logger.exception("failed", extra={"component": "x"})
    entry = json.loads(stream.getvalue())
    assert entry["component"] == "x"
    assert "ValueError: boom" in entry["exception"]
    assert "request_id" not in entry


def test_metrics_lifecycle_is_repeatable() -> None:
    metrics = Metrics()
    metrics.start("1")
    metrics.start("2")  # restarting replaces the runtime collectors instead of colliding
    assert b'control_plane_build_info{version="2"} 1.0' in metrics.render()
    metrics.stop()
    assert b"python_info" not in metrics.render()


# ---------------------------------------------------------------------------
# Compile
# ---------------------------------------------------------------------------
async def test_compile_returns_the_bundle_as_json(
    client: httpx.AsyncClient, spec: dict[str, Any]
) -> None:
    response = await client.post(COMPILE, json=spec)
    assert response.status_code == 200
    body = response.json()
    assert (body["environment"], body["namespace"], body["count"]) == ("dev", "ai-system", 15)
    assert body["kinds"] == {
        "NetworkPolicy": 6,
        "PersistentVolumeClaim": 1,
        "Service": 4,
        "Deployment": 2,
        "StatefulSet": 1,
        "ScaledObject": 1,
    }
    assert body["documents"][0]["kind"] == "NetworkPolicy"
    assert body["documents"][-1]["kind"] == "ScaledObject"
    bundle = ManifestBundle.from_yaml(render_yaml(body["documents"]))
    assert bundle.to_documents() == body["documents"]


@pytest.mark.parametrize(
    ("params", "accept"),
    [({"format": "yaml"}, "application/json"), ({}, "application/yaml"), ({}, "text/yaml;q=0.9")],
)
async def test_compile_returns_yaml_that_safe_loads(
    client: httpx.AsyncClient, spec: dict[str, Any], params: dict[str, str], accept: str
) -> None:
    response = await client.post(COMPILE, params=params, json=spec, headers={"Accept": accept})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/yaml")
    documents = list(yaml.safe_load_all(response.text))
    assert len(documents) == 15
    assert response.text.startswith("---\napiVersion: networking.k8s.io/v1\n")
    assert {d["metadata"]["namespace"] for d in documents} == {"ai-system"}


@pytest.mark.parametrize(
    ("output", "accept", "expected"),
    [
        ("yaml", "", True),
        ("json", "application/yaml", False),
        (None, "application/json, application/yaml", False),
        (None, "text/html, application/x-yaml", True),
        (None, "*/*", False),
        (None, "text/html", False),
        (None, "", False),
    ],
)
def test_wants_yaml(output: str | None, accept: str, expected: bool) -> None:
    assert wants_yaml(output, accept) is expected


async def test_compile_honours_environment_and_namespace(
    client: httpx.AsyncClient, spec: dict[str, Any]
) -> None:
    response = await client.post(COMPILE, json=spec | {"environment": "prod", "namespace": "ml"})
    documents = response.json()["documents"]
    assert {d["metadata"]["namespace"] for d in documents} == {"ml"}
    deployment = next(d for d in documents if d["kind"] == "Deployment")
    assert deployment["metadata"]["labels"]["environment"] == "prod"


@pytest.mark.parametrize(
    ("mutate", "loc"),
    [
        (lambda s: s.pop("stack"), ["body", "stack"]),
        (lambda s: s.update(environment="qa"), ["body", "environment"]),
        (
            lambda s: s["stack"]["app"].update(image="ghcr.io/x/api:latest"),
            ["body", "stack", "app", "image"],
        ),
        (lambda s: s["stack"]["app"].update(replicas="2"), ["body", "stack", "app", "replicas"]),
        (lambda s: s["stack"]["redis"].update(maxmemory="4Gi"), ["body", "stack", "redis"]),
        (lambda s: s.update(surprise=1), ["body", "surprise"]),
    ],
)
async def test_compile_rejects_invalid_specs(
    client: httpx.AsyncClient, spec: dict[str, Any], mutate: Any, loc: list[str]
) -> None:
    body = copy.deepcopy(spec)
    mutate(body)
    problem = assert_problem(await client.post(COMPILE, json=body), 422, "invalid-request")
    assert loc in [e["loc"] for e in problem["errors"]]
    assert {"loc", "msg", "type"} == set(problem["errors"][0])


async def test_compile_rejects_malformed_json(client: httpx.AsyncClient) -> None:
    problem = assert_problem(
        await client.post(
            COMPILE, content=b"{not json", headers={"content-type": "application/json"}
        ),
        422,
        "invalid-request",
    )
    assert problem["errors"][0]["type"] == "json_invalid"


async def test_core_errors_become_problems(
    app: FastAPI, client: httpx.AsyncClient, spec: dict[str, Any]
) -> None:
    bounds = copy.deepcopy(spec)
    bounds["stack"]["autoscaling"] |= {"minReplicas": 5, "maxReplicas": 3}
    problem = assert_problem(await client.post(COMPILE, json=bounds), 422, "resource-constraint")
    assert "exceeds max_replicas" in problem["detail"]
    clash = copy.deepcopy(spec)
    clash["stack"]["redis"]["name"] = clash["stack"]["qdrant"]["name"]
    problem = assert_problem(await client.post(COMPILE, json=clash), 400, "manifest-render")
    assert "component names must be distinct" in problem["detail"]
    assert sample(app, "manifest_compilations_total", {"outcome": "failure"}) == 2


async def test_request_bodies_are_bounded(tmp_path: Path, log: io.StringIO) -> None:
    app = create_app(ApiSettings(chart_dir=CHART_DIR, max_body_bytes=1024), log_stream=log)

    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(3):
            yield b" " * 600

    async with app.router.lifespan_context(app), _client(app) as http:
        declared = await http.post(COMPILE, content=b"{" + b" " * 2048 + b"}")
        problem = assert_problem(declared, 413, "http-413")
        assert problem["detail"] == "request body exceeds 1024 bytes"
        assert_problem(await http.post(COMPILE, content=chunks()), 413, "http-413")


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------
async def test_stream_emits_sse_frames(app: FastAPI, client: httpx.AsyncClient) -> None:
    response = await client.get(STREAM)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "no-cache"
    events = parse_sse(response.text)
    assert [e["event"] for e in events] == ["manifest"] * 15 + ["complete"]
    assert [e["id"] for e in events] == list(range(16))
    manifests = events[:-1]
    assert all(e["data"]["total"] == 15 for e in manifests)
    documents = [yaml.safe_load(e["data"]["yaml"]) for e in manifests]
    assert [d["kind"] for d in documents] == [e["data"]["kind"] for e in manifests]
    assert events[-1]["data"]["count"] == 15
    assert sample(app, "manifest_streams_total", {"outcome": "completed"}) == 1


async def test_stream_reference_with_overrides(client: httpx.AsyncClient) -> None:
    response = await client.get(STREAM, params={"namespace": "team-a", "environment": "staging"})
    events = parse_sse(response.text)
    assert {e["data"]["namespace"] for e in events[:-1]} == {"team-a"}
    bad = assert_problem(
        await client.get(STREAM, params={"namespace": "Bad_NS"}), 422, "invalid-request"
    )
    assert bad["errors"][0]["loc"] == ["query", "namespace"]


async def test_stream_submitted_spec(client: httpx.AsyncClient, spec: dict[str, Any]) -> None:
    response = await client.post(STREAM, json=spec | {"namespace": "ml"})
    events = parse_sse(response.text)
    assert events[-1]["event"] == "complete"
    assert events[0]["data"]["namespace"] == "ml"
    invalid = await client.post(STREAM, json={"stack": {}})
    assert_problem(invalid, 422, "invalid-request")  # never a half-written stream


def test_sse_frame_format() -> None:
    frame = sse("manifest", {"yaml": "a: 1\nb: 2\n"}, 7)
    assert frame == 'id: 7\nevent: manifest\ndata: {"yaml":"a: 1\\nb: 2\\n"}\n\n'


async def test_client_disconnect_cancels_the_stream_without_leaking_tasks(app: FastAPI) -> None:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": STREAM,
        "raw_path": STREAM.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": [(b"host", b"control-plane")],
        "client": ("127.0.0.1", 50000),
        "server": ("control-plane", 80),
    }
    disconnected = asyncio.Event()
    request_sent = False
    bodies: list[bytes] = []

    async def receive() -> Message:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await disconnected.wait()
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        if message["type"] == "http.response.body" and message.get("body"):
            bodies.append(message["body"])
            disconnected.set()  # the client goes away after the first event
            await asyncio.sleep(0)

    async with app.router.lifespan_context(app):
        before = asyncio.all_tasks()
        await asyncio.wait_for(app(scope, receive, send), timeout=10)
        await asyncio.sleep(0)
        leaked = {t for t in asyncio.all_tasks() - before if not t.done()}
        assert leaked == set()
    received = b"".join(bodies).decode()
    assert 1 <= received.count("event: manifest") < 15
    assert "event: complete" not in received
    assert sample(app, "manifest_streams_total", {"outcome": "aborted"}) == 1
    assert sample(app, "manifest_streams_total", {"outcome": "completed"}) == 0
    assert sample(app, "http_requests_in_flight") == 0


# ---------------------------------------------------------------------------
# Chart validation
# ---------------------------------------------------------------------------
async def test_validate_chart_passes_defaults_and_releases(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    response = await client.post(VALIDATE_CHART, json={})
    assert response.status_code == 200
    assert response.json() == {
        "status": "pass",
        "release": {"name": "ai", "namespace": "ai-system"},
        "findings": [],
    }
    overlay = {
        "values": {"autoscaling": {"enabled": False}},
        "release": {"name": "prod", "namespace": "ml"},
    }
    response = await client.post(VALIDATE_CHART, json=overlay)
    assert response.json()["release"] == {"name": "prod", "namespace": "ml"}
    assert sample(app, "validations_total", {"target": "chart", "outcome": "pass"}) == 2


@pytest.mark.parametrize(
    ("values", "fragment"),
    [
        ({"redis": {"maxmemory": "4Gi"}}, "must stay below the memory limit"),
        ({"api": {"image": {"tag": "latest"}}}, "api.image.tag"),
        ({"autoscaling": {"minReplicas": 5, "maxReplicas": 3}}, "exceeds max_replicas"),
        ({"surprise": 1}, "Additional properties are not allowed"),
    ],
)
async def test_validate_chart_flags_violations(
    app: FastAPI, client: httpx.AsyncClient, values: dict[str, Any], fragment: str
) -> None:
    problem = assert_problem(
        await client.post(VALIDATE_CHART, json={"values": values}), 422, "chart-lint-failed"
    )
    assert problem["detail"] == "chart lint failed"
    assert all(f.startswith("[request] ") for f in problem["findings"])
    assert any(fragment in f for f in problem["findings"]), problem["findings"]
    assert sample(app, "validations_total", {"target": "chart", "outcome": "fail"}) == 1


@pytest.mark.parametrize(
    "body",
    [{"values": 3}, {"release": {"name": "Bad_Name"}}, {"values": {}, "extra": True}],
)
async def test_validate_chart_rejects_malformed_requests(
    client: httpx.AsyncClient, body: dict[str, Any]
) -> None:
    assert_problem(await client.post(VALIDATE_CHART, json=body), 422, "invalid-request")


# ---------------------------------------------------------------------------
# Topology validation
# ---------------------------------------------------------------------------
async def test_validate_topology_passes_compiled_manifests(
    app: FastAPI, client: httpx.AsyncClient, manifests: str
) -> None:
    for response in (
        await client.post(VALIDATE_TOPOLOGY, json={"manifests": manifests}),
        await client.post(
            VALIDATE_TOPOLOGY, content=manifests, headers={"content-type": "application/yaml"}
        ),
    ):
        assert response.status_code == 200
        body = response.json()
        assert (body["status"], body["policies"], body["workloads"]) == ("pass", 6, 3)
        assert "inference-api -> qdrant TCP/6333" in body["reachable"]
        assert not any(flow.startswith("redis -> qdrant") for flow in body["reachable"])
        intruder = [f for f in body["reachable"] if f.startswith("intruder -> ")]
        assert all(" -> kube-dns " in f for f in intruder)  # DNS is the only shared egress
    assert sample(app, "validations_total", {"target": "topology", "outcome": "pass"}) == 2


async def test_validate_topology_with_an_explicit_spec(
    client: httpx.AsyncClient, spec: dict[str, Any]
) -> None:
    team = spec | {"namespace": "team-a"}
    compiled = (await client.post(COMPILE, params={"format": "yaml"}, json=team)).text
    response = await client.post(VALIDATE_TOPOLOGY, json={"manifests": compiled, "spec": team})
    assert response.status_code == 200
    assert response.json()["namespace"] == "team-a"


def _without(manifests: str, name: str) -> str:
    documents = [d for d in yaml.safe_load_all(manifests) if d["metadata"]["name"] != name]
    return render_yaml(documents)


def _open_qdrant(manifests: str) -> str:
    documents = list(yaml.safe_load_all(manifests))
    policy = next(d for d in documents if d["metadata"]["name"] == "qdrant-allow-from-app")
    policy["spec"]["ingress"][0]["from"] = [{"podSelector": {}}]
    return render_yaml(documents)


@pytest.mark.parametrize(
    ("tamper", "codes"),
    [
        (lambda m: _without(m, "default-deny-all"), {"missing-default-deny"}),
        (_open_qdrant, {"exclusive-ingress"}),
        (lambda m: _without(m, "allow-dns-egress"), {"missing-dns-egress"}),
    ],
)
async def test_validate_topology_flags_violations(
    app: FastAPI, client: httpx.AsyncClient, manifests: str, tamper: Any, codes: set[str]
) -> None:
    response = await client.post(VALIDATE_TOPOLOGY, json={"manifests": tamper(manifests)})
    problem = assert_problem(response, 422, "topology-conflict")
    assert problem["detail"] == "zero-trust topology violated"
    assert codes <= {v["code"] for v in problem["violations"]}
    assert all(set(v) == {"code", "message"} for v in problem["violations"])
    assert sample(app, "validations_total", {"target": "topology", "outcome": "fail"}) == 1


async def test_validate_topology_needs_the_workloads(
    client: httpx.AsyncClient, manifests: str
) -> None:
    policies = [d for d in yaml.safe_load_all(manifests) if d["kind"] == "NetworkPolicy"]
    problem = assert_problem(
        await client.post(VALIDATE_TOPOLOGY, json={"manifests": render_yaml(policies)}),
        422,
        "topology-conflict",
    )
    assert "unknown DNS clients" in problem["detail"]
    assert problem["violations"] == []


BILLION_LAUGHS = (
    "---\na: &a [x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\n"
)


@pytest.mark.parametrize(
    ("content", "content_type", "status", "slug", "fragment"),
    [
        ("kind: [", "application/yaml", 400, "manifest-render", "invalid YAML"),
        (BILLION_LAUGHS, "application/yaml", 400, "manifest-render", "anchors and aliases"),
        ("---\napiVersion: v1\nkind: Pod\nmetadata: {name: p}\n", "application/yaml", 400,
         "manifest-render", "unsupported manifest type v1/Pod"),
        ("", "application/yaml", 422, "invalid-request", ""),
        ("\udcff", "text/yaml", 400, "http-400", "UTF-8"),
        ('{"manifests": ""}', "application/json", 422, "invalid-request", ""),
    ],
)  # fmt: skip
async def test_validate_topology_rejects_bad_input(
    client: httpx.AsyncClient,
    *,
    content: str,
    content_type: str,
    status: int,
    slug: str,
    fragment: str,
) -> None:
    raw = content.encode("utf-8", "surrogateescape")
    response = await client.post(
        VALIDATE_TOPOLOGY, content=raw, headers={"content-type": content_type}
    )
    problem = assert_problem(response, status, slug)
    assert fragment in problem["detail"]


def test_reject_yaml_aliases_allows_plain_documents() -> None:
    reject_yaml_aliases("---\na: 1\n---\nb: [1, 2]\n")
    with pytest.raises(ManifestRenderError, match="anchors"):
        reject_yaml_aliases("a: &x 1\n")


# ---------------------------------------------------------------------------
# Errors, middleware, OpenAPI
# ---------------------------------------------------------------------------
async def test_unhandled_errors_become_opaque_500_problems(app: FastAPI, log: io.StringIO) -> None:
    async def explode() -> None:
        raise RuntimeError("secret internals")

    app.add_api_route("/explode", explode)
    async with app.router.lifespan_context(app), _client(app) as http:
        response = await http.get("/explode", headers={"X-Request-ID": "req-500"})
    problem = assert_problem(response, 500, "internal-error")
    assert "secret" not in response.text
    assert problem["requestId"] == "req-500"
    error = next(json.loads(line) for line in log.getvalue().splitlines() if "unhandled" in line)
    assert error["request_id"] == "req-500"
    assert "RuntimeError: secret internals" in error["exception"]
    assert (
        sample(app, "http_requests_total", {"method": "GET", "route": "/explode", "status": "500"})
        == 1
    )


async def test_errors_after_the_response_started_propagate(app: FastAPI) -> None:
    async def body() -> AsyncIterator[str]:
        yield "partial"
        raise RuntimeError("mid-stream")

    async def broken_stream() -> StreamingResponse:
        return StreamingResponse(body())

    app.add_api_route("/broken-stream", broken_stream)
    async with app.router.lifespan_context(app), _client(app) as http:
        with pytest.raises(RuntimeError, match="mid-stream"):
            await http.get("/broken-stream")
    assert sample(app, "http_requests_in_flight") == 0


async def test_non_http_scopes_pass_through() -> None:
    seen: list[str] = []

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        seen.append(scope["type"])

    middleware = RequestContextMiddleware(inner, metrics=Metrics())
    await middleware({"type": "websocket"}, None, None)  # type: ignore[arg-type]
    assert seen == ["websocket"]


@pytest.mark.parametrize(
    ("error", "status", "slug", "extension"),
    [
        (ChartValuesError(["a: bad", "b: worse"]), 422, "invalid-chart-values",
         {"problems": ["a: bad", "b: worse"]}),
        (TopologyConflictError("broken", [Violation("x", "y")]), 422, "topology-conflict",
         {"violations": [{"code": "x", "message": "y"}]}),
        (K8sAiCoreError("generic"), 400, "core-error", {}),
    ],
)  # fmt: skip
def test_core_problem_mapping(
    error: K8sAiCoreError, status: int, slug: str, extension: dict[str, Any]
) -> None:
    request = Request(
        {"type": "http", "path": "/x", "headers": [], "query_string": b"", "server": ("h", 80)}
    )
    response = _handle_core(request, error)
    body = json.loads(bytes(response.body))
    assert (response.status_code, body["type"].rsplit(":", 1)[1]) == (status, slug)
    assert body.items() >= extension.items()
    assert "requestId" not in body
    assert "\n" not in body["detail"]


def test_route_template_falls_back_for_unknown_paths() -> None:
    assert route_template({"type": "http", "path": "/nope"}) == "<unmatched>"


async def test_openapi_documents_bodies_and_resolves_every_ref(client: httpx.AsyncClient) -> None:
    document = (await client.get("/openapi.json")).json()
    paths = document["paths"]
    assert {
        COMPILE,
        STREAM,
        VALIDATE_CHART,
        VALIDATE_TOPOLOGY,
        "/healthz",
        "/readyz",
        "/metrics",
    } <= set(paths)
    body = paths[COMPILE]["post"]["requestBody"]["content"]["application/json"]["schema"]
    assert body == {"$ref": "#/components/schemas/InfraSpec"}
    assert "application/yaml" in paths[VALIDATE_TOPOLOGY]["post"]["requestBody"]["content"]
    schemas = document["components"]["schemas"]
    assert {"InfraSpec", "AIStackSpec", "ChartValidationRequest", "TopologyRequest"} <= set(schemas)
    assert "containerPort" in schemas["FastAPIAppSpec"]["properties"]  # camelCase on the wire

    def refs(node: Any) -> Iterator[str]:
        if isinstance(node, dict):
            if isinstance(node.get("$ref"), str):
                yield node["$ref"]
            for value in node.values():
                yield from refs(value)
        elif isinstance(node, list):
            for value in node:
                yield from refs(value)

    unresolved = {
        r for r in refs(document) if r.removeprefix("#/components/schemas/") not in schemas
    }
    assert unresolved == set()
    assert (await client.get("/openapi.json")).json() == document  # cached, stable


# ---------------------------------------------------------------------------
# Admission guardrails
# ---------------------------------------------------------------------------
VALIDATE_ADMISSION = f"{API_PREFIX}/validate/admission"


def _edit(manifests: str, change: Any) -> str:
    documents = list(yaml.safe_load_all(manifests))
    change(documents)
    return render_yaml(documents)


def _drop_default_deny(documents: list[dict[str, Any]]) -> None:
    documents[:] = [d for d in documents if d["metadata"]["name"] != "default-deny-all"]


def _deny_and_latest(documents: list[dict[str, Any]]) -> None:
    _drop_default_deny(documents)
    _latest_api_image(documents)


def _latest_api_image(documents: list[dict[str, Any]]) -> None:
    for document in documents:
        if document["kind"] == "Deployment" and document["metadata"]["name"] == "inference-api":
            document["spec"]["template"]["spec"]["containers"][0]["image"] = "ghcr.io/x/api:latest"


async def test_admission_allows_compiled_manifests(
    app: FastAPI, client: httpx.AsyncClient, manifests: str
) -> None:
    for response in (
        await client.post(VALIDATE_ADMISSION, json={"manifests": manifests}),
        await client.post(
            VALIDATE_ADMISSION, content=manifests, headers={"content-type": "application/yaml"}
        ),
    ):
        assert response.status_code == 200
        body = response.json()
        assert body["report"]["decision"] == "ALLOW"
        assert body["report"]["violations"] == []
        assert len(body["report"]["objects"]) == 15
        assert "remediation" not in body
    assert sample(app, "validations_total", {"target": "admission", "outcome": "allow"}) == 2


async def test_admission_warnings_still_admit(client: httpx.AsyncClient, manifests: str) -> None:
    def aggressive(documents: list[dict[str, Any]]) -> None:
        next(d for d in documents if d["kind"] == "ScaledObject")["spec"]["pollingInterval"] = 2

    response = await client.post(
        VALIDATE_ADMISSION, json={"manifests": _edit(manifests, aggressive)}
    )
    assert response.status_code == 200
    report = response.json()["report"]
    assert report["decision"] == "WARN"
    assert [v["code"] for v in report["violations"]] == ["keda-polling-too-aggressive"]


async def test_admission_denial_is_a_structured_problem(
    app: FastAPI, client: httpx.AsyncClient, manifests: str
) -> None:
    broken = _edit(manifests, _deny_and_latest)
    problem = assert_problem(
        await client.post(VALIDATE_ADMISSION, json={"manifests": broken}), 422, "admission-denied"
    )
    assert problem["decision"] == "DENY"
    assert problem["detail"] == "admission denied: 3 blocking violation(s)"
    violations = {v["code"]: v for v in problem["violations"]}
    assert set(violations) == {
        "image-latest-tag",
        "missing-default-deny-ingress",
        "missing-default-deny-egress",
    }
    image = violations["image-latest-tag"]
    assert image["target"] == {
        "kind": "Deployment",
        "namespace": "ai-system",
        "name": "inference-api",
    }
    assert image["path"] == "/spec/template/spec/containers/0/image"
    assert image["remediation"]["action"] == "manual"
    deny = violations["missing-default-deny-ingress"]["remediation"]
    assert deny["action"] == "create"
    assert deny["document"]["metadata"]["name"] == "default-deny-all"
    assert "remediation" not in problem
    assert sample(app, "validations_total", {"target": "admission", "outcome": "deny"}) == 1


async def test_admission_remediation_fixes_what_it_can(
    client: httpx.AsyncClient, manifests: str
) -> None:
    fixable = _edit(manifests, _drop_default_deny)
    response = await client.post(
        VALIDATE_ADMISSION, params={"remediate": "true"}, json={"manifests": fixable}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["report"]["decision"] == "ALLOW"
    remediation = body["remediation"]
    assert remediation["initialDecision"] == "DENY"
    assert remediation["converged"] is True
    assert remediation["rounds"][0]["applied"] == [
        "missing-default-deny-ingress Namespace -/ai-system"
    ]
    names = {d["metadata"]["name"] for d in yaml.safe_load_all(remediation["manifests"])}
    assert "default-deny-all" in names
    # What the critic loop produced passes the topology solver as well.
    topology = await client.post(VALIDATE_TOPOLOGY, json={"manifests": remediation["manifests"]})
    assert topology.status_code == 200

    manual = _edit(manifests, _deny_and_latest)
    response = await client.post(
        VALIDATE_ADMISSION, params={"remediate": "true"}, json={"manifests": manual}
    )
    problem = assert_problem(response, 422, "admission-denied")
    assert [v["code"] for v in problem["violations"]] == ["image-latest-tag"]
    assert problem["remediation"]["converged"] is True
    assert "default-deny-all" in problem["remediation"]["manifests"]


@pytest.mark.parametrize(
    ("content", "status", "slug"),
    [
        ("---\n- just\n- a list\n", 400, "manifest-render"),
        ("a: &x 1\nb: *x\n", 400, "manifest-render"),
        ("", 422, "invalid-request"),
    ],
)
async def test_admission_rejects_unparseable_input(
    app: FastAPI, client: httpx.AsyncClient, content: str, status: int, slug: str
) -> None:
    response = await client.post(
        VALIDATE_ADMISSION, content=content, headers={"content-type": "application/yaml"}
    )
    assert_problem(response, status, slug)
    if status == 400:
        assert sample(app, "validations_total", {"target": "admission", "outcome": "error"}) == 1


def test_guardrail_errors_map_to_400() -> None:
    request = Request(
        {"type": "http", "path": "/x", "headers": [], "query_string": b"", "server": ("h", 80)}
    )
    response = _handle_core(request, GuardrailError("cannot evaluate"))
    assert response.status_code == 400
    assert json.loads(bytes(response.body))["type"].endswith(":guardrail-error")
