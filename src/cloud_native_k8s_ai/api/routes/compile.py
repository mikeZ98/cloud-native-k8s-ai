"""Compile an AI stack into Kubernetes manifests: one response, or a stream of events.

The stack is compiled (and zero-trust checked) before anything is sent, so a bad spec is
always a problem response and never a half-written stream.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import AsyncGenerator, Mapping, Sequence
from typing import Annotated, Any, Final, Literal

import anyio
import anyio.lowlevel
from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.types import Receive, Scope, Send

from cloud_native_k8s_ai.api.deps import Plane, component, json_body, parse_model, read_body
from cloud_native_k8s_ai.api.models import CompileResponse, InfraSpec
from cloud_native_k8s_ai.api.problems import PROBLEM_JSON
from cloud_native_k8s_ai.api.routes import API_PREFIX
from cloud_native_k8s_ai.api.telemetry import Metrics
from cloud_native_k8s_ai.core import render_yaml
from cloud_native_k8s_ai.schemas import DNS1123Label
from cloud_native_k8s_ai.schemas.settings import Environment

router = APIRouter(prefix=API_PREFIX, tags=["compile"])

YAML_MEDIA_TYPE: Final = "application/yaml"
YAML_MEDIA_TYPES: Final = frozenset({YAML_MEDIA_TYPE, "application/x-yaml", "text/yaml"})
EVENT_STREAM: Final = "text/event-stream"
_PROBLEMS: Final[dict[int | str, dict[str, Any]]] = {
    status: {"description": text, "content": {PROBLEM_JSON: {}}}
    for status, text in (
        (400, "Manifests cannot be rendered"),
        (413, "Request body too large"),
        (422, "Invalid spec, resource constraint or zero-trust violation"),
        (503, "Control plane unavailable"),
    )
}


def wants_yaml(output: str | None, accept: str) -> bool:
    """``?format=`` wins; otherwise the first YAML or JSON media type in ``Accept``."""
    if output is not None:
        return output == "yaml"
    for item in accept.split(","):
        media = item.split(";")[0].strip().lower()
        if media in YAML_MEDIA_TYPES:
            return True
        if media in {"application/json", "application/*", "*/*"}:
            return False
    return False


@router.post(
    "/compile",
    summary="Compile an AI stack to Kubernetes manifests",
    openapi_extra=json_body(InfraSpec),
    responses={
        200: {
            "description": "The bundle as JSON, or multi-document YAML (?format=yaml / Accept)",
            "content": {
                "application/json": {"schema": component(CompileResponse)},
                YAML_MEDIA_TYPE: {"schema": {"type": "string"}},
            },
        },
        **_PROBLEMS,
    },
)
async def compile_manifests(
    request: Request,
    plane: Plane,
    output: Annotated[Literal["json", "yaml"] | None, Query(alias="format")] = None,
) -> Response:
    spec = parse_model(InfraSpec, await read_body(request, plane.settings.max_body_bytes))
    bundle = await anyio.to_thread.run_sync(plane.compile, spec)
    if wants_yaml(output, request.headers.get("accept", "")):
        return Response(bundle.to_yaml(), media_type=YAML_MEDIA_TYPE)
    return JSONResponse(CompileResponse.from_bundle(spec, bundle).to_wire())


def sse(event: str, data: Mapping[str, Any], event_id: int) -> str:
    """One Server-Sent Events frame; JSON data never spans lines."""
    return f"id: {event_id}\nevent: {event}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n"


async def manifest_events(
    documents: Sequence[Mapping[str, Any]], metrics: Metrics
) -> AsyncGenerator[str]:
    """``manifest`` events in apply order, then ``complete``. A client disconnect cancels
    the stream at the next checkpoint; the outcome is counted either way."""
    completed = False
    try:
        for index, document in enumerate(documents):
            metadata = document["metadata"]
            payload = {
                "index": index,
                "total": len(documents),
                "kind": document["kind"],
                "name": metadata["name"],
                "namespace": metadata.get("namespace"),
                "yaml": render_yaml([document]),
            }
            yield sse("manifest", payload, index)
            await anyio.lowlevel.checkpoint()  # checkpoint between documents
        kinds = dict(Counter(d["kind"] for d in documents))
        yield sse("complete", {"count": len(documents), "kinds": kinds}, len(documents))
        completed = True
    finally:
        metrics.streams.labels("completed" if completed else "aborted").inc()


class ManifestStream(StreamingResponse):
    """An SSE response that closes its event generator as soon as the response ends.
    Starlette abandons the iterator when a client disconnects, deferring cleanup to the GC."""

    def __init__(self, events: AsyncGenerator[str]) -> None:
        super().__init__(
            events,
            media_type=EVENT_STREAM,
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
        self.events = events

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            await self.events.aclose()


async def _stream(plane: Plane, spec: InfraSpec) -> StreamingResponse:
    bundle = await anyio.to_thread.run_sync(plane.compile, spec)
    return ManifestStream(manifest_events(bundle.to_documents(), plane.metrics))


_STREAM_RESPONSES: Final[dict[int | str, dict[str, Any]]] = {
    200: {
        "description": "SSE: one `manifest` event per document, then `complete`",
        "content": {EVENT_STREAM: {"schema": {"type": "string"}}},
    },
    **_PROBLEMS,
}


@router.get(
    "/stream/compile",
    summary="Stream the reference stack (chart defaults) document by document",
    responses=_STREAM_RESPONSES,
)
async def stream_reference(
    plane: Plane,
    environment: Environment | None = None,
    namespace: Annotated[DNS1123Label | None, Query(max_length=63)] = None,
) -> StreamingResponse:
    overrides = {
        k: v for k, v in (("environment", environment), ("namespace", namespace)) if v is not None
    }
    return await _stream(plane, plane.reference_spec(overrides))


@router.post(
    "/stream/compile",
    summary="Stream a submitted stack document by document",
    openapi_extra=json_body(InfraSpec),
    responses=_STREAM_RESPONSES,
)
async def stream_spec(request: Request, plane: Plane) -> StreamingResponse:
    spec = parse_model(InfraSpec, await read_body(request, plane.settings.max_body_bytes))
    return await _stream(plane, spec)
