"""Validate Helm values overlays and submitted manifests without touching a cluster."""

from __future__ import annotations

import json
from typing import Any, Final

import anyio
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from cloud_native_k8s_ai.api.deps import Plane, component, json_body, parse_model, read_body
from cloud_native_k8s_ai.api.models import (
    ChartValidationRequest,
    ChartValidationResponse,
    TopologyRequest,
    TopologyResponse,
)
from cloud_native_k8s_ai.api.problems import PROBLEM_JSON
from cloud_native_k8s_ai.api.routes import API_PREFIX
from cloud_native_k8s_ai.api.routes.compile import YAML_MEDIA_TYPE, YAML_MEDIA_TYPES

router = APIRouter(prefix=f"{API_PREFIX}/validate", tags=["validate"])


def _responses(model: type[BaseModel], failure: str) -> dict[int | str, dict[str, Any]]:
    return {
        200: {
            "description": "All checks passed",
            "content": {"application/json": {"schema": component(model)}},
        },
        400: {"description": "Manifests cannot be parsed", "content": {PROBLEM_JSON: {}}},
        413: {"description": "Request body too large", "content": {PROBLEM_JSON: {}}},
        422: {"description": failure, "content": {PROBLEM_JSON: {}}},
        503: {"description": "Control plane unavailable", "content": {PROBLEM_JSON: {}}},
    }


_CHART_RESPONSES: Final = _responses(
    ChartValidationResponse, "Schema, contract, render, parity or zero-trust findings"
)
_TOPOLOGY_RESPONSES: Final = _responses(
    TopologyResponse, "Zero-trust violations (default deny, isolation, unauthorized flows)"
)


@router.post(
    "/chart",
    summary="Lint a values overlay against the chart (schema, contracts, parity, zero trust)",
    openapi_extra=json_body(ChartValidationRequest),
    responses=_CHART_RESPONSES,
)
async def validate_chart(request: Request, plane: Plane) -> JSONResponse:
    body = parse_model(
        ChartValidationRequest, await read_body(request, plane.settings.max_body_bytes)
    )
    await anyio.to_thread.run_sync(plane.validate_chart, body.values, body.release.to_release())
    return JSONResponse(ChartValidationResponse(release=body.release).to_wire())


def _is_yaml(content_type: str) -> bool:
    return content_type.split(";", maxsplit=1)[0].strip().lower() in YAML_MEDIA_TYPES


@router.post(
    "/topology",
    summary="Run the zero-trust topology solver on submitted manifests",
    openapi_extra=json_body(TopologyRequest, YAML_MEDIA_TYPE),
    responses=_TOPOLOGY_RESPONSES,
)
async def validate_topology(request: Request, plane: Plane) -> JSONResponse:
    raw = await read_body(request, plane.settings.max_body_bytes)
    if _is_yaml(request.headers.get("content-type", "")):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HTTPException(400, "manifests must be UTF-8 encoded") from exc
        body = parse_model(TopologyRequest, json.dumps({"manifests": text}).encode())
    else:
        body = parse_model(TopologyRequest, raw)
    result = await anyio.to_thread.run_sync(plane.validate_topology, body.manifests, body.spec)
    return JSONResponse(result.to_wire())
