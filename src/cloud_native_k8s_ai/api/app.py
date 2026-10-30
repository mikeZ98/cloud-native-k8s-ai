"""FastAPI control plane: compile, stream and validate AI-stack manifests, with probes
and Prometheus telemetry.

Serve with ``uvicorn --factory cloud_native_k8s_ai.api:create_app --port 8000``; the
chart's FastAPI Deployment probes ``/healthz`` (liveness) and ``/readyz`` (readiness).
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, TextIO

import anyio
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST

from cloud_native_k8s_ai import __version__
from cloud_native_k8s_ai.api.config import ApiSettings
from cloud_native_k8s_ai.api.deps import SCHEMA_COMPONENTS, component
from cloud_native_k8s_ai.api.middleware import RequestContextMiddleware
from cloud_native_k8s_ai.api.models import HealthResponse, ReadinessResponse
from cloud_native_k8s_ai.api.problems import install_problem_handlers
from cloud_native_k8s_ai.api.routes import compile as compile_routes
from cloud_native_k8s_ai.api.routes import validate as validate_routes
from cloud_native_k8s_ai.api.service import ControlPlane
from cloud_native_k8s_ai.api.telemetry import Metrics, configure_logging


class ControlPlaneApp(FastAPI):
    """FastAPI whose OpenAPI document also carries the hand-registered body schemas."""

    def openapi(self) -> dict[str, Any]:
        if self.openapi_schema is None:
            schema = super().openapi()
            schemas = schema.setdefault("components", {}).setdefault("schemas", {})
            schemas.update(SCHEMA_COMPONENTS)
        return super().openapi()


def create_app(settings: ApiSettings | None = None, *, log_stream: TextIO | None = None) -> FastAPI:
    """Build the control plane. The lifespan configures JSON logging, registers runtime
    collectors on the app's Prometheus registry and runs the readiness self-checks."""
    settings = settings or ApiSettings()
    metrics = Metrics()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        logger = configure_logging(settings.log_level, log_stream)
        metrics.start(__version__)
        plane = await anyio.to_thread.run_sync(ControlPlane.start, settings, metrics)
        app.state.plane = plane
        logger.info("control plane started", extra={"ready": plane.ready, "checks": plane.checks})
        try:
            yield
        finally:
            plane.draining = True  # /readyz fails while connections drain
            metrics.stop()
            logger.info("control plane stopped")

    app = ControlPlaneApp(
        title="cloud-native-k8s-ai control plane",
        version=__version__,
        summary="Compile, stream and validate zero-trust AI stack manifests, offline.",
        lifespan=lifespan,
        redoc_url=None,
    )
    app.state.settings = settings
    app.state.metrics = metrics
    app.state.started = time.monotonic()
    app.add_middleware(RequestContextMiddleware, metrics=metrics)
    install_problem_handlers(app)
    app.include_router(compile_routes.router)
    app.include_router(validate_routes.router)

    @app.get(
        "/healthz",
        tags=["probes"],
        summary="Liveness: the process serves requests",
        responses={200: {"content": {"application/json": {"schema": component(HealthResponse)}}}},
    )
    async def healthz() -> JSONResponse:
        uptime = round(time.monotonic() - app.state.started, 3)
        return JSONResponse(HealthResponse(version=__version__, uptime_seconds=uptime).to_wire())

    @app.get(
        "/readyz",
        tags=["probes"],
        summary="Readiness: chart, schemas and generator passed their self-checks",
        responses={
            200: {"content": {"application/json": {"schema": component(ReadinessResponse)}}},
            503: {"description": "Not ready (starting, failed self-check or draining)"},
        },
    )
    async def readyz(request: Request) -> JSONResponse:
        plane: ControlPlane | None = getattr(request.app.state, "plane", None)
        checks = {"lifespan": "not started"} if plane is None else dict(plane.checks)
        if plane is not None and plane.draining:
            checks["lifespan"] = "draining"
        ready = plane is not None and plane.ready
        body = ReadinessResponse(status="ready" if ready else "unavailable", checks=checks)
        return JSONResponse(body.to_wire(), status_code=200 if ready else 503)

    @app.get(
        "/metrics",
        tags=["probes"],
        summary="Prometheus metrics (text exposition format)",
        responses={200: {"content": {CONTENT_TYPE_LATEST: {"schema": {"type": "string"}}}}},
    )
    async def prometheus_metrics() -> Response:
        return Response(metrics.render(), media_type=CONTENT_TYPE_LATEST)

    return app
