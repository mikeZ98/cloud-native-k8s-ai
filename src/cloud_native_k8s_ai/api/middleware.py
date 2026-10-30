"""Request tracing: correlation IDs, access logs, HTTP metrics and the last-resort 500.

A pure ASGI middleware (not ``BaseHTTPMiddleware``) so streaming responses pass through
untouched and a client disconnect cancels the endpoint instead of leaking a task.
"""

from __future__ import annotations

import logging
import time

from starlette.datastructures import Headers, MutableHeaders
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from cloud_native_k8s_ai.api.problems import internal_error
from cloud_native_k8s_ai.api.telemetry import (
    LOGGER_NAME,
    REQUEST_ID,
    REQUEST_ID_HEADER,
    Metrics,
    accept_request_id,
)

_LOG = logging.getLogger(LOGGER_NAME)
UNMATCHED_ROUTE = "<unmatched>"


def route_template(scope: Scope) -> str:
    """Path template of the matched route (``/api/v1/compile``): a low-cardinality label."""
    return str(getattr(scope.get("route"), "path", UNMATCHED_ROUTE))


class RequestContextMiddleware:
    """Tag each HTTP request with a correlation ID; log and measure it on completion."""

    def __init__(self, app: ASGIApp, *, metrics: Metrics) -> None:
        self.app = app
        self.metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = accept_request_id(Headers(scope=scope).get(REQUEST_ID_HEADER))
        token = REQUEST_ID.set(request_id)
        status, started = 500, False
        begin = time.perf_counter()
        self.metrics.in_flight.inc()

        async def send_with_id(message: Message) -> None:
            nonlocal status, started
            if message["type"] == "http.response.start":
                status, started = message["status"], True
                MutableHeaders(scope=message).append(REQUEST_ID_HEADER, request_id)
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        except Exception:
            _LOG.exception("unhandled error", extra={"path": scope["path"]})
            if started:  # too late for a problem response: let the server drop the connection
                raise
            await internal_error(Request(scope))(scope, receive, send_with_id)
        finally:
            elapsed = time.perf_counter() - begin
            route = route_template(scope)
            method = scope["method"]
            self.metrics.in_flight.dec()
            self.metrics.requests.labels(method, route, str(status)).inc()
            self.metrics.latency.labels(method, route).observe(elapsed)
            _LOG.info(
                "request completed",
                extra={
                    "method": method,
                    "path": scope["path"],
                    "route": route,
                    "status": status,
                    "duration_ms": round(elapsed * 1000, 3),
                },
            )
            REQUEST_ID.reset(token)
