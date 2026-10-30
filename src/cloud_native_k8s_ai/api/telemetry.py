"""Correlation IDs, structured JSON logging and Prometheus metrics for the control plane.

Every app instance owns its own ``CollectorRegistry`` so several apps (one per test, or
per worker) never collide on the process-global default registry.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any, Final, TextIO

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
)
from prometheus_client.gc_collector import GCCollector
from prometheus_client.platform_collector import PlatformCollector
from prometheus_client.process_collector import ProcessCollector
from prometheus_client.registry import Collector

LOGGER_NAME: Final = "cloud_native_k8s_ai.api"
REQUEST_ID_HEADER: Final = "X-Request-ID"
REQUEST_ID: ContextVar[str | None] = ContextVar("request_id", default=None)
"""Correlation ID of the request being served (also visible in worker threads)."""

_REQUEST_ID_RE: Final = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def accept_request_id(value: str | None) -> str:
    """Propagate the caller's correlation ID when it is safe to echo back, else mint one."""
    if value is not None and _REQUEST_ID_RE.match(value):
        return value
    return uuid.uuid4().hex


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
_RECORD_ATTRIBUTES: Final = frozenset(
    set(vars(logging.LogRecord("", logging.INFO, "", 0, "", (), None))) | {"message", "asctime"}
)


class JsonFormatter(logging.Formatter):
    """One JSON object per line: timestamp, level, logger, message, request ID, extras."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if (request_id := REQUEST_ID.get()) is not None:
            entry["request_id"] = request_id
        entry |= {k: v for k, v in vars(record).items() if k not in _RECORD_ATTRIBUTES}
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


class _JsonHandler(logging.StreamHandler[TextIO]):
    """Marker type so ``configure_logging`` replaces only its own handler."""


def configure_logging(level: str, stream: TextIO | None = None) -> logging.Logger:
    """Point the API logger at ``stream`` (stderr by default) with JSON lines; idempotent."""
    logger = logging.getLogger(LOGGER_NAME)
    for handler in [h for h in logger.handlers if isinstance(h, _JsonHandler)]:
        logger.removeHandler(handler)
    handler = _JsonHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
_LATENCY_BUCKETS: Final = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


class Metrics:
    """The control plane's Prometheus metrics, on a registry private to one app."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        registry = self.registry
        self.requests = Counter(
            "http_requests_total",
            "HTTP requests by method, route template and status code.",
            ("method", "route", "status"),
            registry=registry,
        )
        self.latency = Histogram(
            "http_request_duration_seconds",
            "HTTP request latency by method and route template (streams: until the last byte).",
            ("method", "route"),
            buckets=_LATENCY_BUCKETS,
            registry=registry,
        )
        self.in_flight = Gauge(
            "http_requests_in_flight", "HTTP requests being served.", registry=registry
        )
        self.compilations = Counter(
            "manifest_compilations_total",
            "AI stack compilations by outcome (success, failure).",
            ("outcome",),
            registry=registry,
        )
        self.compile_latency = Histogram(
            "manifest_compile_duration_seconds",
            "Time to build, bind and zero-trust-check one AI stack.",
            buckets=_LATENCY_BUCKETS,
            registry=registry,
        )
        self.documents = Counter(
            "manifest_documents_total",
            "Kubernetes documents emitted by successful compilations, by kind.",
            ("kind",),
            registry=registry,
        )
        self.validations = Counter(
            "validations_total",
            "Chart and topology validations by target and outcome (pass, fail).",
            ("target", "outcome"),
            registry=registry,
        )
        self.streams = Counter(
            "manifest_streams_total",
            "Manifest event streams by outcome (completed, aborted).",
            ("outcome",),
            registry=registry,
        )
        self.build = Info(
            "control_plane_build", "Control plane build information.", registry=registry
        )
        self._runtime: list[Collector] = []

    def start(self, version: str) -> None:
        """Register process, platform and GC collectors (once per app lifespan)."""
        self.stop()
        self._runtime = [
            ProcessCollector(registry=None),
            PlatformCollector(registry=None),
            GCCollector(registry=CollectorRegistry()),  # detached; registered below
        ]
        for collector in self._runtime:
            self.registry.register(collector)
        self.build.info({"version": version})

    def stop(self) -> None:
        for collector in self._runtime:
            self.registry.unregister(collector)
        self._runtime = []

    def render(self) -> bytes:
        return generate_latest(self.registry)
