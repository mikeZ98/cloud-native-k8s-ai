"""RFC 7807 problem responses for every failure the control plane can report.

Core errors map onto stable problem types: contract and zero-trust violations are 422
(the request is well-formed but describes an invalid stack), unparseable manifests are
400, an unready control plane is 503. Unknown errors become an opaque 500 problem.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, Final, cast

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from cloud_native_k8s_ai.api.models import RemediationSummary
from cloud_native_k8s_ai.api.telemetry import REQUEST_ID
from cloud_native_k8s_ai.core import (
    K8sAiCoreError,
    ManifestRenderError,
    ResourceConstraintError,
    TopologyConflictError,
)
from cloud_native_k8s_ai.guardrails import AdmissionDeniedError, GuardrailError
from cloud_native_k8s_ai.tools.helm import ChartLintError, ChartValuesError

PROBLEM_JSON: Final = "application/problem+json"
PROBLEM_TYPE_PREFIX: Final = "urn:cloud-native-k8s-ai:problem:"


class ControlPlaneUnavailableError(RuntimeError):
    """The control plane is not started, is draining, or lacks its reference chart."""


def problem(
    request: Request,
    status: int,
    slug: str,
    title: str,
    detail: str,
    *,
    headers: Mapping[str, str] | None = None,
    **extensions: Any,
) -> JSONResponse:
    """An ``application/problem+json`` response carrying the request's correlation ID."""
    body: dict[str, Any] = {
        "type": f"{PROBLEM_TYPE_PREFIX}{slug}",
        "title": title,
        "status": status,
        "detail": detail,
        "instance": request.url.path,
    }
    if (request_id := REQUEST_ID.get()) is not None:
        body["requestId"] = request_id
    body |= extensions
    return JSONResponse(body, status_code=status, media_type=PROBLEM_JSON, headers=headers)


@dataclass(frozen=True, slots=True)
class _CoreProblem:
    status: int
    slug: str
    title: str


# Most specific first: Starlette resolves handlers along the exception's MRO.
_CORE_PROBLEMS: Final[Sequence[tuple[type[K8sAiCoreError], _CoreProblem]]] = (
    (AdmissionDeniedError, _CoreProblem(422, "admission-denied", "Admission denied")),
    (GuardrailError, _CoreProblem(400, "guardrail-error", "Guardrails could not evaluate")),
    (ChartValuesError, _CoreProblem(422, "invalid-chart-values", "Chart values are invalid")),
    (ChartLintError, _CoreProblem(422, "chart-lint-failed", "Chart lint failed")),
    (TopologyConflictError, _CoreProblem(422, "topology-conflict", "Zero-trust topology violated")),
    (
        ResourceConstraintError,
        _CoreProblem(422, "resource-constraint", "Resource constraints violated"),
    ),
    (
        ManifestRenderError,
        _CoreProblem(400, "manifest-render", "Manifests cannot be rendered or parsed"),
    ),
    (K8sAiCoreError, _CoreProblem(400, "core-error", "Infrastructure compilation failed")),
)


def _core_extensions(exc: K8sAiCoreError) -> dict[str, Any]:
    match exc:
        case AdmissionDeniedError():
            extensions: dict[str, Any] = {
                "decision": exc.report.decision.value,
                "violations": [v.to_wire() for v in exc.report.violations],
            }
            if exc.remediation is not None:
                summary = RemediationSummary.from_result(exc.remediation)
                extensions["remediation"] = summary.to_wire()
            return extensions
        case ChartValuesError():
            return {"problems": list(exc.problems)}
        case ChartLintError():
            return {"findings": list(exc.findings)}
        case TopologyConflictError():
            return {"violations": [{"code": v.code, "message": v.message} for v in exc.violations]}
        case _:
            return {}


def _core_detail(exc: K8sAiCoreError) -> str:
    """List-carrying errors put the list in an extension; keep only the headline."""
    text = str(exc)
    if isinstance(
        exc, AdmissionDeniedError | ChartValuesError | ChartLintError | TopologyConflictError
    ):
        return text.splitlines()[0].removesuffix(":")
    return text


def _handle_core(request: Request, exc: Exception) -> JSONResponse:
    exc = cast("K8sAiCoreError", exc)  # registered for core errors only
    spec = next(p for kind, p in _CORE_PROBLEMS if isinstance(exc, kind))
    return problem(
        request, spec.status, spec.slug, spec.title, _core_detail(exc), **_core_extensions(exc)
    )


def _handle_validation(request: Request, exc: Exception) -> JSONResponse:
    exc = cast("RequestValidationError", exc)
    errors = [
        {
            "loc": list(e.get("loc", ())),
            "msg": str(e.get("msg", "")),
            "type": str(e.get("type", "")),
        }
        for e in exc.errors()
    ]
    return problem(
        request,
        422,
        "invalid-request",
        "Request validation failed",
        f"{len(errors)} validation error(s) in the request",
        errors=errors,
    )


def _handle_http(request: Request, exc: Exception) -> JSONResponse:
    exc = cast("StarletteHTTPException", exc)
    title = HTTPStatus(exc.status_code).phrase
    return problem(
        request,
        exc.status_code,
        f"http-{exc.status_code}",
        title,
        str(exc.detail),
        headers=exc.headers,
    )


def _handle_unavailable(request: Request, exc: Exception) -> JSONResponse:
    return problem(request, 503, "unavailable", "Control plane unavailable", str(exc))


def internal_error(request: Request) -> JSONResponse:
    """Opaque 500: details go to the log (with the request ID), never to the client."""
    return problem(
        request,
        500,
        "internal-error",
        "Internal server error",
        "an unexpected error occurred; quote the request ID when reporting it",
    )


def install_problem_handlers(app: FastAPI) -> None:
    for kind, _ in _CORE_PROBLEMS:
        app.add_exception_handler(kind, _handle_core)
    app.add_exception_handler(RequestValidationError, _handle_validation)
    app.add_exception_handler(StarletteHTTPException, _handle_http)
    app.add_exception_handler(ControlPlaneUnavailableError, _handle_unavailable)
