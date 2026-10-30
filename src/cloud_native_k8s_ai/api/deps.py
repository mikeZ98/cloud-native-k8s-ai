"""Request plumbing shared by the routers: the control plane, bounded bodies, strict parsing.

Bodies are parsed with ``model_validate_json`` rather than FastAPI's body binding: the
contracts are strict, and Python-mode validation rejects JSON arrays for tuple fields.
``json_body`` documents those bodies in OpenAPI all the same.
"""

from __future__ import annotations

from typing import Annotated, Any, Final

from fastapi import Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ValidationError

from cloud_native_k8s_ai.api.problems import ControlPlaneUnavailableError
from cloud_native_k8s_ai.api.service import ControlPlane

SCHEMA_COMPONENTS: Final[dict[str, Any]] = {}
"""Request body schemas (and their ``$defs``), merged into ``components.schemas``."""


def get_plane(request: Request) -> ControlPlane:
    plane: ControlPlane | None = getattr(request.app.state, "plane", None)
    if plane is None:
        raise ControlPlaneUnavailableError("control plane is not started")
    return plane


Plane = Annotated[ControlPlane, Depends(get_plane)]


async def read_body(request: Request, limit: int) -> bytes:
    """The request body, refused with 413 as soon as it exceeds ``limit`` bytes."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise HTTPException(413, f"request body exceeds {limit} bytes")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(413, f"request body exceeds {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def parse_model[M: BaseModel](model: type[M], raw: bytes) -> M:
    """Strict JSON-mode validation; failures become a 422 ``invalid-request`` problem."""
    try:
        return model.model_validate_json(raw)
    except ValidationError as exc:
        errors = [
            {"loc": ("body", *e["loc"]), "msg": e["msg"], "type": e["type"]} for e in exc.errors()
        ]
        raise RequestValidationError(errors) from exc


def component(model: type[BaseModel]) -> dict[str, str]:
    """Register ``model`` (camelCase) in ``components.schemas``; return a ``$ref`` to it."""
    schema = model.model_json_schema(by_alias=True, ref_template="#/components/schemas/{model}")
    SCHEMA_COMPONENTS.update(schema.pop("$defs", {}))
    SCHEMA_COMPONENTS[model.__name__] = schema
    return {"$ref": f"#/components/schemas/{model.__name__}"}


def json_body(model: type[BaseModel], *extra_media: str) -> dict[str, Any]:
    """``openapi_extra`` declaring ``model`` as the JSON request body."""
    content: dict[str, Any] = {"application/json": {"schema": component(model)}}
    content |= {media: {"schema": {"type": "string"}} for media in extra_media}
    return {"requestBody": {"required": True, "content": content}}
