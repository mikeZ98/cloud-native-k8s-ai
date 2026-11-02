"""Generate the API and CLI reference from the live OpenAPI document and argparse parser.

``docs/api_reference.md`` carries hand-written prose plus generated blocks between
``<!-- BEGIN GENERATED: <name> -->`` and ``<!-- END GENERATED: <name> -->`` markers;
``docs/openapi.json`` is the full OpenAPI snapshot. ``tests/test_docs.py`` fails when
either drifts from the code. Regenerate with::

    python -m cloud_native_k8s_ai.tools.reference
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, Final

from cloud_native_k8s_ai.api import create_app
from cloud_native_k8s_ai.api.config import DEFAULT_CHART_DIR
from cloud_native_k8s_ai.cli import build_parser

REPO_ROOT: Final = DEFAULT_CHART_DIR.parents[2]
API_REFERENCE: Final = Path("docs") / "api_reference.md"
OPENAPI_SNAPSHOT: Final = Path("docs") / "openapi.json"
REF_PREFIX: Final = "#/components/schemas/"
_METHODS: Final = ("get", "post", "put", "patch", "delete")


class ReferenceError(Exception):  # noqa: A001 - the reference documents, not the builtin
    """A generated block's markers are missing or malformed."""


def openapi() -> dict[str, Any]:
    document: dict[str, Any] = create_app().openapi()
    return document


def openapi_snapshot(document: Mapping[str, Any]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------------
# JSON Schema rendering
# ---------------------------------------------------------------------------
def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _code(value: Any) -> str:
    return f"`{_cell(json.dumps(value, ensure_ascii=False))}`"


def describe(schema: Mapping[str, Any]) -> str:  # noqa: PLR0911 - one exit per schema kind
    """A compact, linked type expression for a JSON Schema."""
    if "$ref" in schema:
        name = str(schema["$ref"]).removeprefix(REF_PREFIX)
        return f"[{name}](#{name.lower()})"
    if "const" in schema:
        return _code(schema["const"])
    if "enum" in schema:
        return " \\| ".join(_code(v) for v in schema["enum"])
    for key in ("anyOf", "oneOf", "allOf"):
        if key in schema:
            return " or ".join(describe(s) for s in schema[key])
    kind = schema.get("type")
    if kind == "array":
        if "prefixItems" in schema:
            return "[" + ", ".join(describe(s) for s in schema["prefixItems"]) + "]"
        return f"array of {describe(schema.get('items', {}))}"
    if kind == "object":
        values = schema.get("additionalProperties")
        if isinstance(values, Mapping):
            return f"map of {describe(values)}"
        patterns = schema.get("patternProperties")
        if isinstance(patterns, Mapping) and patterns:
            return f"map of {describe(next(iter(patterns.values())))}"
        return "object"
    return str(kind) if kind else "any"


_CONSTRAINTS: Final = (
    ("minimum", "≥ {}"),
    ("exclusiveMinimum", "> {}"),
    ("maximum", "≤ {}"),
    ("exclusiveMaximum", "< {}"),
    ("minLength", "length ≥ {}"),
    ("maxLength", "length ≤ {}"),
    ("minItems", "items ≥ {}"),
    ("maxItems", "items ≤ {}"),
    ("format", "format {}"),
)


def constraints(schema: Mapping[str, Any]) -> str:
    parts = [template.format(schema[key]) for key, template in _CONSTRAINTS if key in schema]
    if "pattern" in schema:
        parts.append(f"pattern `{_cell(str(schema['pattern']))}`")
    return ", ".join(parts)


def _default(schema: Mapping[str, Any]) -> str:
    if "default" not in schema:
        return ""
    text = json.dumps(schema["default"], ensure_ascii=False)
    return _code(schema["default"]) if len(text) <= 40 else "(see `openapi.json`)"  # noqa: PLR2004


def schema_section(name: str, schema: Mapping[str, Any]) -> str:
    lines = [f"### {name}", ""]
    if description := schema.get("description"):
        lines += [" ".join(str(description).split()), ""]
    properties: Mapping[str, Any] = schema.get("properties", {})
    if not properties:
        lines += [f"Type: {describe(schema)}", ""]
        return "\n".join(lines)
    required = set(schema.get("required", ()))
    lines += [
        "| Field | Type | Required | Default | Constraints |",
        "|---|---|---|---|---|",
        *(
            f"| `{field}` | {describe(prop)} | {'yes' if field in required else ''} "
            f"| {_default(prop)} | {constraints(prop)} |"
            for field, prop in properties.items()
        ),
        "",
    ]
    return "\n".join(lines)


def schemas_block(document: Mapping[str, Any]) -> str:
    components: Mapping[str, Any] = document["components"]["schemas"]
    return "\n".join(schema_section(name, components[name]) for name in sorted(components))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
def _operations(document: Mapping[str, Any]) -> Iterator[tuple[str, str, Mapping[str, Any]]]:
    for path, item in document["paths"].items():
        for method in _METHODS:
            if method in item:
                yield path, method, item[method]


def endpoints_block(document: Mapping[str, Any]) -> str:
    lines = ["| Method | Path | Summary |", "|---|---|---|"]
    lines += [
        f"| `{method.upper()}` | `{path}` | {op.get('summary', '')} |"
        for path, method, op in _operations(document)
    ]
    for path, method, op in _operations(document):
        lines += ["", f"### `{method.upper()} {path}`", "", str(op.get("summary", "")), ""]
        if parameters := op.get("parameters"):
            lines += [
                "| Parameter | In | Type | Required | Default | Constraints |",
                "|---|---|---|---|---|---|",
                *(
                    f"| `{p['name']}` | {p['in']} | {describe(p.get('schema', {}))} "
                    f"| {'yes' if p.get('required') else ''} | {_default(p.get('schema', {}))} "
                    f"| {constraints(p.get('schema', {}))} |"
                    for p in parameters
                ),
                "",
            ]
        if body := op.get("requestBody"):
            lines.append("Request body:")
            lines += [
                f"- `{media}`: {describe(spec.get('schema', {}))}"
                for media, spec in body.get("content", {}).items()
            ]
            lines.append("")
        lines += ["| Status | Description | Content |", "|---|---|---|"]
        for status, response in op.get("responses", {}).items():
            content = response.get("content", {})
            rendered = "; ".join(
                f"`{media}`" + (f" {describe(spec['schema'])}" if spec.get("schema") else "")
                for media, spec in content.items()
            )
            lines.append(
                f"| {status} | {_cell(str(response.get('description', '')))} | {rendered} |"
            )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _subcommands(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    return {}


def _cli_default(value: Any) -> str:
    if value is None or value is False or value in ([], argparse.SUPPRESS):
        return ""
    if isinstance(value, Path):
        value = value.relative_to(REPO_ROOT).as_posix()
    return f"`{value}`"


def _cli_rows(parser: argparse.ArgumentParser) -> list[str]:
    rows = []
    for action in parser._actions:
        if isinstance(action, argparse._HelpAction | argparse._SubParsersAction):
            continue
        name = ", ".join(action.option_strings) if action.option_strings else action.dest
        choices = " \\| ".join(f"`{c}`" for c in action.choices) if action.choices else ""
        repeat = " (repeatable)" if isinstance(action, argparse._AppendAction) else ""
        help_text = _cell(str(action.help or "")) + repeat
        rows.append(f"| `{name}` | {_cli_default(action.default)} | {choices} | {help_text} |")
    return rows


def cli_block(parser: argparse.ArgumentParser | None = None) -> str:
    parser = parser or build_parser()
    lines: list[str] = []

    def walk(command: argparse.ArgumentParser, path: str) -> None:
        children = _subcommands(command)
        rows = _cli_rows(command)
        if path:
            lines.extend(["", f"### `{path}`", ""])
            if command.description:
                lines.extend([command.description, ""])
            if rows:
                lines.extend(
                    ["| Argument | Default | Choices | Description |", "|---|---|---|---|"]
                )
                lines.extend(rows)
        for name, child in children.items():
            walk(child, f"{path} {name}".strip())

    walk(parser, "")
    return "\n".join(lines).strip()


# ---------------------------------------------------------------------------
# Splicing
# ---------------------------------------------------------------------------
def splice(markdown: str, name: str, content: str) -> str:
    """Replace the generated block ``name`` in ``markdown`` with ``content``."""
    begin, finish = f"<!-- BEGIN GENERATED: {name} -->\n", f"\n<!-- END GENERATED: {name} -->"
    pattern = re.compile(f"({re.escape(begin)}).*?({re.escape(finish)})", re.DOTALL)
    if len(pattern.findall(markdown)) != 1:
        raise ReferenceError(f"expected exactly one generated block {name!r}")
    return pattern.sub(lambda m: m.group(1) + content + m.group(2), markdown)


def render_reference(markdown: str, document: Mapping[str, Any]) -> str:
    for name, content in (
        ("endpoints", endpoints_block(document)),
        ("schemas", schemas_block(document)),
        ("cli", cli_block()),
    ):
        markdown = splice(markdown, name, content)
    return markdown


def regenerate(root: Path) -> list[Path]:
    """Rewrite the generated files under ``root``; return those that changed."""
    document = openapi()
    snapshot, reference = root / OPENAPI_SNAPSHOT, root / API_REFERENCE
    updates = {
        snapshot: openapi_snapshot(document),
        reference: render_reference(reference.read_text(encoding="utf-8"), document),
    }
    changed: list[Path] = []
    for path, text in updates.items():
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")
            changed.append(path)
    return changed


if __name__ == "__main__":
    for written in regenerate(Path.cwd()):
        print(f"regenerated {written}")  # noqa: T201
