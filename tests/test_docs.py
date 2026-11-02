"""Documentation and CI stay true to the code.

Hermetic: files are read from the repository and compared with live objects (the
topology solver's reachable flows, the violation-code catalog, the adversarial vectors,
the CLI parser and the API routes). No network, no subprocess.
"""

from __future__ import annotations

import argparse
import os
import re
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

from cloud_native_k8s_ai.api import create_app
from cloud_native_k8s_ai.cli import _reference, build_parser
from cloud_native_k8s_ai.core import (
    AIStackGenerator,
    AutoscalingPolicy,
    TopologySolver,
    compile_ai_stack,
    desired_replicas,
)
from cloud_native_k8s_ai.guardrails import CATALOG
from tests.test_adversarial import BOMBS, VECTORS

ROOT = Path(__file__).resolve().parent.parent
CHART_DIR = ROOT / "deploy" / "helm" / "cloud-native-k8s-ai"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
ARCHITECTURE = ROOT / "docs" / "architecture.md"
SECURITY = ROOT / "docs" / "security_model.md"
README = ROOT / "README.md"


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("K8SAI_"):
            monkeypatch.delenv(key)


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def table_rows(markdown: str) -> list[list[str]]:
    return [
        [cell.strip() for cell in line.strip("|").split("|")]
        for line in markdown.splitlines()
        if line.startswith("|") and not re.match(r"^\|[-| ]+\|$", line)
    ]


def markdown_table(markdown: str, header: str) -> list[list[str]]:
    """Data rows of the table whose header row starts with ``header`` (header excluded)."""
    lines = markdown.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(header))
    end = next((i for i in range(start, len(lines)) if not lines[i].startswith("|")), len(lines))
    return table_rows("\n".join(lines[start + 1 : end]))


# Fenced code blocks (``` or ~~~, up to three spaces of indent) and inline code spans.
FENCED_BLOCK = re.compile(
    r"^ {0,3}(?P<fence>`{3,}|~{3,})(?P<info>[^\n]*)\n(?P<body>.*?)^ {0,3}(?P=fence)[ \t]*$",
    re.MULTILINE | re.DOTALL,
)
INLINE_CODE = re.compile(r"(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)")
SHELL_FENCES = frozenset({"", "bash", "sh", "shell", "console", "zsh"})


def without_fences(markdown: str) -> str:
    """Markdown minus fenced code blocks: ``#`` comments in shell blocks are not headings."""
    return FENCED_BLOCK.sub("", markdown)


def prose(markdown: str) -> str:
    """Markdown minus fenced blocks and inline code: only real links live here."""
    return INLINE_CODE.sub("", without_fences(markdown))


def shell_snippets(markdown: str) -> list[str]:
    """Bodies of shell code fences plus inline code spans: where commands are written."""
    fenced = [
        m["body"]
        for m in FENCED_BLOCK.finditer(markdown)
        if m["info"].strip().split(" ")[0] in SHELL_FENCES
    ]
    return fenced + [m.group(2) for m in INLINE_CODE.finditer(without_fences(markdown))]


def links(markdown: str) -> list[str]:
    """Targets of inline Markdown links outside code."""
    return re.findall(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", prose(markdown))


# ---------------------------------------------------------------------------
# CI workflow
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def workflow() -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(text(WORKFLOW))
    return loaded


def run_lines(workflow: dict[str, Any], job: str) -> list[str]:
    return [step["run"] for step in workflow["jobs"][job]["steps"] if "run" in step]


def test_workflow_triggers_and_least_privilege(workflow: dict[str, Any]) -> None:
    triggers = workflow[True]  # type: ignore[index]  # YAML 1.1 reads the bare `on:` as True
    assert triggers.keys() == {"push", "pull_request", "workflow_dispatch"}
    assert triggers["push"] == {"branches": ["main"]}
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"]["cancel-in-progress"] is True
    assert "secrets." not in text(WORKFLOW)
    assert workflow["env"]["HYPOTHESIS_PROFILE"] == "hermetic"
    assert workflow["env"]["PYTHONHASHSEED"] == "0"


def test_workflow_actions_are_pinned_by_commit_sha(workflow: dict[str, Any]) -> None:
    steps = [s for job in workflow["jobs"].values() for s in job["steps"]]
    uses = [s["uses"] for s in steps if "uses" in s]
    assert uses
    assert all(re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u) for u in uses), uses
    for line in text(WORKFLOW).splitlines():
        if "uses:" in line:
            assert re.search(r"@[0-9a-f]{40}  # v\d+\.\d+\.\d+$", line), line
    checkouts = [s for s in steps if s.get("uses", "").startswith("actions/checkout@")]
    assert all(s["with"]["persist-credentials"] is False for s in checkouts)


def test_workflow_runs_every_quality_gate(workflow: dict[str, Any]) -> None:
    jobs = workflow["jobs"]
    assert jobs.keys() == {"static-analysis", "tests", "attribution"}
    assert jobs["tests"]["needs"] == "static-analysis"
    assert all(job["timeout-minutes"] <= 30 for job in jobs.values())
    static = run_lines(workflow, "static-analysis")
    assert static == [
        "uv sync --locked",
        "uv run --locked ruff check .",
        "uv run --locked ruff format --check .",
        "uv run --locked mypy",
        "uv run --locked bandit -c pyproject.toml -r src",
        "uv run --locked yamllint --strict .",
    ]
    assert run_lines(workflow, "tests") == ["uv sync --locked", "uv run --locked pytest"]
    assert run_lines(workflow, "attribution") == ["scripts/audit-attribution.sh --history-only"]
    checkout = jobs["attribution"]["steps"][0]
    assert checkout["with"]["fetch-depth"] == 0  # the audit needs the whole history
    # ... and the PR head, never GitHub's synthetic merge commit (committer "GitHub")
    assert checkout["with"]["ref"] == "${{ github.event.pull_request.head.sha || github.sha }}"


def test_coverage_gate_is_100_percent_branch() -> None:
    pyproject = tomllib.loads(text(ROOT / "pyproject.toml"))
    assert pyproject["tool"]["coverage"]["report"]["fail_under"] == 100
    assert pyproject["tool"]["coverage"]["run"]["branch"] is True
    assert "--disable-socket" in pyproject["tool"]["pytest"]["ini_options"]["addopts"]


# ---------------------------------------------------------------------------
# Architecture
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def reachable() -> set[str]:
    reference = _reference(CHART_DIR)
    generator = AIStackGenerator(reference.settings(), reference.stack)
    bundle = compile_ai_stack(reference.settings(), reference.stack)
    report = TopologySolver(generator.topology(bundle)).verify(generator.intent())
    assert report.ok
    return {str(flow) for flow in report.reachable}


def test_reachable_flow_listing_matches_the_solver(reachable: set[str]) -> None:
    block = re.search(
        r"<!-- reachable:begin -->\n```text\n(.*?)```\n<!-- reachable:end -->",
        text(ARCHITECTURE),
        re.DOTALL,
    )
    assert block is not None
    assert set(block.group(1).strip().splitlines()) == reachable
    assert f"= 5 + 8 = {len(reachable)}" in text(ARCHITECTURE)


def test_topology_matrix_matches_the_solver(reachable: set[str]) -> None:
    rows = table_rows(text(ARCHITECTURE).split("## 3. Topology matrix")[1].split("The same set")[0])
    header, *body = rows
    destinations = header[1:]
    documented = set()
    for source, *cells in body:
        for destination, cell in zip(destinations, cells, strict=True):
            if cell != "—":
                documented |= {f"{source} -> {destination} {port}" for port in cell.split(", ")}
    assert documented == reachable


def test_keda_table_matches_the_model() -> None:
    section = text(ARCHITECTURE).split("For the reference policy")[1]
    lengths, replicas = (row[1:] for row in table_rows(section)[:2])
    policy = AutoscalingPolicy()
    assert [desired_replicas(policy, int(q)) for q in lengths] == [int(r) for r in replicas]


def test_architecture_has_every_required_diagram() -> None:
    blocks = re.findall(r"```mermaid\n(\w+)", text(ARCHITECTURE))
    assert blocks.count("flowchart") >= 4
    assert "sequenceDiagram" in blocks
    for heading in (
        "Topology matrix",
        "The zero-trust invariant",
        "Admission control critic loop",
        "Zero-trust flow interception",
        "KEDA scaling loop",
    ):
        assert f". {heading}" in text(ARCHITECTURE)


# ---------------------------------------------------------------------------
# Security model
# ---------------------------------------------------------------------------
def test_code_catalog_is_documented_exactly() -> None:
    section = text(SECURITY).split("## 5. Violation code catalog")[1].split("## 6.")[0]
    rows = [r for r in table_rows(section) if r[0].startswith("`")]
    documented = {r[0].strip("`"): (r[1], r[2], r[3], r[4]) for r in rows}
    expected = {
        code: (spec.policy, spec.decision.value, spec.remediation, spec.summary)
        for code, spec in CATALOG.items()
    }
    assert documented == expected


def test_threat_matrix_covers_every_adversarial_vector() -> None:
    section = text(SECURITY).split("## 3. Threat matrix")[1].split("## 4.")[0]
    rows = {r[1].strip("`"): r for r in table_rows(section) if r[0].isdigit()}
    assert len(rows) == len(VECTORS) == 41
    for index, vector in enumerate(VECTORS, start=1):
        number, _, detected, after = rows[vector.name]
        assert int(number) == index
        assert set(re.findall(r"`([a-z-]+)`", detected)) == set(vector.codes)
        expected_after = set(vector.manual)
        assert set(re.findall(r"`([a-z-]+)`", after)) == expected_after
        assert (after == "clean") == (not expected_after)


def test_every_yaml_bomb_is_documented() -> None:
    section = text(SECURITY).split("## 4. Untrusted input")[1].split("## 5.")[0]
    documented = {r[0].strip("`") for r in table_rows(section)}
    assert set(BOMBS) <= documented


# ---------------------------------------------------------------------------
# README
# ---------------------------------------------------------------------------
def assert_link_resolves(doc: Path, target: str) -> None:
    """A relative link names an existing file and, for Markdown, an existing heading anchor."""
    if target.startswith(("http://", "https://", "mailto:")):
        return
    path, _, fragment = target.partition("#")
    resolved = (doc.parent / path) if path else doc
    assert resolved.exists(), (doc.name, target)
    if fragment and resolved.suffix == ".md":
        assert fragment in anchors(text(resolved)), (doc.name, target)


@pytest.mark.parametrize("doc", [README, ARCHITECTURE, SECURITY], ids=lambda p: p.name)
def test_doc_links_resolve(doc: Path) -> None:
    for target in links(text(doc)):
        assert_link_resolves(doc, target)


def test_readme_badges() -> None:
    badges = re.findall(r"\[!\[([^\]]+)\]", text(README))
    for expected in (
        "CI",
        "Python 3.12+",
        "Coverage: 100% branch",
        "Bandit: clean",
        "Zero trust: default deny",
    ):
        assert expected in badges
    assert "actions/workflows/ci.yml/badge.svg" in text(README)


def _subcommands(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    action = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    return dict(action.choices)


def test_readme_commands_exist() -> None:
    commands = _subcommands(build_parser())
    used = set(re.findall(r"k8s-ai ([a-z]+)", text(README)))
    assert used
    assert used <= set(commands), used - set(commands)
    chart = _subcommands(commands["chart"])
    assert set(re.findall(r"k8s-ai chart ([a-z]+)", text(README))) <= set(chart)


def test_readme_endpoints_exist() -> None:
    routes = set(create_app().openapi()["paths"])
    documented = set(re.findall(r"`(?:GET|POST)[^`]*?(/[a-z0-9/_]+)`", text(README)))
    documented |= set(re.findall(r"localhost:8000(/[a-z0-9/_]+)", text(README)))
    assert documented
    assert documented <= routes, documented - routes


def test_readme_eval_run_is_reproducible() -> None:
    from cloud_native_k8s_ai.evals import EvalConfig, Evaluator  # noqa: PLC0415

    block = re.search(
        r"<!-- eval:begin -->\n```text\n\$ k8s-ai eval --seed 0 --samples 300 --spec-samples 100 "
        r"--epsilon 0\.5\n(.*?)```\n<!-- eval:end -->",
        text(README),
        re.DOTALL,
    )
    assert block is not None
    reference = _reference(CHART_DIR)
    config = EvalConfig(seed=0, samples=300, spec_samples=100, epsilon=0.5)
    report = Evaluator(reference.settings(), reference.stack).run(config)
    assert block.group(1).strip() == report.to_text()


# ---------------------------------------------------------------------------
# Phase 10: generated API reference, runbook, alerting rules
# ---------------------------------------------------------------------------
import argparse as _argparse  # noqa: E402
import json  # noqa: E402
import shlex  # noqa: E402
import shutil  # noqa: E402

from cloud_native_k8s_ai.api.problems import _CORE_PROBLEMS  # noqa: E402
from cloud_native_k8s_ai.api.routes.compile import manifest_events  # noqa: E402
from cloud_native_k8s_ai.api.telemetry import Metrics  # noqa: E402
from cloud_native_k8s_ai.cli import EXIT_DENIED, EXIT_INVALID, EXIT_OK  # noqa: E402
from cloud_native_k8s_ai.guardrails import GuardrailDecision  # noqa: E402
from cloud_native_k8s_ai.tools import reference  # noqa: E402

API_REFERENCE = ROOT / "docs" / "api_reference.md"
RUNBOOK = ROOT / "docs" / "runbook.md"
ALERTS = ROOT / "deploy" / "monitoring" / "alerts.yaml"


def anchors(markdown: str) -> set[str]:
    """GitHub heading anchors.

    Headings inside fenced code are ignored (``# comment`` in a shell block is not a
    heading); optional closing hashes are dropped; the text is lower-cased, punctuation
    other than ``-`` and ``_`` removed and each space turned into a hyphen; repeated
    slugs get ``-1``, ``-2``, ... suffixes, as GitHub renders them.
    """
    seen: dict[str, int] = {}
    slugs = set()
    for line in without_fences(markdown).splitlines():
        if heading := re.match(r"^ {0,3}#{1,6}[ \t]+(.+?)(?:[ \t]+#+)?[ \t]*$", line):
            base = re.sub(r"[^\w\- ]", "", heading.group(1).lower()).replace(" ", "-")
            count = seen.get(base, 0)
            seen[base] = count + 1
            slugs.add(f"{base}-{count}" if count else base)
    return slugs


@pytest.mark.parametrize(
    ("markdown", "expected"),
    [
        ("### 3.1 Admission denial storm", {"31-admission-denial-storm"}),
        ("## `k8s-ai eval` options ##", {"k8s-ai-eval-options"}),
        ("## FAQ\n## FAQ\n## FAQ", {"faq", "faq-1", "faq-2"}),
        ("```bash\n# not a heading\n```\n## Real", {"real"}),
        ("#hashtag, not a heading", set()),
    ],
)
def test_anchor_slugs_follow_github(markdown: str, expected: set[str]) -> None:
    assert anchors(markdown) == expected


@pytest.mark.parametrize(
    ("markdown", "expected"),
    [
        ("see [runbook](runbook.md#3-x) and [api](api.md)", ["runbook.md#3-x", "api.md"]),
        ("regex `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` is code", []),
        ("```text\n[a](b.md)\n```\nafter [c](d.md)", ["d.md"]),
        ('titled [x](y.md "Title")', ["y.md"]),
    ],
)
def test_links_skip_code(markdown: str, expected: list[str]) -> None:
    assert links(markdown) == expected


def test_shell_snippets_skip_diagrams_and_prose() -> None:
    markdown = (
        'Run k8s-ai stack in prose.\n```mermaid\nA --> B["k8s-ai CLI"]\n```\n'
        "```bash\nk8s-ai spec\n```\nInline `k8s-ai eval --min x=1`."
    )
    assert shell_snippets(markdown) == ["k8s-ai spec\n", "k8s-ai eval --min x=1"]


def section(markdown: str, start: str, end: str) -> str:
    return markdown.split(start, 1)[1].split(end, 1)[0]


@pytest.fixture(scope="module")
def openapi_document() -> dict[str, Any]:
    return reference.openapi()


def test_openapi_snapshot_is_current(openapi_document: dict[str, Any]) -> None:
    assert text(ROOT / "docs" / "openapi.json") == reference.openapi_snapshot(openapi_document)


def test_api_reference_generated_blocks_are_current(openapi_document: dict[str, Any]) -> None:
    current = text(API_REFERENCE)
    assert reference.render_reference(current, openapi_document) == current
    for path, ops in openapi_document["paths"].items():
        for method in ops:
            assert f"### `{method.upper()} {path}`" in current
    for name in openapi_document["components"]["schemas"]:
        assert f"### {name}\n" in current
    in_page = anchors(current)
    for target in re.findall(r"\]\(#([^)]+)\)", current):
        assert target in in_page, target


def test_regenerate_writes_only_what_changed(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    shutil.copy(API_REFERENCE, tmp_path / "docs" / "api_reference.md")
    stale = reference.splice(text(API_REFERENCE), "cli", "stale")
    (tmp_path / "docs" / "api_reference.md").write_text(stale, encoding="utf-8")
    changed = reference.regenerate(tmp_path)
    assert {p.name for p in changed} == {"openapi.json", "api_reference.md"}
    assert (tmp_path / "docs" / "api_reference.md").read_text(encoding="utf-8") == text(
        API_REFERENCE
    )
    assert reference.regenerate(tmp_path) == []
    with pytest.raises(reference.ReferenceError, match="exactly one generated block 'cli'"):
        reference.splice("no markers here", "cli", "x")


@pytest.mark.parametrize(
    ("schema", "rendered"),
    [
        ({"$ref": "#/components/schemas/InfraSpec"}, "[InfraSpec](#infraspec)"),
        ({"const": "ALL"}, '`"ALL"`'),
        ({"enum": ["a", "b"]}, '`"a"` \\| `"b"`'),
        ({"anyOf": [{"type": "integer"}, {"type": "null"}]}, "integer or null"),
        ({"type": "array", "prefixItems": [{"const": "ALL"}]}, '[`"ALL"`]'),
        ({"type": "array", "items": {"type": "string"}}, "array of string"),
        ({"type": "object", "additionalProperties": {"type": "integer"}}, "map of integer"),
        ({"type": "object", "patternProperties": {"^x$": {"type": "string"}}}, "map of string"),
        ({"type": "object"}, "object"),
        ({}, "any"),
    ],
)
def test_reference_type_rendering(schema: dict[str, Any], rendered: str) -> None:
    assert reference.describe(schema) == rendered


def test_reference_constraints_defaults_and_bare_schemas() -> None:
    schema = {
        "minimum": 1, "exclusiveMinimum": 0, "maximum": 9, "exclusiveMaximum": 10, "minLength": 1,
        "maxLength": 3, "minItems": 1, "maxItems": 2, "format": "uri", "pattern": "^a|b$",
    }  # fmt: skip
    rendered = reference.constraints(schema)
    assert rendered.startswith("≥ 1, > 0, ≤ 9, < 10, length ≥ 1")
    assert rendered.endswith("format uri, pattern `^a\\|b$`")
    assert reference.schema_section("Choice", {"enum": ["x"]}) == '### Choice\n\nType: `"x"`\n'
    long_default = reference.schema_section(
        "M", {"properties": {"f": {"type": "object", "default": {"k": "v" * 50}}}}
    )
    assert "(see `openapi.json`)" in long_default


def test_reference_cli_block_handles_any_parser() -> None:
    parser = _argparse.ArgumentParser(prog="tool", description="a tool")
    parser.add_argument("--path", type=Path, default=reference.REPO_ROOT / "docs")
    parser.add_argument("--quiet", action="store_true", default=_argparse.SUPPRESS)
    assert reference.cli_block(parser) == ""  # no subcommands: nothing to document
    commands = parser.add_subparsers(dest="command")
    child = commands.add_parser("run", description="run it")
    child.add_argument("--path", type=Path, default=reference.REPO_ROOT / "docs")
    child.add_argument("--mode", choices=("a", "b"), default="a", help="pick | one")
    commands.add_parser("bare")  # no description, no arguments: heading only
    block = reference.cli_block(parser)
    assert block.endswith("### `bare`")
    assert "### `run`" in block
    assert "| `--path` | `docs` |  |  |" in block
    assert "| `--mode` | `a` | `a` \\| `b` | pick \\| one |" in block


# Problem types raised by the API layer itself rather than by a core error.
BUILTIN_PROBLEMS = {"invalid-request": "422", "unavailable": "503", "internal-error": "500"}


def test_problem_catalog_matches_the_handlers() -> None:
    rows = table_rows(section(text(API_REFERENCE), "## 3. Problem details", "## 4."))
    documented = {r[0].strip("`"): r[1] for r in rows[1:]}
    core = {spec.slug: str(spec.status) for _, spec in _CORE_PROBLEMS}
    assert documented.items() >= core.items()
    assert documented.items() >= BUILTIN_PROBLEMS.items()
    assert set(documented) == set(core) | set(BUILTIN_PROBLEMS) | {"http-{status}"}


async def test_sse_fields_are_documented() -> None:
    documents = compile_ai_stack(*_reference_stack()).to_documents()[:2]
    frames = [frame async for frame in manifest_events(documents, Metrics())]
    fields = set()
    for frame in frames:
        data = next(line for line in frame.splitlines() if line.startswith("data: "))
        fields |= set(json.loads(data.removeprefix("data: ")))
    sse = section(text(API_REFERENCE), "## 4. Server-Sent Events protocol", "## 5.")
    documented = {f.strip("` ") for row in table_rows(sse)[1:] for f in row[1].split(",")}
    assert documented == fields
    assert "event: manifest" in sse
    assert "event: complete" in sse


def _reference_stack() -> tuple[Any, Any]:
    stack = _reference(CHART_DIR)
    return stack.settings(), stack.stack


def test_exit_codes_are_documented() -> None:
    rows = table_rows(section(text(API_REFERENCE), "| Exit code | Meaning |", "```bash"))
    assert {r[0].strip("`") for r in rows} == {str(EXIT_OK), str(EXIT_DENIED), str(EXIT_INVALID)}


def _parsers() -> dict[str, _argparse.ArgumentParser]:
    commands = _subcommands(build_parser())
    nested = {f"chart {name}": p for name, p in _subcommands(commands["chart"]).items()}
    return {**commands, **nested}


@pytest.mark.parametrize("doc", [RUNBOOK, API_REFERENCE, README], ids=lambda p: p.name)
def test_documented_cli_invocations_parse(doc: Path) -> None:
    parsers = _parsers()
    invocations = [
        invocation
        for snippet in shell_snippets(text(doc))
        # Standalone command only: not the tail of a path or repo name (cloud-native-k8s-ai).
        for invocation in re.findall(r"(?<![\w/.-])k8s-ai ([^`\n|\\]+)", snippet)
    ]
    assert invocations
    for invocation in invocations:
        tokens = [t for t in shlex.split(invocation.split("#")[0]) if t != "…"]
        name = " ".join(tokens[:2]) if tokens[:1] == ["chart"] and len(tokens) > 1 else tokens[0]
        if name.startswith(("-", "[", "<")):  # usage synopsis: `k8s-ai [--version] <command>`
            continue
        assert name in parsers, invocation
        options = {o for action in parsers[name]._actions for o in action.option_strings}
        flags = {t.split("=")[0] for t in tokens if t.startswith("-") and t != "-"}
        assert flags <= options, (invocation, flags - options)


def _metric_names() -> set[str]:
    names = set()
    for family in Metrics().registry.collect():
        suffixes = {
            "counter": ("_total",),
            "histogram": ("", "_bucket", "_count", "_sum"),
            "info": ("_info",),
        }.get(family.type, ("",))
        names |= {family.name + suffix for suffix in suffixes}
    return names


OWN_METRIC = re.compile(
    r"\b(?:http_[a-z_]+|manifest_[a-z_]+|validations_total|control_plane_[a-z_]+)\b"
)


def test_runbook_metrics_codes_and_endpoints_exist(openapi_document: dict[str, Any]) -> None:
    runbook = text(RUNBOOK)
    assert set(OWN_METRIC.findall(runbook)) <= _metric_names()
    not_codes = {
        "ai-system", "inference-api", "keda-hpa-inference-api", "inference-jobs",
        "default-deny-all", "allow-dns-egress", "qdrant-allow-from-app",
        "inference-api-allow-ingress",
        "inference-api-allow-egress", "redis-allow-ingress", "ingress-nginx",
    }  # fmt: skip
    known = set(CATALOG) | {spec.slug for _, spec in _CORE_PROBLEMS} | set(BUILTIN_PROBLEMS)
    kebab = set(re.findall(r"`([a-z]+(?:-[a-z]+)+)`", runbook)) - not_codes
    assert kebab <= known, kebab - known
    warn_row = next(line for line in runbook.splitlines() if line.startswith("| `WARN` codes"))
    warns = set(re.findall(r"`([a-z]+(?:-[a-z]+)+)`", warn_row))
    assert warns == {c for c, s in CATALOG.items() if s.decision is GuardrailDecision.WARN}
    paths = set(re.findall(r"`?(/api/v1/[a-z/]+|/readyz|/healthz|/metrics)\b", runbook))
    assert paths <= set(openapi_document["paths"])


@pytest.fixture(scope="module")
def alerts() -> list[dict[str, Any]]:
    loaded: dict[str, Any] = yaml.safe_load(text(ALERTS))
    return [rule | {"group": g["name"]} for g in loaded["groups"] for rule in g["rules"]]


def test_alert_rules_are_well_formed(alerts: list[dict[str, Any]]) -> None:
    assert {a["group"] for a in alerts} == {"k8s-ai-control-plane", "k8s-ai-scaling"}
    names = [a["alert"] for a in alerts]
    assert len(names) == len(set(names))
    runbook_anchors = anchors(text(RUNBOOK))
    prefix = "https://github.com/mikeZ98/cloud-native-k8s-ai/blob/main/docs/runbook.md#"
    for alert in alerts:
        assert alert["labels"]["severity"] in {"warning", "critical"}
        assert re.fullmatch(r"\d+m", alert["for"])
        assert alert["annotations"]["summary"]
        url = alert["annotations"]["runbook_url"]
        assert url.startswith(prefix)
        assert url.removeprefix(prefix) in runbook_anchors, url


def test_alert_expressions_use_known_metrics(alerts: list[dict[str, Any]]) -> None:
    own = _metric_names()
    for alert in alerts:
        identifiers = set(re.findall(r"\b([a-z][a-z0-9_]*)(?=\s*[{\[(])", alert["expr"]))
        functions = {"sum", "rate", "increase", "histogram_quantile", "absent", "max", "by", "on"}
        metrics = identifiers - functions
        if alert["group"] == "k8s-ai-control-plane":
            assert metrics <= own, (alert["alert"], metrics - own)
        else:
            assert all(m.startswith(("kube_", "redis_", "keda_")) for m in metrics), metrics


def test_runbook_alert_table_matches_the_rules(alerts: list[dict[str, Any]]) -> None:
    rows = markdown_table(text(RUNBOOK), "| Alert | Fires when |")
    assert {r[0].strip("`") for r in rows} == {a["alert"] for a in alerts}


@pytest.mark.parametrize("doc", [ARCHITECTURE, README], ids=lambda p: p.name)
def test_navigation_links_every_document(doc: Path) -> None:
    targets = {Path(t.split("#")[0]).name for t in links(text(doc))}
    expected = {
        "architecture.md",
        "security_model.md",
        "runbook.md",
        "api_reference.md",
        "openapi.json",
        "alerts.yaml",
    }
    assert expected - {"architecture.md"} <= targets | (
        {"architecture.md"} if doc == ARCHITECTURE else set()
    )
    for linked in (RUNBOOK, API_REFERENCE):
        for target in links(text(linked)):
            assert_link_resolves(linked, target)
