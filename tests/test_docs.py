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
def test_readme_links_resolve() -> None:
    for target in re.findall(r"\]\(([^)]+)\)", text(README)):
        if target.startswith(("http://", "https://")):
            continue
        path = target.split("#")[0]
        assert (ROOT / path).exists(), target
    for doc in (ARCHITECTURE, SECURITY):
        for target in re.findall(r"\]\(([^)#][^)]*)\)", text(doc)):
            if not target.startswith("http"):
                assert (doc.parent / target.split("#")[0]).exists(), target


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
