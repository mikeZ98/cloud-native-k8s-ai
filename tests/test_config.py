"""Phase 1 verification: repository configuration, strict tooling, attribution policy and
hermetic test isolation.

Pure file inspection plus in-process checks: no subprocesses, no network, no git invocation,
no Kubernetes cluster or cloud API.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import tomllib
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
import yaml
from pytest_socket import SocketBlockedError
from yamllint import linter
from yamllint.config import YamlLintConfig

import cloud_native_k8s_ai

ROOT = Path(__file__).resolve().parent.parent
ALLOWED_NAME = "mikeZ98"
ALLOWED_EMAIL = "145975972+mikeZ98@users.noreply.github.com"

CORE_DEPENDENCIES = {
    "fastapi",
    "uvicorn",
    "pydantic",
    "pydantic-settings",
    "pyyaml",
    "httpx",
    "prometheus-client",
}
DEV_DEPENDENCIES = {
    "pytest",
    "pytest-asyncio",
    "pytest-cov",
    "pytest-socket",
    "ruff",
    "mypy",
    "bandit",
    "yamllint",
}
EXECUTABLES = (
    "scripts/audit-attribution.sh",
    ".githooks/pre-commit",
    ".githooks/commit-msg",
    ".githooks/pre-push",
)
# Directories never scanned for YAML (caches, venv, VCS metadata).
SKIP_DIRS = {".cache", ".git", ".venv", ".terraform", "__pycache__"}
# TEST-NET-1 (RFC 5737): never routable, so nothing could leave even if the guard failed.
UNROUTABLE_HOST = "192.0.2.1"


def _requirement_name(spec: str) -> str:
    match = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", spec)
    assert match is not None, spec
    return match.group(0).lower().replace("_", "-")


def _shell_constant(text: str, name: str) -> str:
    match = re.search(rf"^readonly {name}='(.*)'$", text, re.MULTILINE)
    assert match is not None, f"{name} not defined in _policy.sh"
    return match.group(1)


def _repo_yaml_files() -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in ROOT.walk():
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        found.extend(dirpath / f for f in filenames if f.endswith((".yaml", ".yml")))
    return sorted(found)


@pytest.fixture(scope="module")
def pyproject() -> dict[str, Any]:
    with (ROOT / "pyproject.toml").open("rb") as fh:
        return tomllib.load(fh)


@pytest.fixture(scope="module")
def tool(pyproject: dict[str, Any]) -> dict[str, Any]:
    section: dict[str, Any] = pyproject["tool"]
    return section


@pytest.fixture(scope="module")
def policy() -> str:
    return (ROOT / ".githooks" / "_policy.sh").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def yamllint_config() -> YamlLintConfig:
    return YamlLintConfig(file=str(ROOT / ".yamllint.yaml"))


# ---------------------------------------------------------------------------
# Required files
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "relpath",
    [
        "pyproject.toml",
        "uv.lock",
        ".python-version",
        ".gitignore",
        ".editorconfig",
        ".envrc",
        ".yamllint.yaml",
        ".claude/settings.json",
        ".githooks/_policy.sh",
        "CLAUDE.md",
        "CONTRIBUTING.md",
        "README.md",
        "LICENSE",
        "src/cloud_native_k8s_ai/__init__.py",
        "src/cloud_native_k8s_ai/py.typed",
        *EXECUTABLES,
    ],
)
def test_required_file_present(relpath: str) -> None:
    assert (ROOT / relpath).is_file(), f"missing {relpath}"


@pytest.mark.parametrize("relpath", EXECUTABLES)
def test_scripts_are_executable_bash(relpath: str) -> None:
    path = ROOT / relpath
    assert os.access(path, os.X_OK), f"{relpath} is not executable"
    text = path.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "set -euo pipefail" in text


# ---------------------------------------------------------------------------
# Project metadata & dependencies
# ---------------------------------------------------------------------------
def test_python_312_plus(pyproject: dict[str, Any]) -> None:
    assert pyproject["project"]["requires-python"].startswith(">=3.12")
    assert (ROOT / ".python-version").read_text(encoding="utf-8").strip() == "3.12"


def test_sole_author_metadata(pyproject: dict[str, Any]) -> None:
    assert pyproject["project"]["authors"] == [{"name": ALLOWED_NAME, "email": ALLOWED_EMAIL}]


def test_core_dependencies(pyproject: dict[str, Any]) -> None:
    declared = {_requirement_name(d) for d in pyproject["project"]["dependencies"]}
    assert declared >= CORE_DEPENDENCIES


def test_dev_dependencies(pyproject: dict[str, Any]) -> None:
    declared = {_requirement_name(d) for d in pyproject["dependency-groups"]["dev"]}
    assert declared >= DEV_DEPENDENCIES


def test_every_dependency_is_locked(pyproject: dict[str, Any]) -> None:
    with (ROOT / "uv.lock").open("rb") as fh:
        lock = tomllib.load(fh)
    locked = {pkg["name"] for pkg in lock["package"] if "version" in pkg}
    declared = {
        _requirement_name(d)
        for d in [*pyproject["project"]["dependencies"], *pyproject["dependency-groups"]["dev"]]
    }
    assert declared <= locked, f"unlocked: {sorted(declared - locked)}"


def test_package_version_matches_metadata(pyproject: dict[str, Any]) -> None:
    assert cloud_native_k8s_ai.__version__ == pyproject["project"]["version"]


# ---------------------------------------------------------------------------
# Tooling strictness
# ---------------------------------------------------------------------------
def test_mypy_strict(tool: dict[str, Any]) -> None:
    mypy = tool["mypy"]
    assert mypy["strict"] is True
    assert mypy["python_version"] == "3.12"
    assert "pydantic.mypy" in mypy["plugins"]
    assert mypy["warn_unreachable"] is True
    assert set(mypy["files"]) == {"src", "tests"}


def test_ruff_linter_and_formatter(tool: dict[str, Any]) -> None:
    ruff = tool["ruff"]
    assert ruff["target-version"] == "py312"
    assert {"E", "F", "I", "B", "S", "UP", "ASYNC", "RUF"} <= set(ruff["lint"]["select"])
    assert "format" in ruff


def test_pytest_hermetic_and_strict(tool: dict[str, Any]) -> None:
    ini = tool["pytest"]["ini_options"]
    addopts = set(ini["addopts"])
    assert {"--strict-markers", "--strict-config", "--disable-socket", "--cov-branch"} <= addopts
    assert not any(opt.startswith("--allow-hosts") for opt in addopts)
    assert ini["asyncio_mode"] == "auto"
    assert ini["filterwarnings"][0] == "error"


def test_coverage_threshold(tool: dict[str, Any]) -> None:
    assert tool["coverage"]["run"]["branch"] is True
    assert tool["coverage"]["report"]["fail_under"] >= 90


def test_bandit_scans_src(tool: dict[str, Any]) -> None:
    assert tool["bandit"]["targets"] == ["src"]


def test_caches_pinned_inside_repo(tool: dict[str, Any]) -> None:
    assert tool["ruff"]["cache-dir"].startswith(".cache/")
    assert tool["mypy"]["cache_dir"].startswith(".cache/")
    assert tool["pytest"]["ini_options"]["cache_dir"].startswith(".cache/")
    assert tool["coverage"]["run"]["data_file"].startswith(".cache/")


def test_gitignore_blocks_caches_secrets_and_iac_state() -> None:
    lines = set((ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())
    assert {".cache/", ".venv/", ".env", "__pycache__/"} <= lines
    assert {".terraform/", "*.tfstate", "*.tfstate.*", "*.tfvars", "kubeconfig*"} <= lines
    assert ".terraform.lock.hcl" not in lines


# ---------------------------------------------------------------------------
# Kubernetes / IaC linting (yamllint, in-process)
# ---------------------------------------------------------------------------
def test_yamllint_rules_strict() -> None:
    raw = yaml.safe_load((ROOT / ".yamllint.yaml").read_text(encoding="utf-8"))
    assert raw["extends"] == "default"
    rules = raw["rules"]
    assert rules["document-start"] == {"present": True}
    assert rules["indentation"]["spaces"] == 2
    assert rules["truthy"]["allowed-values"] == ["true", "false"]
    assert rules["key-duplicates"] == "enable"
    assert rules["octal-values"]["forbid-implicit-octal"] is True


def test_yamllint_ignores_helm_templates_and_caches(yamllint_config: YamlLintConfig) -> None:
    assert yamllint_config.is_file_ignored("deploy/helm/cloud-native-k8s-ai/templates/svc.yaml")
    assert yamllint_config.is_file_ignored(".cache/venv/lib/x.yaml")
    assert not yamllint_config.is_file_ignored("deploy/helm/cloud-native-k8s-ai/values.yaml")


def test_repo_yaml_lints_clean(yamllint_config: YamlLintConfig) -> None:
    files = _repo_yaml_files()
    assert ROOT / ".yamllint.yaml" in files
    problems: list[str] = []
    for path in files:
        rel = path.relative_to(ROOT).as_posix()
        if yamllint_config.is_file_ignored(rel):
            continue
        problems.extend(
            f"{rel}:{p.line}:{p.column} [{p.level}] {p.message}"
            for p in linter.run(path.read_text(encoding="utf-8"), yamllint_config, rel)
        )
    assert problems == []


@pytest.mark.parametrize(
    ("document", "rule"),
    [
        ("apiVersion: v1\nkind: Pod\n", "document-start"),
        ("---\nmetadata:\n  name: a\n  name: b\n", "key-duplicates"),
        ("---\nspec:\n  hostNetwork: yes\n", "truthy"),
        ("---\nspec:\n    replicas: 2\n", "indentation"),
        ("---\ndata:\n  mode: 0644\n", "octal-values"),
    ],
)
def test_yamllint_rejects_bad_manifests(
    yamllint_config: YamlLintConfig, document: str, rule: str
) -> None:
    found = {p.rule for p in linter.run(document, yamllint_config, "manifest.yaml")}
    assert rule in found


# ---------------------------------------------------------------------------
# Attribution policy & git identity rules
# ---------------------------------------------------------------------------
def test_policy_identity(policy: str) -> None:
    assert f'readonly POLICY_ALLOWED_NAME="{ALLOWED_NAME}"' in policy
    assert f'readonly POLICY_ALLOWED_EMAIL="{ALLOWED_EMAIL}"' in policy


def test_envrc_sets_identity_and_hooks() -> None:
    envrc = (ROOT / ".envrc").read_text(encoding="utf-8")
    assert "config core.hooksPath .githooks" in envrc
    assert f'config user.name "{ALLOWED_NAME}"' in envrc
    assert f'config user.email "{ALLOWED_EMAIL}"' in envrc
    assert "config user.useConfigOnly true" in envrc


def test_envrc_isolates_cluster_and_iac_homes() -> None:
    envrc = (ROOT / ".envrc").read_text(encoding="utf-8")
    for var in ("KUBECONFIG", "KUBECACHEDIR", "HELM_CACHE_HOME", "HELM_CONFIG_HOME"):
        assert re.search(rf'^export {var}="\$CACHE_ROOT/', envrc, re.MULTILINE), var
    assert re.search(r'^export TF_PLUGIN_CACHE_DIR="\$CACHE_ROOT/', envrc, re.MULTILINE)
    assert 'export CHECKPOINT_DISABLE="1"' in envrc


def test_claude_settings_disable_attribution() -> None:
    settings = json.loads((ROOT / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert settings["includeCoAuthoredBy"] is False
    assert settings["attribution"] == {"commit": "", "pr": ""}


def test_audit_script_uses_shared_policy() -> None:
    text = (ROOT / "scripts" / "audit-attribution.sh").read_text(encoding="utf-8")
    assert 'source "$ROOT/.githooks/_policy.sh"' in text
    assert '"${1:-}" == "--history-only"' in text
    for check in ("policy_check_identity", "policy_check_message"):
        assert check in text


def test_pre_commit_guards() -> None:
    text = (ROOT / ".githooks" / "pre-commit").read_text(encoding="utf-8")
    assert "policy_check_identity" in text
    assert "policy_forbidden_paths" in text
    assert "ruff" in text
    assert "yamllint" in text


def test_pre_push_audits_outgoing_commits() -> None:
    text = (ROOT / ".githooks" / "pre-push").read_text(encoding="utf-8")
    assert '"$ROOT/scripts/audit-attribution.sh"' in text


@pytest.mark.parametrize(
    "message",
    [
        "chore: x\n\nCo-authored-by: Someone <a@b.c>",
        "chore: x\n\nGenerated-by: tool",
        "feat: x\n\nGenerated with some assistant",
        "fix: x\n\nAssisted-by: bot",
        "fix: written by Claude",
        "docs: courtesy of ChatGPT",
        "docs: via GitHub Copilot",
        "chore: 🤖 automated",
    ],
)
def test_forbidden_message_rejected(policy: str, message: str) -> None:
    pattern = re.compile(_shell_constant(policy, "POLICY_FORBIDDEN_MSG_RE"), re.IGNORECASE)
    assert pattern.search(message) is not None


@pytest.mark.parametrize(
    "message",
    [
        "chore(config): initialize cloud-native-k8s-ai repository with uv, linters, and "
        "attribution gates",
        "docs: document rules in CLAUDE.md",
        "feat(helm): add qdrant statefulset and keda scaledobject",
    ],
)
def test_clean_message_accepted(policy: str, message: str) -> None:
    pattern = re.compile(_shell_constant(policy, "POLICY_FORBIDDEN_MSG_RE"), re.IGNORECASE)
    assert pattern.search(message.replace("CLAUDE.md", "")) is None


@pytest.mark.parametrize(
    ("subject", "valid"),
    [
        (
            "chore(config): initialize cloud-native-k8s-ai repository with uv, linters, and "
            "attribution gates",
            True,
        ),
        ("feat(k8s)!: break the chart values contract", True),
        ("update stuff", False),
        ("Feat: capitalised type", False),
        ("feat: " + "x" * 120, False),
    ],
)
def test_conventional_subject(policy: str, subject: str, valid: bool) -> None:
    pattern = re.compile(_shell_constant(policy, "POLICY_CONVENTIONAL_RE"))
    assert (pattern.search(subject) is not None) is valid


@pytest.mark.parametrize(
    ("path", "forbidden"),
    [
        (".cache/venv/bin/python", True),
        ("src/pkg/__pycache__/mod.pyc", True),
        (".env", True),
        (".env.production", True),
        (".env.example", False),
        ("tls/server.key", True),
        ("infra/terraform/bootstrap/terraform.tfstate", True),
        ("infra/terraform/bootstrap/terraform.tfstate.backup", True),
        ("infra/terraform/bootstrap/prod.tfvars", True),
        ("infra/terraform/bootstrap/.terraform/providers/x", True),
        ("infra/terraform/bootstrap/.terraform.lock.hcl", False),
        ("infra/terraform/bootstrap/terraform.tfvars.example", False),
        ("kubeconfig", True),
        ("ops/kubeconfig-prod.yaml", True),
        ("ops/staging.kubeconfig", True),
        ("deploy/helm/cloud-native-k8s-ai/values.yaml", False),
        (".envrc", False),
    ],
)
def test_forbidden_paths(policy: str, path: str, forbidden: bool) -> None:
    blocked = re.compile(_shell_constant(policy, "POLICY_FORBIDDEN_PATH_RE"))
    allowed = re.compile(_shell_constant(policy, "POLICY_ALLOWED_PATH_RE"))
    assert (blocked.search(path) is not None and allowed.search(path) is None) is forbidden


# ---------------------------------------------------------------------------
# Hermetic isolation (pytest-socket)
# ---------------------------------------------------------------------------
@contextmanager
def _socket_blocked() -> Iterator[None]:
    # pytest-socket warns, then raises, before any packet could be sent.
    with (
        pytest.warns(UserWarning, match="tried to use socket"),
        pytest.raises(SocketBlockedError),
    ):
        yield


@pytest.mark.parametrize("family", [socket.AF_INET, socket.AF_INET6])
def test_inet_sockets_blocked(family: socket.AddressFamily) -> None:
    with _socket_blocked():
        socket.socket(family, socket.SOCK_STREAM)


def test_outbound_connection_blocked() -> None:
    with _socket_blocked():
        socket.create_connection((UNROUTABLE_HOST, 443), timeout=0.1)


async def test_async_outbound_connection_blocked() -> None:
    with _socket_blocked():
        await asyncio.open_connection(UNROUTABLE_HOST, 443)


def test_unix_socketpair_allowed_for_event_loop() -> None:
    left, right = socket.socketpair()
    with left, right:
        left.sendall(b"ping")
        assert right.recv(4) == b"ping"
