"""The ``k8s-ai`` command line, driven in memory through ``cli.main``."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
from typing import Any

import pytest
import yaml

from cloud_native_k8s_ai import cli
from cloud_native_k8s_ai.core import ManifestBundle

ROOT = Path(__file__).resolve().parent.parent
CHART_DIR = ROOT / "deploy" / "helm" / "cloud-native-k8s-ai"


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("K8SAI_"):
            monkeypatch.delenv(key)


def run(*argv: str, stdin: str = "") -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(list(argv), stdin=io.StringIO(stdin), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture(scope="module")
def spec_yaml() -> str:
    code, out, _ = run("spec")
    assert code == cli.EXIT_OK
    return out


def test_spec_prints_the_reference_stack(spec_yaml: str, tmp_path: Path) -> None:
    spec = yaml.safe_load(spec_yaml)
    assert (spec["environment"], spec["namespace"]) == ("dev", "ai-system")
    assert spec["stack"]["app"]["name"] == "inference-api"
    target = tmp_path / "spec.yaml"
    assert run("spec", "--namespace", "team-a", "--environment", "prod", "-o", str(target))[0] == 0
    overridden = yaml.safe_load(target.read_text())
    assert (overridden["namespace"], overridden["environment"]) == ("team-a", "prod")


def test_compile_yaml_json_stdin_and_file(spec_yaml: str, tmp_path: Path) -> None:
    code, out, _ = run("compile", "-", stdin=spec_yaml)
    assert code == 0
    assert len(ManifestBundle.from_yaml(out)) == 15
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(yaml.safe_load(spec_yaml)))
    target = tmp_path / "bundle.json"
    assert run("compile", str(spec_file), "--format", "json", "-o", str(target))[0] == 0
    assert json.loads(target.read_text())["count"] == 15


@pytest.mark.parametrize(
    ("stdin", "message"),
    [
        ("", "exactly one YAML/JSON document, got 0"),
        ("---\na: 1\n---\nb: 2\n", "got 2"),
        ("stack: {}\n", "invalid spec: stack.app: Field required"),
        ("a: &x 1\nb: *x\n", "anchors and aliases"),
        ("- 1\n", "is not a mapping"),
    ],
)
def test_compile_rejects_bad_specs(stdin: str, message: str) -> None:
    code, out, err = run("compile", "-", stdin=stdin)
    assert (code, out) == (cli.EXIT_INVALID, "")
    assert err.startswith("k8s-ai: error: ")
    assert message in err


def test_compile_reports_core_errors(spec_yaml: str) -> None:
    spec: dict[str, Any] = yaml.safe_load(spec_yaml)
    spec["stack"]["autoscaling"] |= {"minReplicas": 5, "maxReplicas": 3}
    code, _, err = run("compile", "-", stdin=yaml.safe_dump(spec))
    assert code == cli.EXIT_INVALID
    assert "exceeds max_replicas" in err


def test_missing_files_are_input_errors() -> None:
    code, _, err = run("compile", "/does/not/exist.yaml")
    assert code == cli.EXIT_INVALID
    assert "cannot read /does/not/exist.yaml" in err


def test_admit_allows_denies_and_remediates(spec_yaml: str, tmp_path: Path) -> None:
    manifests = run("compile", "-", stdin=spec_yaml)[1]
    code, out, _ = run("admit", "-", stdin=manifests)
    assert (code, json.loads(out)["decision"]) == (cli.EXIT_OK, "ALLOW")

    documents = [
        d for d in yaml.safe_load_all(manifests) if d["metadata"]["name"] != "default-deny-all"
    ]
    broken = yaml.safe_dump_all(documents)
    code, out, _ = run("admit", "-", stdin=broken)
    assert (code, json.loads(out)["decision"]) == (cli.EXIT_DENIED, "DENY")

    fixed = tmp_path / "fixed.yaml"
    code, out, _ = run("admit", "-", "--remediate", "-o", str(fixed), stdin=broken)
    assert (code, json.loads(out)["decision"]) == (cli.EXIT_OK, "ALLOW")
    assert "default-deny-all" in fixed.read_text()
    assert run("admit", "-", "--remediate", stdin=broken)[0] == cli.EXIT_OK


def test_admit_with_a_spec_trusts_its_namespaces(spec_yaml: str, tmp_path: Path) -> None:
    spec: dict[str, Any] = yaml.safe_load(spec_yaml)
    spec["stack"]["ingressNamespace"] = "gateway"
    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(yaml.safe_dump(spec))
    manifests = run("compile", str(spec_file))[1]
    assert run("admit", "-", stdin=manifests)[0] == cli.EXIT_DENIED  # generic trust
    assert run("admit", "-", "--spec", str(spec_file), stdin=manifests)[0] == cli.EXIT_OK


def test_chart_lint_and_render(tmp_path: Path) -> None:
    code, out, _ = run("chart", "lint", "--chart", str(CHART_DIR))
    assert (code, out) == (0, "chart lint: ok\n")
    values = tmp_path / "prod.yaml"
    values.write_text("environment: prod\nredis:\n  maxmemory: 4Gi\n")
    code, out, _ = run("chart", "lint", "--values", str(values))
    assert code == cli.EXIT_DENIED
    assert "must stay below the memory limit" in out

    good = tmp_path / "ok.yaml"
    good.write_text("environment: staging\n")
    rendered = tmp_path / "out.yaml"
    args = ("chart", "render", "--values", str(good), "--namespace", "ml", "-o", str(rendered))
    assert run(*args)[0] == 0
    documents = list(yaml.safe_load_all(rendered.read_text()))
    assert {d["metadata"]["namespace"] for d in documents} == {"ml"}
    assert run("chart", "render", "--release", "Bad_Name")[0] == cli.EXIT_INVALID


def test_serve_starts_uvicorn(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: calls.append({"app": app, **kw}))
    assert run("serve", "--port", "9000")[0] == 0
    (call,) = calls
    assert (call["host"], call["port"]) == ("127.0.0.1", 9000)
    assert call["app"].title == "cloud-native-k8s-ai control plane"


def test_usage_errors_and_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as info:
        cli.main([])
    assert info.value.code == 2
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert capsys.readouterr().out.strip() == "k8s-ai 0.1.0"


def test_console_script_is_declared() -> None:
    import tomllib  # noqa: PLC0415

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert pyproject["project"]["scripts"] == {"k8s-ai": "cloud_native_k8s_ai.cli:main"}
