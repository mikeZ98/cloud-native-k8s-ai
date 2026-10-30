"""``k8s-ai``: compile, admit and render the AI stack from the command line, offline.

Commands (``-`` reads stdin; results go to stdout unless ``-o`` is given):

* ``spec``            print the reference stack spec (the chart's default values)
* ``compile SPEC``    spec (YAML/JSON) -> zero-trust manifests (YAML, or ``--format json``)
* ``admit FILE``      run the admission guardrails; ``--remediate`` runs the critic loop
* ``chart lint``      lint the Helm chart for its defaults and ``--values`` overlays
* ``chart render``    render the chart offline (``helm template`` equivalent)
* ``eval``            perturbation benchmark: guardrail precision/recall, remediation, robustness
* ``serve``           run the FastAPI control plane with uvicorn

Exit codes: 0 allowed (ALLOW/WARN, lint clean, eval thresholds met), 1 denied, lint findings
or eval thresholds missed, 2 invalid input.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

import yaml
from pydantic import ValidationError

from cloud_native_k8s_ai import __version__
from cloud_native_k8s_ai.api.config import DEFAULT_CHART_DIR, ApiSettings
from cloud_native_k8s_ai.api.models import CompileResponse, InfraSpec
from cloud_native_k8s_ai.core import K8sAiCoreError, compile_ai_stack, parse_untrusted_yaml
from cloud_native_k8s_ai.evals import EvalConfig, EvalError, Evaluator
from cloud_native_k8s_ai.guardrails import AdmissionEngine, GuardrailDecision
from cloud_native_k8s_ai.tools.helm import (
    Chart,
    Release,
    lint_chart,
    merge_values,
    render_chart,
    validate_values,
)

EXIT_OK, EXIT_DENIED, EXIT_INVALID = 0, 1, 2


class CliError(Exception):
    """Invalid input: reported on stderr with exit code 2."""


class _Io:
    def __init__(self, stdin: TextIO, stdout: TextIO) -> None:
        self.stdin, self.stdout = stdin, stdout

    def read(self, source: str) -> str:
        if source == "-":
            return self.stdin.read()
        try:
            return Path(source).read_text(encoding="utf-8")
        except OSError as exc:
            raise CliError(f"cannot read {source}: {exc.strerror}") from exc

    def write(self, text: str, target: str | None) -> None:
        text = text if text.endswith("\n") else f"{text}\n"
        if target is None:
            self.stdout.write(text)
        else:
            Path(target).write_text(text, encoding="utf-8")


def _single_document(text: str, what: str) -> dict[str, Any]:
    documents = parse_untrusted_yaml(text)
    if len(documents) != 1:
        raise CliError(f"{what} must contain exactly one YAML/JSON document, got {len(documents)}")
    return documents[0]


def _spec(io: _Io, source: str) -> InfraSpec:
    try:
        return InfraSpec.from_wire(_single_document(io.read(source), "spec"))
    except ValidationError as exc:
        problems = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
        raise CliError(f"invalid spec: {problems}") from exc


def _reference(chart_dir: Path) -> InfraSpec:
    chart = Chart.load(chart_dir)
    stack = validate_values(chart, chart.values)
    return InfraSpec(
        environment=stack.settings.environment,
        namespace=stack.settings.namespace,
        stack=stack.spec,
    )


def _overlays(io: _Io, paths: Sequence[str]) -> dict[str, dict[str, Any]]:
    return {path: _single_document(io.read(path), f"values file {path}") for path in paths}


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def _cmd_spec(args: argparse.Namespace, io: _Io) -> int:
    spec = _reference(args.chart)
    overrides = {
        k: v for k, v in (("namespace", args.namespace), ("environment", args.environment)) if v
    }
    spec = InfraSpec.from_wire(spec.to_wire() | overrides)
    io.write(yaml.safe_dump(spec.to_wire(), sort_keys=False), args.output)
    return EXIT_OK


def _cmd_compile(args: argparse.Namespace, io: _Io) -> int:
    spec = _spec(io, args.spec)
    bundle = compile_ai_stack(spec.settings(), spec.stack)
    if args.format == "json":
        body = json.dumps(CompileResponse.from_bundle(spec, bundle).to_wire(), indent=2)
    else:
        body = bundle.to_yaml()
    io.write(body, args.output)
    return EXIT_OK


def _cmd_admit(args: argparse.Namespace, io: _Io) -> int:
    manifests = io.read(args.manifests)
    engine = AdmissionEngine()
    if args.spec is not None:
        spec = _spec(io, args.spec)
        engine = AdmissionEngine.for_stack(spec.settings(), spec.stack)
    if args.remediate:
        result = engine.remediate(manifests)
        report = result.final
        if args.output is not None:
            io.write(result.to_yaml(), args.output)
    else:
        report = engine.evaluate(manifests)
    io.write(json.dumps(report.to_wire(), indent=2), None)
    return EXIT_OK if report.decision is not GuardrailDecision.DENY else EXIT_DENIED


def _cmd_chart_lint(args: argparse.Namespace, io: _Io) -> int:
    release = Release(name=args.release, namespace=args.namespace)
    report = lint_chart(Chart.load(args.chart), _overlays(io, args.values), release)
    io.write("\n".join(report.findings) or "chart lint: ok", None)
    return EXIT_OK if report.ok else EXIT_DENIED


def _cmd_chart_render(args: argparse.Namespace, io: _Io) -> int:
    chart = Chart.load(args.chart)
    overlay: dict[str, Any] = {}
    for values in _overlays(io, args.values).values():
        overlay = merge_values(overlay, values)
    release = Release(name=args.release, namespace=args.namespace)
    io.write(render_chart(chart, overlay, release, strict=True).to_yaml(), args.output)
    return EXIT_OK


def _thresholds(entries: Sequence[str]) -> dict[str, float]:
    thresholds: dict[str, float] = {}
    for entry in entries:
        name, separator, value = entry.partition("=")
        try:
            thresholds[name.strip()] = float(value)
        except ValueError:
            separator = ""
        if not separator or not name.strip():
            raise CliError(f"--min expects METRIC=VALUE, got {entry!r}")
    return thresholds


def _cmd_eval(args: argparse.Namespace, io: _Io) -> int:
    spec = _spec(io, args.spec) if args.spec else _reference(args.chart)
    thresholds = _thresholds(args.min)
    config = EvalConfig(
        seed=args.seed,
        samples=args.samples,
        spec_samples=args.spec_samples,
        epsilon=args.epsilon,
        benign_ratio=args.benign_ratio,
        remediate=not args.no_remediate,
    )
    report = Evaluator(spec.settings(), spec.stack).run(config)
    try:
        unmet = report.unmet(thresholds)
    except KeyError as exc:
        raise CliError(str(exc.args[0])) from exc
    body = report.to_text() if args.format == "text" else json.dumps(report.to_wire(), indent=2)
    io.write(body, args.output)
    for line in unmet:
        io.write(f"threshold missed: {line}", None)
    return EXIT_DENIED if unmet else EXIT_OK


def _cmd_serve(args: argparse.Namespace, io: _Io) -> int:  # noqa: ARG001 - uniform signature
    import uvicorn  # noqa: PLC0415 - only the server needs it

    from cloud_native_k8s_ai.api import create_app  # noqa: PLC0415

    uvicorn.run(create_app(ApiSettings(chart_dir=args.chart)), host=args.host, port=args.port)
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="k8s-ai",
        description="Compile, admit and render zero-trust AI stack manifests, offline.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    def add(name: str, handler: Any, text: str, *, chart: bool = True) -> argparse.ArgumentParser:
        command = commands.add_parser(name, help=text, description=text)
        command.set_defaults(handler=handler)
        if chart:
            command.add_argument(
                "--chart", type=Path, default=DEFAULT_CHART_DIR, help="chart directory"
            )
        return command

    spec = add("spec", _cmd_spec, "print the reference stack spec (chart defaults)")
    spec.add_argument("--namespace")
    spec.add_argument("--environment", choices=("dev", "staging", "prod"))
    spec.add_argument("-o", "--output")

    compile_ = add("compile", _cmd_compile, "compile a stack spec into manifests", chart=False)
    compile_.add_argument("spec", help="InfraSpec file (YAML or JSON), or - for stdin")
    compile_.add_argument("--format", choices=("yaml", "json"), default="yaml")
    compile_.add_argument("-o", "--output")

    admit = add("admit", _cmd_admit, "run the admission guardrails on manifests", chart=False)
    admit.add_argument("manifests", help="multi-document manifest YAML, or - for stdin")
    admit.add_argument("--spec", help="trust this stack's namespaces and selectors")
    admit.add_argument("--remediate", action="store_true", help="run the critic loop first")
    admit.add_argument("-o", "--output", help="write remediated manifests here")

    chart = commands.add_parser("chart", help="lint or render the Helm chart offline")
    chart_commands = chart.add_subparsers(dest="chart_command", required=True)
    for name, handler, text in (
        ("lint", _cmd_chart_lint, "lint the chart (schema, contracts, parity, zero trust)"),
        ("render", _cmd_chart_render, "render the chart like helm template"),
    ):
        command = chart_commands.add_parser(name, help=text, description=text)
        command.set_defaults(handler=handler)
        command.add_argument("--chart", type=Path, default=DEFAULT_CHART_DIR)
        command.add_argument("--values", action="append", default=[], help="values overlay file")
        command.add_argument("--release", default="ai")
        command.add_argument("--namespace", default="ai-system")
        if name == "render":
            command.add_argument("-o", "--output")

    evaluate = add("eval", _cmd_eval, "benchmark the guardrails against seeded perturbations")
    evaluate.add_argument("--spec", help="stack spec to evaluate (default: chart reference)")
    evaluate.add_argument("--seed", type=int, default=0)
    evaluate.add_argument("--samples", type=int, default=200)
    evaluate.add_argument("--spec-samples", type=int, default=50)
    evaluate.add_argument("--epsilon", type=float, default=0.3, help="perturbation budget 0..1")
    evaluate.add_argument("--benign-ratio", type=float, default=0.25)
    evaluate.add_argument("--no-remediate", action="store_true", help="skip the critic loop")
    evaluate.add_argument("--format", choices=("text", "json"), default="text")
    evaluate.add_argument(
        "--min", action="append", default=[], metavar="METRIC=VALUE", help="quality gate"
    )
    evaluate.add_argument("-o", "--output")

    serve = add("serve", _cmd_serve, "run the control plane (uvicorn)")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    io = _Io(stdin or sys.stdin, stdout or sys.stdout)
    try:
        result: int = args.handler(args, io)
    except (CliError, K8sAiCoreError, ValidationError, EvalError) as exc:
        (stderr or sys.stderr).write(f"k8s-ai: error: {exc}\n")
        return EXIT_INVALID
    return result
