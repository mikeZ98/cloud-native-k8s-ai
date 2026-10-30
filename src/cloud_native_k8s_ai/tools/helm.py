"""Hermetic Helm tooling: load a chart, validate values, render and lint it in memory.

Nothing here runs the ``helm`` binary or talks to a cluster. Templates execute on the
offline Go template engine (``tools.gotemplate``) with Helm's built-in objects. Values are
checked in two layers: ``values.schema.json`` (JSON Schema draft-07, the dialect Helm 3
enforces at install time), then the strict Pydantic contracts the core generator consumes.

``lint_chart`` holds the rendered chart to the same bar as ``core.compile_ai_stack``: every
document must parse into the typed models, carry the Helm release labels, match the core
generator's manifests object for object, and pass the zero-trust topology solver.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Final, Literal

import yaml
from jsonschema import Draft7Validator
from jsonschema.exceptions import SchemaError
from pydantic import Field, StringConstraints, ValidationError

from cloud_native_k8s_ai.core import (
    AIStackGenerator,
    AIStackSpec,
    K8sAiCoreError,
    ManifestBundle,
    ManifestRenderError,
    TopologySolver,
    parse_yaml,
    render_yaml,
)
from cloud_native_k8s_ai.schemas import DNS1123Label, InfraModel, InfraSettings, K8sModel
from cloud_native_k8s_ai.schemas.settings import DEFAULT_NAMESPACE
from cloud_native_k8s_ai.tools.gotemplate import Struct, TemplateSet, helm_numbers

NOTES_TEMPLATE: Final = "templates/NOTES.txt"
HELM_RELEASE_LABELS: Final = (
    "helm.sh/chart",
    "app.kubernetes.io/instance",
    "app.kubernetes.io/managed-by",
    "app.kubernetes.io/version",
)
"""Labels Helm stamps for release tracking; they are the only allowed drift from core."""


class ChartError(ManifestRenderError):
    """The chart is malformed: missing files, invalid metadata or an invalid values schema."""


class ChartValuesError(ChartError):
    """Values break ``values.schema.json`` or the typed contracts; ``problems`` lists each."""

    def __init__(self, problems: Sequence[str]) -> None:
        self.problems: tuple[str, ...] = tuple(problems)
        detail = "".join(f"\n  - {p}" for p in self.problems)
        super().__init__(f"values do not satisfy the chart contract:{detail}")


# ---------------------------------------------------------------------------
# Chart model
# ---------------------------------------------------------------------------
SemVer = Annotated[
    str,
    StringConstraints(
        pattern=(
            r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
            r"(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$"
        )
    ),
]
ReleaseName = Annotated[
    str,
    StringConstraints(
        max_length=53,
        pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
    ),
]


class Maintainer(K8sModel):
    name: str = Field(min_length=1)
    email: str | None = None
    url: str | None = None


class ChartMetadata(K8sModel):
    """``Chart.yaml`` of an application chart (API v2, no sub-chart dependencies)."""

    api_version: Literal["v2"]
    name: DNS1123Label
    version: SemVer
    app_version: str = Field(min_length=1)
    description: str = Field(min_length=1)
    type: Literal["application"] = "application"
    kube_version: str | None = None
    home: str | None = None
    sources: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    maintainers: tuple[Maintainer, ...] = ()
    annotations: dict[str, str] = Field(default_factory=dict)

    @property
    def chart_label(self) -> str:
        """Value of the ``helm.sh/chart`` label."""
        return f"{self.name}-{self.version}".replace("+", "_")[:63].removesuffix("-")

    def to_template(self) -> Struct:
        """``.Chart`` as templates see it: Helm's ``*chart.Metadata`` struct."""
        return Struct(
            "*chart.Metadata",
            {
                "APIVersion": self.api_version,
                "Name": self.name,
                "Version": self.version,
                "AppVersion": self.app_version,
                "Description": self.description,
                "Type": self.type,
                "KubeVersion": self.kube_version or "",
                "Home": self.home or "",
                "Sources": list(self.sources),
                "Keywords": list(self.keywords),
                "Maintainers": [m.to_wire() for m in self.maintainers],
                "Annotations": dict(self.annotations),
                "Icon": "",
                "Deprecated": False,
            },
        )


class Release(InfraModel):
    """The release a chart is rendered for (``helm template <name> --namespace <ns>``)."""

    name: ReleaseName = "ai"
    namespace: DNS1123Label = DEFAULT_NAMESPACE
    revision: int = Field(default=1, ge=1)
    is_upgrade: bool = False

    def to_template(self) -> dict[str, Any]:
        """``.Release`` as templates see it."""
        return {
            "Name": self.name,
            "Namespace": self.namespace,
            "Revision": self.revision,
            "Service": "Helm",
            "IsInstall": not self.is_upgrade,
            "IsUpgrade": self.is_upgrade,
        }


@dataclass(frozen=True, slots=True)
class Chart:
    """A chart loaded into memory: metadata, default values, values schema and templates."""

    metadata: ChartMetadata
    values: Mapping[str, Any]
    schema: Mapping[str, Any] | None
    templates: Mapping[str, str]

    @classmethod
    def load(cls, root: Path) -> Chart:
        """Read a chart directory; only ``Chart.yaml``, values files and templates matter."""
        if not (root / "Chart.yaml").is_file():
            raise ChartError(f"{root}: Chart.yaml not found")
        files = {
            path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }
        return cls.from_files(files)

    @classmethod
    def from_files(cls, files: Mapping[str, str]) -> Chart:
        """Build a chart from ``{relative path: text}``, e.g. an in-memory test fixture."""
        if "Chart.yaml" not in files:
            raise ChartError("Chart.yaml not found")
        try:
            metadata = ChartMetadata.from_wire(_yaml_mapping(files["Chart.yaml"], "Chart.yaml"))
        except ValidationError as exc:
            raise ChartError(f"Chart.yaml: {'; '.join(_problems(exc))}") from exc
        values = _yaml_mapping(files.get("values.yaml", ""), "values.yaml")
        schema = None
        if (text := files.get("values.schema.json")) is not None:
            try:
                schema = json.loads(text)
                Draft7Validator.check_schema(schema)
            except json.JSONDecodeError as exc:
                raise ChartError(f"values.schema.json: {exc}") from exc
            except SchemaError as exc:
                raise ChartError(f"values.schema.json: invalid schema: {exc.message}") from exc
        templates = {name: text for name, text in files.items() if name.startswith("templates/")}
        return cls(metadata, values, schema, templates)

    def schema_problems(self, values: Mapping[str, Any]) -> list[str]:
        """Every ``values.schema.json`` violation, as ``<path>: <message>``."""
        if self.schema is None:
            return []
        errors = Draft7Validator(self.schema).iter_errors(values)
        return sorted(f"{_json_path(e.absolute_path)}: {e.message}" for e in errors)


def _yaml_mapping(text: str, what: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ChartError(f"{what}: invalid YAML: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ChartError(f"{what}: top level must be a mapping")
    return data


def _json_path(path: Sequence[Any]) -> str:
    text = "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in path)
    return text.removeprefix(".") or "<root>"


def _problems(exc: ValidationError) -> list[str]:
    return [f"{_json_path(e['loc'])}: {e['msg']}" for e in exc.errors()]


def merge_values(base: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    """Helm's value coalescing: maps merge recursively, ``null`` deletes, the rest replaces."""
    merged = copy.deepcopy(dict(base))
    for key, value in overlay.items():
        current = merged.get(key)
        if value is None:
            merged.pop(key, None)
        elif isinstance(value, Mapping) and isinstance(current, Mapping):
            merged[key] = merge_values(current, value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class RenderedChart:
    """Output of one render: manifest text per template, plus the rendered NOTES.txt."""

    release: Release
    values: Mapping[str, Any]
    manifests: Mapping[str, str]
    notes: str

    def documents(self) -> list[dict[str, Any]]:
        """Every non-empty YAML document, in template order."""
        documents: list[dict[str, Any]] = []
        for name, text in self.manifests.items():
            try:
                documents.extend(parse_yaml(text))
            except ManifestRenderError as exc:
                raise ManifestRenderError(f"{name}: {exc}") from exc
        return documents

    def to_yaml(self) -> str:
        """Canonical multi-document YAML (the ``helm template`` output, normalized)."""
        return render_yaml(self.documents())

    def bundle(self) -> ManifestBundle:
        """The rendered objects parsed into the typed, validated models."""
        return ManifestBundle.from_yaml(self.to_yaml())


def render_chart(
    chart: Chart,
    overlay: Mapping[str, Any] | None = None,
    release: Release | None = None,
    *,
    strict: bool = False,
) -> RenderedChart:
    """``helm template`` in memory: merge ``overlay`` over the defaults, check the values
    schema, then execute every template except partials (``_*``). ``strict`` turns a
    missing map key into an error, like ``helm lint --strict``."""
    release = release or Release()
    values = merge_values(chart.values, overlay or {})
    if problems := chart.schema_problems(values):
        raise ChartValuesError(problems)
    templates = TemplateSet(chart.templates, strict=strict)
    top = {
        "Values": helm_numbers(values),
        "Release": release.to_template(),
        "Chart": chart.metadata.to_template(),
    }
    manifests: dict[str, str] = {}
    notes = ""
    for name in sorted(chart.templates):
        if PurePosixPath(name).name.startswith("_"):
            continue
        context = {
            **top,
            "Template": {
                "Name": f"{chart.metadata.name}/{name}",
                "BasePath": f"{chart.metadata.name}/templates",
            },
        }
        text = templates.execute(name, context)
        if name == NOTES_TEMPLATE:
            notes = text
        else:
            manifests[name] = text
    return RenderedChart(release, values, manifests, notes)


# ---------------------------------------------------------------------------
# Values -> typed core inputs
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ChartStack:
    """The typed core generator inputs a set of chart values stands for."""

    settings: InfraSettings
    spec: AIStackSpec
    autoscaling: bool

    @property
    def generator(self) -> AIStackGenerator:
        return AIStackGenerator(self.settings, self.spec)

    def expected(self) -> ManifestBundle:
        """What the core generator emits for these values: the chart must render exactly this."""
        generator = self.generator
        return generator.build() if self.autoscaling else generator.workloads_bundle()


def validate_values(
    chart: Chart, values: Mapping[str, Any], release: Release | None = None
) -> ChartStack:
    """Check fully merged values against the schema, then the strict typed contracts."""
    if chart.schema is None:
        raise ChartError("chart has no values.schema.json")
    if problems := chart.schema_problems(values):
        raise ChartValuesError(problems)
    release = release or Release()
    try:
        stack = ChartStack(
            settings=InfraSettings(environment=values["environment"], namespace=release.namespace),
            spec=AIStackSpec.from_wire(_stack_wire(values)),
            autoscaling=values["autoscaling"]["enabled"],
        )
        stack.expected()
    except ValidationError as exc:
        raise ChartValuesError(_problems(exc)) from exc
    except K8sAiCoreError as exc:
        raise ChartValuesError([str(exc)]) from exc
    return stack


def _image(image: Mapping[str, str]) -> str:
    reference = f"{image['repository']}:{image['tag']}"
    return f"{reference}@{image['digest']}" if "digest" in image else reference


def _volume(volume: Mapping[str, str]) -> dict[str, Any]:
    wire = {"size": volume["size"], "mountPath": volume["mountPath"]}
    return wire | ({"storageClassName": c} if (c := volume["storageClassName"]) else {})


def _stack_wire(values: Mapping[str, Any]) -> dict[str, Any]:
    api, qdrant, redis = values["api"], values["qdrant"], values["redis"]
    scaling, policy = values["autoscaling"], values["networkPolicy"]
    persistence = redis["persistence"]
    return {
        "app": {
            "name": api["name"],
            "image": _image(api["image"]),
            "replicas": api["replicas"],
            "containerPort": api["containerPort"],
            "servicePort": api["service"]["port"],
            "resources": api["resources"],
            "livenessPath": api["probes"]["livenessPath"],
            "readinessPath": api["probes"]["readinessPath"],
            "env": api["env"],
            "labels": api["labels"],
        },
        "qdrant": {
            "name": qdrant["name"],
            "image": _image(qdrant["image"]),
            "restPort": qdrant["ports"]["rest"],
            "grpcPort": qdrant["ports"]["grpc"],
            "resources": qdrant["resources"],
            "storage": _volume(qdrant["persistence"]["storage"]),
            "snapshots": _volume(qdrant["persistence"]["snapshots"]),
            "labels": qdrant["labels"],
        },
        "redis": {
            "name": redis["name"],
            "image": _image(redis["image"]),
            "port": redis["port"],
            "resources": redis["resources"],
            "maxmemory": redis["maxmemory"],
            "maxmemoryPolicy": redis["maxmemoryPolicy"],
            "dataMountPath": redis["dataMountPath"],
            "persistence": {
                "mode": persistence["mode"],
                "appendfsync": persistence["appendfsync"],
                "savePoints": persistence["savePoints"],
                "volumeSize": None if persistence["mode"] == "none" else persistence["size"],
                **(
                    {"storageClassName": c}
                    if (c := persistence["storageClassName"]) and persistence["mode"] != "none"
                    else {}
                ),
            },
            "labels": redis["labels"],
        },
        "autoscaling": {
            "listName": scaling["listName"],
            "listLength": scaling["listLength"],
            "activationListLength": scaling["activationListLength"],
            "minReplicas": scaling["minReplicas"],
            "maxReplicas": scaling["maxReplicas"],
            "cooldownPeriod": scaling["cooldownPeriod"],
            "pollingInterval": scaling["pollingInterval"],
            "databaseIndex": scaling["databaseIndex"],
            "enableTls": scaling["enableTLS"],
            **{
                key: scaling[key] for key in ("idleReplicas", "authenticationRef") if key in scaling
            },
        },
        "ingressNamespace": policy["ingressController"]["namespace"],
        "kedaNamespace": policy["kedaOperator"]["namespace"],
        "kedaOperatorLabels": policy["kedaOperator"]["podLabels"],
    }


# ---------------------------------------------------------------------------
# Comparison and lint
# ---------------------------------------------------------------------------
def document_key(document: Mapping[str, Any]) -> str:
    metadata = document.get("metadata") or {}
    return f"{document.get('kind')} {metadata.get('namespace')}/{metadata.get('name')}"


def without_release_labels(value: Any) -> Any:
    """Drop the Helm release labels from every ``labels`` map (and empty label maps)."""
    if isinstance(value, list):
        return [without_release_labels(v) for v in value]
    if not isinstance(value, dict):
        return value
    out: dict[str, Any] = {}
    for key, item in value.items():
        if key == "labels" and isinstance(item, dict):
            item = {k: v for k, v in item.items() if k not in HELM_RELEASE_LABELS}  # noqa: PLW2901
            if not item:
                continue
        out[key] = without_release_labels(item)
    return out


def _diff(expected: Any, actual: Any, path: str) -> Iterator[str]:
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key in sorted(expected.keys() | actual.keys()):
            sub = f"{path}.{key}" if path else key
            if key not in actual:
                yield f"{sub}: missing, expected {expected[key]!r}"
            elif key not in expected:
                yield f"{sub}: unexpected {actual[key]!r}"
            else:
                yield from _diff(expected[key], actual[key], sub)
    elif isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            yield f"{path}: expected {len(expected)} items, got {len(actual)}"
            return
        for index, (e, a) in enumerate(zip(expected, actual, strict=True)):
            yield from _diff(e, a, f"{path}[{index}]")
    elif type(expected) is not type(actual) or expected != actual:
        yield f"{path}: expected {expected!r}, got {actual!r}"


def diff_manifests(
    expected: Sequence[Mapping[str, Any]], actual: Sequence[Mapping[str, Any]]
) -> list[str]:
    """Field-level differences between two manifest sets, matched by kind/namespace/name.

    Release labels are ignored; everything else, including scalar types (``6333`` vs
    ``"6333"``) and list order, must match exactly.
    """
    want = {document_key(d): without_release_labels(d) for d in expected}
    have: dict[str, Any] = {}
    problems: list[str] = []
    for document in actual:
        key = document_key(document)
        if key in have:
            problems.append(f"{key}: rendered more than once")
        have[key] = without_release_labels(document)
    problems += [f"{key}: missing" for key in sorted(want.keys() - have.keys())]
    problems += [
        f"{key}: not produced by the core generator" for key in sorted(have.keys() - want.keys())
    ]
    for key in sorted(want.keys() & have.keys()):
        problems += [f"{key}: {p}" for p in _diff(want[key], have[key], "")]
    return problems


def release_label_problems(chart: Chart, rendered: RenderedChart) -> list[str]:
    """Every object must carry Helm's release labels with the release's values."""
    want = {
        "helm.sh/chart": chart.metadata.chart_label,
        "app.kubernetes.io/instance": rendered.release.name,
        "app.kubernetes.io/managed-by": "Helm",
        "app.kubernetes.io/version": chart.metadata.app_version,
    }
    problems: list[str] = []
    for document in rendered.documents():
        labels = (document.get("metadata") or {}).get("labels") or {}
        problems += [
            f"{document_key(document)}: label {key}={labels.get(key)!r}, expected {value!r}"
            for key, value in want.items()
            if labels.get(key) != value
        ]
    return problems


_PARTIAL_SCHEMA_KEYWORDS: Final = frozenset({"if", "then", "else", "not"})


def open_schema_objects(schema: Any, pointer: str = "#", *, partial: bool = False) -> list[str]:
    """Object schemas that declare ``properties`` but accept unknown keys.

    Subschemas under ``if``/``then``/``else``/``not`` only add constraints to their parent
    object and are exempt.
    """
    found: list[str] = []
    if isinstance(schema, dict):
        if (
            not partial
            and "properties" in schema
            and schema.get("additionalProperties") is not False
        ):
            found.append(f"{pointer}: object with properties must set additionalProperties: false")
        for key, sub in schema.items():
            found += open_schema_objects(
                sub, f"{pointer}/{key}", partial=key in _PARTIAL_SCHEMA_KEYWORDS
            )
    elif isinstance(schema, list):
        for index, sub in enumerate(schema):
            found += open_schema_objects(sub, f"{pointer}/{index}", partial=partial)
    return found


@dataclass(frozen=True, slots=True)
class LintReport:
    findings: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.findings

    def raise_for_findings(self) -> None:
        if self.findings:
            detail = "".join(f"\n  - {f}" for f in self.findings)
            raise ChartError(f"chart lint failed:{detail}")


def lint_chart(
    chart: Chart,
    overlays: Mapping[str, Mapping[str, Any]] | None = None,
    release: Release | None = None,
) -> LintReport:
    """Lint the chart for its default values and every named overlay.

    Per values set: schema and typed-contract validation, a strict render, typed parsing
    of every document, Helm release labels, object-for-object equality with the core
    generator, and the zero-trust topology solver.
    """
    if chart.schema is None:
        return LintReport(("values.schema.json: missing",))
    findings = [f"values.schema.json: {p}" for p in open_schema_objects(chart.schema)]
    for label, overlay in {"defaults": {}, **(overlays or {})}.items():
        findings += [f"[{label}] {p}" for p in _lint_values(chart, overlay, release)]
    return LintReport(tuple(findings))


def _lint_values(chart: Chart, overlay: Mapping[str, Any], release: Release | None) -> list[str]:
    try:
        stack = validate_values(chart, merge_values(chart.values, overlay), release)
        rendered = render_chart(chart, overlay, release, strict=True)
        bundle = rendered.bundle()
        generator = stack.generator
        report = TopologySolver(generator.topology(bundle)).verify(generator.intent())
    except K8sAiCoreError as exc:
        return [str(exc)]
    return [
        *diff_manifests(stack.expected().to_documents(), rendered.documents()),
        *release_label_problems(chart, rendered),
        *(str(v) for v in report.violations),
    ]
