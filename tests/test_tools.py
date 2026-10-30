"""Phase 4 verification: Helm chart, offline Go template engine and chart tooling.

Hermetic: the chart is read from disk and rendered in memory by the Python template
engine; no ``helm`` binary, no subprocess, no cluster, no network. Rendered manifests are
checked structurally, against the typed core generator and with the topology solver.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft7Validator
from yamllint import linter
from yamllint.config import YamlLintConfig

from cloud_native_k8s_ai.core import (
    AIStackGenerator,
    K8sAiCoreError,
    ManifestBundle,
    ManifestRenderError,
    TopologySolver,
)
from cloud_native_k8s_ai.schemas import NetworkPolicy, ScaledObject, StatefulSet
from cloud_native_k8s_ai.tools.gotemplate import (
    MAX_INCLUDE_DEPTH,
    Struct,
    TemplateError,
    TemplateSet,
    format_value,
    go_float,
    go_quote,
    go_type,
    helm_numbers,
    is_true,
)
from cloud_native_k8s_ai.tools.helm import (
    HELM_RELEASE_LABELS,
    Chart,
    ChartError,
    ChartValuesError,
    LintReport,
    Release,
    RenderedChart,
    diff_manifests,
    lint_chart,
    merge_values,
    open_schema_objects,
    release_label_problems,
    render_chart,
    validate_values,
    without_release_labels,
)

ROOT = Path(__file__).resolve().parent.parent
CHART_DIR = ROOT / "deploy" / "helm" / "cloud-native-k8s-ai"
NS = "ai-system"
API, QDRANT, REDIS = "inference-api", "qdrant", "redis"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    import os  # noqa: PLC0415 - only needed to scrub the settings prefix

    for key in list(os.environ):
        if key.startswith("K8SAI_"):
            monkeypatch.delenv(key)


@pytest.fixture(scope="module")
def chart() -> Chart:
    return Chart.load(CHART_DIR)


@pytest.fixture(scope="module")
def chart_files() -> dict[str, str]:
    return {
        p.relative_to(CHART_DIR).as_posix(): p.read_text(encoding="utf-8")
        for p in sorted(CHART_DIR.rglob("*"))
        if p.is_file()
    }


@pytest.fixture(scope="module")
def rendered(chart: Chart) -> RenderedChart:
    return render_chart(chart, strict=True)


@pytest.fixture(scope="module")
def docs(rendered: RenderedChart) -> dict[str, dict[str, Any]]:
    return {f"{d['kind']}/{d['metadata']['name']}": d for d in rendered.documents()}


def render(template: str, data: Any = None, *, strict: bool = False, **extra: str) -> str:
    return TemplateSet({"t": template, **extra}, strict=strict).execute("t", data)


def with_template(files: dict[str, str], name: str, old: str, new: str) -> Chart:
    assert old in files[name], f"{old!r} not in {name}"
    return Chart.from_files({**files, name: files[name].replace(old, new)})


# ---------------------------------------------------------------------------
# Go value semantics
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("value", "text"),
    [
        (6333.0, "6333"),
        (0.5, "0.5"),
        (-2.5, "-2.5"),
        (100.0, "100"),
        (123456.0, "123456"),
        (1e6, "1e+06"),
        (1.5e6, "1.5e+06"),
        (1e21, "1e+21"),
        (0.0001, "0.0001"),
        (1.5e-5, "1.5e-05"),
        (0.0, "0"),
        (math.nan, "NaN"),
        (math.inf, "+Inf"),
        (-math.inf, "-Inf"),
    ],
)
def test_go_float_matches_strconv(value: float, text: str) -> None:
    assert go_float(value) == text


def test_format_value_mirrors_fmt_sprint() -> None:
    struct = Struct("*chart.Metadata", {"Name": "x", "Version": "1.0.0"})
    assert format_value(None) == "<nil>"
    assert format_value(True) == "true"
    assert format_value(7) == "7"
    assert format_value([1, "a", None]) == "[1 a <nil>]"
    assert format_value({"b": 2.0, "a": [True]}) == "map[a:[true] b:2]"
    assert format_value(struct) == "{x 1.0.0}"


@pytest.mark.parametrize(
    ("value", "name"),
    [
        (None, "<nil>"),
        (True, "bool"),
        (1, "int"),
        (1.0, "float64"),
        ("s", "string"),
        ([], "[]interface {}"),
        ({}, "map[string]interface {}"),
        (Struct("T", {}), "T"),
        ((1,), "unknown"),
    ],
)
def test_go_type_names(value: Any, name: str) -> None:
    assert go_type(value) == name


@pytest.mark.parametrize(
    ("value", "truth"),
    [(None, False), (0, False), (0.0, False), ("", False), ([], False), ({}, False),
     (False, False), (1, True), ("x", True), ([0], True), (Struct("T", {}), True)],
)  # fmt: skip
def test_go_truth(value: Any, truth: bool) -> None:
    assert is_true(value) is truth


def test_go_quote_escapes() -> None:
    assert go_quote('a"b\\c\n\t\x01\x7fé') == '"a\\"b\\\\c\\n\\t\\x01\\x7fé"'


def test_helm_numbers_are_float64_but_bools_stay() -> None:
    assert helm_numbers({"a": [1, True, "1"], "b": {"c": 2}}) == {
        "a": [1.0, True, "1"],
        "b": {"c": 2.0},
    }


# ---------------------------------------------------------------------------
# Template language
# ---------------------------------------------------------------------------
def test_trim_markers_and_comments() -> None:
    assert render("a  {{- 1 -}}  b") == "a1b"
    assert render("a {{/* note */}} b") == "a  b"
    assert render("a\n  {{- /* note */ -}}\n  b") == "ab"
    assert render("{{-3}}") == "-3"  # a negative number, not a trim marker


def test_conditionals_with_else_if_and_with() -> None:
    template = "{{ if eq . 1 }}one{{ else if eq . 2 }}two{{ else }}many{{ end }}"
    assert [render(template, n) for n in (1, 2, 3)] == ["one", "two", "many"]
    assert render("{{ with .a }}[{{ . }}]{{ else }}none{{ end }}", {"a": "x"}) == "[x]"
    assert render("{{ with .a }}[{{ . }}]{{ else with .b }}<{{ . }}>{{ end }}", {"b": 2}) == "<2>"


def test_range_over_lists_maps_and_nothing() -> None:
    assert render("{{ range $i, $v := . }}{{ $i }}={{ $v }};{{ end }}", ["a", "b"]) == "0=a;1=b;"
    assert render("{{ range $k, $v := . }}{{ $k }}={{ $v }};{{ end }}", {"z": 1, "a": 2}) == (
        "a=2;z=1;"
    )
    assert render("{{ range . }}{{ . }}{{ end }}", ["x", "y"]) == "xy"
    assert render("{{ range . }}x{{ else }}empty{{ end }}", []) == "empty"
    assert render("{{ range .missing }}x{{ else }}nil{{ end }}", {}) == "nil"


def test_variables_scope_and_assignment() -> None:
    template = (
        "{{ $x := 1 }}{{ if true }}{{ $x = 2 }}{{ $y := 3 }}{{ end }}{{ $x }}"
        "{{ range list 1 2 }}{{ $x = . }}{{ end }}{{ $x }}{{ $.name }}"
    )
    assert render(template, {"name": "!"}) == "22!"


def test_define_include_template_and_dollar() -> None:
    sources = {
        "t": '{{ template "greet" .name }}/{{ include "greet" "b" | upper_ok }}',
        "_h.tpl": '{{ define "greet" }}hi {{ . }}{{ end }}',
    }
    with pytest.raises(TemplateError, match='function "upper_ok" not defined'):
        TemplateSet(sources)
    sources["t"] = (
        '{{ template "greet" .name }}/{{ include "greet" "b" | quote }}{{ template "x" }}'
    )
    sources["_h.tpl"] += '{{ define "x" }}[{{ $ }}]{{ end }}'
    assert TemplateSet(sources).execute("t", {"name": "a"}) == 'hi a/"hi b"[]'


def test_parenthesized_pipelines_and_field_chains() -> None:
    assert render('{{ (dict "a" (dict "b" 7)).a.b }}') == "7"
    assert render('{{ $m := dict "k" "v" }}{{ $m.k }}{{ ($m).k }}') == "vv"
    assert render("{{ .a.b }}", {"a": {"b": [1, 2]}}) == "[1 2]"


def test_string_literals_and_escapes() -> None:
    assert render(r'{{ "tab\there\x41é\101\"" }}') == 'tab\there\x41é\x41"'
    assert render("{{ `raw\\n` }}") == "raw\\n"
    assert render("{{ 0x1F }} {{ 1.5 }} {{ true }} {{ print nil }}") == "31 1.5 true <nil>"


def test_and_or_short_circuit() -> None:
    assert render("{{ and 1 0 (fail `never`) }}") == "0"
    assert render("{{ or 0 `x` (fail `never`) }}") == "x"
    assert render("{{ and 1 2 }}|{{ or 0 `` }}|{{ 0 | or 5 }}") == "2||5"


# -- Helm value semantics -------------------------------------------------
def test_helm_float64_gotchas_are_reproduced() -> None:
    values = helm_numbers({"port": 6333, "big": 1000000})
    assert render("{{ .port }}|{{ .big }}|{{ int .big }}", values) == "6333|1e+06|1000000"
    assert render('{{ printf "%d" .port }}', values) == "%!d(float64=6333)"
    assert render('{{ printf "%d" (int .port) }}', values) == "6333"
    with pytest.raises(TemplateError, match="incompatible types for comparison"):
        render("{{ eq .port 6333 }}", values)
    assert render("{{ eq (int .port) 6333 }}", values) == "true"


def test_missing_keys_render_empty_unless_strict() -> None:
    assert render("[{{ .a.missing }}]", {"a": {}}) == "[]"
    with pytest.raises(TemplateError, match='map has no entry for key "missing"'):
        render("{{ .a.missing }}", {"a": {}}, strict=True)


def test_struct_fields_never_default() -> None:
    data = {"Chart": Struct("*chart.Metadata", {"Name": "c"})}
    assert render("{{ .Chart.Name }}", data) == "c"
    with pytest.raises(TemplateError, match=r"can't evaluate field Nme in type \*chart.Metadata"):
        render("{{ .Chart.Nme }}", data)


@pytest.mark.parametrize(
    ("template", "message"),
    [
        ("{{ .a.b }}", r"nil pointer evaluating interface \{\}.b"),
        ("{{ .s.x }}", "can't evaluate field x in type string"),
        ("{{ range .s }}{{ end }}", "range can't iterate over str"),
        ('{{ include "nope" . }}', 'no template "nope"'),
        ('{{ template "nope" }}', 'no template "nope"'),
        ("{{ len 3 }}", "len of type int"),
        ("{{ index .s 0 }}", "can't index item of type string"),
        ("{{ index .l 5 }}", "index out of range: 5"),
        ("{{ index .l `a` }}", "cannot index slice with type string"),
        ("{{ index .a `b` `c` }}", "index of untyped nil"),
        ("{{ index .m 1 }}", "expected string; got int"),
        ("{{ not }}", "wrong number of args for not: want 1 got 0"),
        ("{{ printf }}", "want at least 1 got 0"),
        ("{{ default }}", "want 1-2 got 0"),
        ("{{ and }}", "wrong number of args for and: want at least 1 got 0"),
        ("{{ include `x` }}", "wrong number of args for include: want 2 got 1"),
        ("{{ fail `boom` }}", "boom"),
        ("{{ required `need it` .missing }}", "need it"),
        ("{{ required `need it` `` }}", "need it"),
        ("{{ lt true false }}", "invalid type for comparison"),
        ("{{ gt 1 `a` }}", "incompatible types for comparison"),
        ("{{ eq .l .l }}", "invalid type for comparison"),
        ("{{ ne 1 `1` }}", "incompatible types for comparison"),
        ('{{ printf "%5d" 1 }}', "unsupported directive %5"),
        ('{{ printf "%.2s" `a` }}', r"unsupported directive %\.2s"),
        ("{{ indent 1.0 `x` }}", "expected int; got float64"),
        ("{{ trunc 1 3 }}", "expected string; got int"),
        ("{{ hasKey .l `a` }}", r"expected map\[string\]interface \{\}; got \[\]interface \{\}"),
        ("{{ append .s 1 }}", "Cannot push on type string"),
    ],
)
def test_execution_errors_carry_location(template: str, message: str) -> None:
    data: dict[str, Any] = {"s": "str", "l": [1], "m": {}, "a": None}
    with pytest.raises(TemplateError, match=message) as info:
        render(template, data)
    assert info.value.template is not None or "no template" in str(info.value)


def test_error_message_names_template_and_line() -> None:
    with pytest.raises(TemplateError) as info:
        render("line1\n{{ fail `here` }}")
    assert (info.value.template, info.value.line) == ("t", 2)
    assert str(info.value) == "template: t:2: here"


def test_recursive_include_is_bounded() -> None:
    sources = {
        "t": '{{ include "loop" . }}',
        "_h": '{{ define "loop" }}{{ include "loop" . }}{{ end }}',
    }
    with pytest.raises(TemplateError, match="nested reference name: loop") as info:
        TemplateSet(sources).execute("t", None)
    assert MAX_INCLUDE_DEPTH == 100
    assert info.value.template == "loop"


def test_missing_top_level_template() -> None:
    with pytest.raises(TemplateError, match='no template "nope"'):
        TemplateSet({}).execute("nope", None)


@pytest.mark.parametrize(
    ("template", "message"),
    [
        ("{{ .a", "unclosed action"),
        ("{{/* x", "unclosed comment"),
        ("{{/* x */ }}", "unclosed comment"),
        ("{{ # }}", "unexpected '#' in action"),
        ("{{ end }}", r"unexpected \{\{end\}\}"),
        ("{{ else }}", r"unexpected \{\{else\}\}"),
        ("{{ if 1 }}x", r"unexpected EOF: \{\{if\}\} not closed"),
        ("{{ if 1 }}{{ else }}x", r"unexpected EOF: \{\{else\}\} not closed"),
        ("{{ if 1 }}{{ else }}{{ else }}{{ end }}", r"expected \{\{end\}\}, found \{\{else\}\}"),
        ("{{ if 1 }}{{ else foo }}{{ end }}", "function \"foo\" not defined|unexpected 'foo'"),
        ("{{ if 1 }}{{ else 1 }}{{ end }}", "unexpected '1' after else"),
        ("{{ range . }}{{ else if 1 }}{{ end }}", "unexpected tokens after"),
        ("{{ range $x = . }}{{ end }}", "undefined variable|only declare"),
        ("{{ $x := 1 }}{{ range $x = . }}{{ end }}", "only declare variables with :="),
        ("{{ if 1 }}{{ define `x` }}{{ end }}{{ end }}", "define is only allowed at the top level"),
        ("{{ define x }}{{ end }}", "define expects exactly one quoted template name"),
        ("{{ define `x` }}{{ else }}{{ end }}", r"unexpected \{\{else\}\} in define"),
        ('{{ define "x" }}{{ end }}{{ define "x" }}{{ end }}', "template 'x' defined twice"),
        ("{{ template }}", "template expects a quoted template name"),
        ("{{ block `x` . }}{{ end }}", r"\{\{block\}\} is not supported offline"),
        ("{{ }}", "missing value for command"),
        ("{{ 1 | }}", "missing value for command"),
        ("{{ $nope }}", 'undefined variable "\\$nope"'),
        ("{{ $nope = 1 }}", 'undefined variable "\\$nope"'),
        ("{{ upper `x` }}", 'function "upper" not defined'),
        ("{{ nil }}", "nil is not a command"),
        ("{{ .a 1 }}", "can't give argument to non-function"),
        ("{{ 1 | .a }}", "non executable command in pipeline stage 2"),
        ("{{ (1 }}", "unclosed left paren"),
        ("{{ , }}", "unexpected ',' in operand"),
        ("{{ $a := 0 }}{{ 1 $a := 2 }}", "unexpected ':=' in operand"),
        ("{{ $a := 0 }}{{ $a, 1 := 2 }}", "unexpected ',' in operand"),
        ("{{ $a, $b := 1 }}", r"too many declarations in \$a \$b"),
        ("{{ ($a := 1) }}", r"too many declarations in \$a"),
        (r'{{ "\q" }}', r"unknown escape sequence \\q"),
    ],
)
def test_parse_errors(template: str, message: str) -> None:
    with pytest.raises(TemplateError, match=message):
        TemplateSet({"t": template})


def test_template_names_are_unique_across_files() -> None:
    with pytest.raises(TemplateError, match="defined more than once"):
        TemplateSet({"a": '{{ define "x" }}{{ end }}', "b": '{{ define "x" }}{{ end }}'})
    assert "a" in TemplateSet({"a": ""})


# -- functions ------------------------------------------------------------
@pytest.mark.parametrize(
    ("template", "expected"),
    [
        ('{{ printf "%v|%s|%q|%d|%t|%f|%.2f|%%" 1 `a` `b` 2 true 1.5 2.0 }}',
         '1|a|"b"|2|true|1.500000|2.00|%'),
        ('{{ printf "%s %d" 1 }}', "%!s(int=1) %!d(MISSING)"),
        ('{{ printf "%s" nil }}', "%!s(<nil>)"),
        ('{{ printf "x" 1 `y` }}', "x%!(EXTRA int=1, string=y)"),
        ("{{ print 1 2 `a` 3 `b` `c` }}", "1 2a3bc"),
        ("{{ quote `a` nil 1 }}", '"a" "1"'),
        ("{{ default `d` `` }}|{{ default `d` `v` }}|{{ default `d` }}", "d|v|d"),
        ("{{ empty 0 }}{{ empty `x` }}", "truefalse"),
        ("{{ toString 1.5 }}|{{ toString `s` }}", "1.5|s"),
        ("{{ int `08` }} {{ int `0x10` }} {{ int `2.0` }} {{ int true }}", "0 16 2 1"),
        ("{{ int nil }} {{ required `m` `ok` }} {{ len list }} {{ 1 | and 2 }}", "0 ok 0 1"),
        ("{{ int 2.9 }} {{ int64 `-3` }} {{ int `x` }}", "2 -3 0"),
        ("{{ mul 2 `3` 4.0 }}", "24"),
        ("{{ trunc 3 `abcdef` }}|{{ trunc -2 `abcdef` }}|{{ trunc -9 `ab` }}", "abc|ef|ab"),
        ("{{ trimSuffix `-` `a-` }}|{{ hasSuffix `Gi` `2Gi` }}", "a|true"),
        ("{{ replace `+` `_` `1.0.0+b` }}", "1.0.0_b"),
        ("{{ indent 2 `a\nb` }}|{{ nindent 1 `c` }}", "  a\n  b|\n c"),
        ('{{ $d := dict "a" 1 "b" }}{{ $d.a }}[{{ $d.b }}]{{ hasKey $d "b" }}', "1[]true"),
        ('{{ $d := dict "a" 1 }}{{ $_ := set $d "c" 3 }}{{ get $d "c" }}[{{ get $d "z" }}]', "3[]"),
        ("{{ join `,` (list 1 nil `a`) }}|{{ join `,` nil }}|{{ join `,` 5 }}", "1,a||5"),
        ("{{ len (append (list 1) 2) }}{{ len `abc` }}{{ len (dict) }}", "230"),
        ("{{ index (list (dict `k` `v`)) 0 `k` }}", "v"),
        ("{{ toYaml (dict `b` (list 1 2) `a` 1.0) }}", "a: 1\nb:\n- 1\n- 2"),
        ("{{ toYaml `s` }}|{{ toYaml nil }}|{{ toYaml (dict) }}|{{ toYaml 1.5 }}", "s|null|{}|1.5"),
        ("{{ not 0 }}{{ ne 1 2 }}{{ le 1 1 }}{{ ge `b` `a` }}{{ lt 1.5 2.5 }}", "true" * 5),
        ("{{ eq 1 2 1 }}{{ eq nil 1 }}{{ eq nil nil }}{{ eq `a` `b` }}", "truefalsetruefalse"),
    ],
)  # fmt: skip
def test_functions(template: str, expected: str) -> None:
    assert render(template) == expected


def test_to_yaml_swallows_unrepresentable_values() -> None:
    assert render("[{{ toYaml . }}]", Struct("T", {"a": 1})) == "[]"


def test_set_mutates_values_like_helm() -> None:
    values: dict[str, Any] = {"m": {}}
    render('{{ $_ := set .m "k" "v" }}', values)
    assert values == {"m": {"k": "v"}}


# ---------------------------------------------------------------------------
# Chart files
# ---------------------------------------------------------------------------
def test_chart_metadata(chart: Chart) -> None:
    meta = chart.metadata
    assert (meta.api_version, meta.name, meta.version, meta.type) == (
        "v2",
        "cloud-native-k8s-ai",
        "1.0.0",
        "application",
    )
    assert meta.app_version == "0.1.0"
    assert chart.values["api"]["image"]["tag"] == meta.app_version
    assert meta.kube_version == ">=1.27.0-0"
    assert meta.chart_label == "cloud-native-k8s-ai-1.0.0"
    assert meta.maintainers[0].name == "mikeZ98"
    struct = meta.to_template()
    assert struct.fields["AppVersion"] == "0.1.0"
    assert struct.fields["Maintainers"][0]["name"] == "mikeZ98"


def test_chart_layout(chart: Chart) -> None:
    assert sorted(chart.templates) == [
        "templates/NOTES.txt",
        "templates/_helpers.tpl",
        "templates/deployment-api.yaml",
        "templates/deployment-redis.yaml",
        "templates/networkpolicies.yaml",
        "templates/pvc-redis.yaml",
        "templates/scaledobject.yaml",
        "templates/service-api.yaml",
        "templates/service-qdrant.yaml",
        "templates/service-redis.yaml",
        "templates/statefulset-qdrant.yaml",
    ]
    assert (CHART_DIR / ".helmignore").is_file()


@pytest.mark.parametrize("name", ["Chart.yaml", "values.yaml"])
def test_chart_yaml_files_lint_clean(name: str) -> None:
    config = YamlLintConfig(file=str(ROOT / ".yamllint.yaml"))
    text = (CHART_DIR / name).read_text(encoding="utf-8")
    problems = [f"{p.line}:{p.column} {p.rule} {p.message}" for p in linter.run(text, config)]
    assert problems == []


def test_values_yaml_satisfies_values_schema(chart: Chart) -> None:
    assert chart.schema is not None
    Draft7Validator.check_schema(chart.schema)
    assert chart.schema["$schema"] == "http://json-schema.org/draft-07/schema#"
    assert list(Draft7Validator(chart.schema).iter_errors(chart.values)) == []
    assert chart.schema_problems(dict(chart.values)) == []


def test_values_schema_is_closed(chart: Chart) -> None:
    assert open_schema_objects(chart.schema) == []
    assert set(chart.schema["required"]) == set(chart.values)  # type: ignore[index]


def test_default_values_match_the_core_contract(chart: Chart) -> None:
    stack = validate_values(chart, chart.values)
    assert stack.autoscaling is True
    assert stack.settings.namespace == NS
    assert (stack.spec.app.name, stack.spec.qdrant.name, stack.spec.redis.name) == (
        API,
        QDRANT,
        REDIS,
    )


@pytest.mark.parametrize(
    ("overlay", "fragment"),
    [
        ({"api": {"image": {"tag": "latest"}}}, "api.image.tag"),
        ({"api": {"image": {"tag": 1.0}}}, "api.image.tag: 1.0 is not of type 'string'"),
        ({"api": {"image": {"digest": "sha256:abc"}}}, "api.image.digest"),
        ({"api": {"image": {"repository": "Bad/Repo"}}}, "api.image.repository"),
        ({"api": {"replicas": -1}}, "api.replicas: -1 is less than the minimum of 0"),
        ({"api": {"containerPort": 70000}}, "api.containerPort"),
        ({"api": {"resources": {"limits": {"cpu": "500x"}}}}, "api.resources.limits.cpu"),
        ({"api": {"resources": {"requests": {"cpu": "0m"}}}}, "api.resources.requests.cpu"),
        ({"api": {"resources": {"requests": {"cpu": 1}}}}, "api.resources.requests.cpu"),
        ({"api": {"resources": {"limits": {"memory": "1gb"}}}}, "api.resources.limits.memory"),
        ({"api": {"probes": {"livenessPath": "healthz"}}}, "api.probes.livenessPath"),
        ({"api": {"labels": {"app.kubernetes.io/name": "x"}}}, "api.labels"),
        ({"api": {"labels": {"team": "-bad-"}}}, "api.labels.team"),
        ({"api": {"env": [{"name": "REDIS_URL", "value": "x"}]}}, "api.env[0]"),
        ({"api": {"env": [{"name": "A", "value": "x", "valueFrom": {}}]}}, "api.env[0]"),
        ({"api": {"replica": 2}}, "Additional properties are not allowed ('replica'"),
        ({"qdrant": {"persistence": {"storage": {"storageClassName": "Fast_SSD"}}}},
         "qdrant.persistence.storage.storageClassName"),
        ({"redis": {"maxmemory": "1G"}}, "redis.maxmemory"),
        ({"redis": {"maxmemoryPolicy": "lru"}}, "redis.maxmemoryPolicy"),
        ({"redis": {"persistence": {"mode": "rdb", "savePoints": []}}},
         "redis.persistence.savePoints: [] should be non-empty"),
        ({"redis": {"persistence": {"appendfsync": False}}}, "redis.persistence.appendfsync"),
        ({"autoscaling": {"pollingInterval": 0}}, "autoscaling.pollingInterval"),
        ({"autoscaling": {"databaseIndex": 16}}, "autoscaling.databaseIndex"),
        ({"autoscaling": {"listName": "has space"}}, "autoscaling.listName"),
        ({"networkPolicy": {"kedaOperator": {"podLabels": {"bad key": "x"}}}},
         "networkPolicy.kedaOperator.podLabels"),
        ({"environment": "qa"}, "environment"),
        ({"surprise": True}, "Additional properties are not allowed ('surprise'"),
    ],
)  # fmt: skip
def test_values_schema_rejects(chart: Chart, overlay: dict[str, Any], fragment: str) -> None:
    with pytest.raises(ChartValuesError) as info:
        render_chart(chart, overlay)
    assert any(fragment in p for p in info.value.problems), info.value.problems


@pytest.mark.parametrize(
    ("overlay", "fragment"),
    [
        ({"redis": {"maxmemory": "1Gi"}}, "must stay below the memory limit"),
        ({"qdrant": {"ports": {"grpc": 6333}}}, "REST and gRPC ports must differ"),
        ({"qdrant": {"persistence": {"snapshots": {"mountPath": "/qdrant/storage"}}}},
         "/qdrant/storage"),
        ({"autoscaling": {"minReplicas": 5, "maxReplicas": 3}}, "exceeds max_replicas"),
        ({"autoscaling": {"idleReplicas": 1}}, "must be lower than min_replicas"),
        ({"autoscaling": {"cooldownPeriod": 10}}, "shorter than polling_interval"),
        ({"api": {"replicas": 20}}, "starts with 20 replicas"),
        ({"redis": {"name": "qdrant"}}, "component names must be distinct"),
    ],
)  # fmt: skip
def test_typed_contract_rejects_what_the_schema_cannot(
    chart: Chart, overlay: dict[str, Any], fragment: str
) -> None:
    values = merge_values(chart.values, overlay)
    assert chart.schema_problems(values) == []
    with pytest.raises(ChartValuesError) as info:
        validate_values(chart, values)
    assert fragment in str(info.value)


@pytest.mark.parametrize(
    ("overlay", "message"),
    [
        ({"redis": {"name": "qdrant"}}, "must be distinct"),
        ({"qdrant": {"ports": {"grpc": 6333}}}, "must differ"),
        ({"autoscaling": {"minReplicas": 5, "maxReplicas": 3}}, "must not exceed"),
        ({"autoscaling": {"idleReplicas": 1}}, "idleReplicas must be lower"),
        ({"autoscaling": {"cooldownPeriod": 10}}, "cooldownPeriod must be at least"),
        ({"api": {"replicas": 20}}, "api.replicas must lie within"),
    ],
)
def test_templates_fail_the_install_on_cross_field_errors(
    chart: Chart, overlay: dict[str, Any], message: str
) -> None:
    with pytest.raises(TemplateError, match=message) as info:
        render_chart(chart, overlay)
    assert info.value.template == "ai.validate"


def test_disabled_autoscaling_skips_its_guards(chart: Chart) -> None:
    overlay = {"autoscaling": {"enabled": False, "minReplicas": 5, "maxReplicas": 3}}
    assert "templates/scaledobject.yaml" in render_chart(chart, overlay).manifests


# ---------------------------------------------------------------------------
# Rendered templates: structure
# ---------------------------------------------------------------------------
def test_rendered_kinds(docs: dict[str, dict[str, Any]]) -> None:
    assert sorted(docs) == sorted(
        [
            f"Deployment/{API}",
            f"Deployment/{REDIS}",
            f"StatefulSet/{QDRANT}",
            f"Service/{API}",
            f"Service/{QDRANT}",
            f"Service/{QDRANT}-headless",
            f"Service/{REDIS}",
            f"PersistentVolumeClaim/{REDIS}-data",
            f"ScaledObject/{API}",
            "NetworkPolicy/default-deny-all",
            "NetworkPolicy/allow-dns-egress",
            "NetworkPolicy/qdrant-allow-from-app",
            f"NetworkPolicy/{API}-allow-ingress",
            f"NetworkPolicy/{API}-allow-egress",
            f"NetworkPolicy/{REDIS}-allow-ingress",
        ]
    )
    assert {d["metadata"]["namespace"] for d in docs.values()} == {NS}


def test_rendered_documents_parse_into_typed_models(rendered: RenderedChart) -> None:
    bundle = rendered.bundle()
    assert len(bundle) == 15
    assert ManifestBundle.from_yaml(bundle.to_yaml()).to_documents() == bundle.to_documents()


def test_every_object_carries_release_labels(chart: Chart, rendered: RenderedChart) -> None:
    assert release_label_problems(chart, rendered) == []
    for document in rendered.documents():
        labels = document["metadata"]["labels"]
        assert labels["app.kubernetes.io/managed-by"] == "Helm"
        assert labels["app.kubernetes.io/instance"] == "ai"


@pytest.mark.parametrize(
    ("key", "component"),
    [
        (f"Deployment/{API}", "api"),
        (f"Deployment/{REDIS}", "broker"),
        (f"StatefulSet/{QDRANT}", "vector-store"),
    ],
)
def test_workload_labels_and_selectors(
    docs: dict[str, dict[str, Any]], key: str, component: str
) -> None:
    workload = docs[key]
    name = workload["metadata"]["name"]
    selector = {"app.kubernetes.io/name": name, "app.kubernetes.io/component": component}
    assert workload["spec"]["selector"] == {"matchLabels": selector}
    pod_labels = workload["spec"]["template"]["metadata"]["labels"]
    assert pod_labels == {
        **selector,
        "app.kubernetes.io/part-of": "cloud-native-k8s-ai",
        "environment": "dev",
    }
    # Chart version and instance stay off pod templates: a chart bump must not roll pods.
    assert not set(pod_labels) & set(HELM_RELEASE_LABELS)
    assert workload["metadata"]["labels"].items() >= pod_labels.items()
    services = [d for d in docs.values() if d["kind"] == "Service"]
    assert any(s["spec"]["selector"] == selector for s in services)


def test_services_select_their_pods(docs: dict[str, dict[str, Any]]) -> None:
    pods = {
        key: d["spec"]["template"]["metadata"]["labels"]
        for key, d in docs.items()
        if d["kind"] in {"Deployment", "StatefulSet"}
    }
    for document in (d for d in docs.values() if d["kind"] == "Service"):
        selector = document["spec"]["selector"]
        matched = [k for k, labels in pods.items() if labels.items() >= selector.items()]
        assert len(matched) == 1, document["metadata"]["name"]
    assert docs[f"Service/{QDRANT}-headless"]["spec"]["clusterIP"] == "None"
    assert docs[f"StatefulSet/{QDRANT}"]["spec"]["serviceName"] == f"{QDRANT}-headless"


def test_api_deployment_probes_and_wiring(docs: dict[str, dict[str, Any]]) -> None:
    container = docs[f"Deployment/{API}"]["spec"]["template"]["spec"]["containers"][0]
    assert container["readinessProbe"]["httpGet"] == {
        "path": "/readyz",
        "port": "http",
        "scheme": "HTTP",
    }
    assert container["livenessProbe"]["httpGet"]["path"] == "/healthz"
    assert container["startupProbe"]["failureThreshold"] == 60
    env = {e["name"]: e["value"] for e in container["env"]}
    assert env == {
        "QDRANT_HOST": f"{QDRANT}.{NS}.svc.cluster.local",
        "QDRANT_HTTP_PORT": "6333",
        "QDRANT_GRPC_PORT": "6334",
        "REDIS_URL": f"redis://{REDIS}.{NS}.svc.cluster.local:6379/0",
        "REDIS_QUEUE": "inference-jobs",
        "TMPDIR": "/scratch",
    }
    assert container["image"] == "ghcr.io/mikez98/inference-api:0.1.0"


@pytest.mark.parametrize(
    "key", [f"Deployment/{API}", f"Deployment/{REDIS}", f"StatefulSet/{QDRANT}"]
)
def test_workload_security_baseline(docs: dict[str, dict[str, Any]], key: str) -> None:
    pod = docs[key]["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"]["runAsNonRoot"] is True
    for container in pod["containers"]:
        ctx = container["securityContext"]
        assert ctx["runAsNonRoot"] is True
        assert ctx["readOnlyRootFilesystem"] is True
        assert ctx["allowPrivilegeEscalation"] is False
        assert ctx["capabilities"]["drop"] == ["ALL"]
        assert container["resources"].keys() == {"requests", "limits"}
        assert {"readinessProbe", "livenessProbe"} <= container.keys()
        assert not container["image"].endswith(":latest")


def test_qdrant_statefulset_storage(docs: dict[str, dict[str, Any]]) -> None:
    sts = docs[f"StatefulSet/{QDRANT}"]["spec"]
    claims = {c["metadata"]["name"]: c["spec"] for c in sts["volumeClaimTemplates"]}
    assert claims["storage"]["resources"]["requests"]["storage"] == "20Gi"
    assert claims["snapshots"]["resources"]["requests"]["storage"] == "10Gi"
    assert "storageClassName" not in claims["storage"]
    ports = sts["template"]["spec"]["containers"][0]["ports"]
    assert [(p["name"], p["containerPort"]) for p in ports] == [("rest", 6333), ("grpc", 6334)]
    assert sts["replicas"] == 1
    assert sts["persistentVolumeClaimRetentionPolicy"] == {
        "whenDeleted": "Retain",
        "whenScaled": "Retain",
    }


def test_redis_args_are_strings(docs: dict[str, dict[str, Any]]) -> None:
    container = docs[f"Deployment/{REDIS}"]["spec"]["template"]["spec"]["containers"][0]
    assert all(isinstance(a, str) for a in container["args"])
    assert container["args"][container["args"].index("--maxmemory") + 1] == "805306368"
    assert container["args"][container["args"].index("--appendonly") + 1] == "yes"


def test_scaledobject_parameters(docs: dict[str, dict[str, Any]]) -> None:
    scaled = docs[f"ScaledObject/{API}"]
    spec = scaled["spec"]
    assert scaled["apiVersion"] == "keda.sh/v1alpha1"
    assert spec["scaleTargetRef"] == {"apiVersion": "apps/v1", "kind": "Deployment", "name": API}
    assert (spec["minReplicaCount"], spec["maxReplicaCount"]) == (1, 10)
    assert (spec["pollingInterval"], spec["cooldownPeriod"]) == (30, 300)
    assert "idleReplicaCount" not in spec
    (trigger,) = spec["triggers"]
    assert trigger["type"] == "redis"
    assert trigger["metadata"] == {
        "address": f"{REDIS}.{NS}.svc.cluster.local:6379",
        "databaseIndex": "0",
        "enableTLS": "false",
        "listName": "inference-jobs",
        "listLength": "5",
        "activationListLength": "0",
    }
    assert all(isinstance(v, str) for v in trigger["metadata"].values())
    ScaledObject.from_wire(scaled)


def test_scaledobject_optional_fields(chart: Chart) -> None:
    overlay = {
        "autoscaling": {"idleReplicas": 0, "authenticationRef": "redis-auth", "enableTLS": True}
    }
    docs = {d["kind"]: d for d in render_chart(chart, overlay, strict=True).documents()}
    spec = docs["ScaledObject"]["spec"]
    assert spec["idleReplicaCount"] == 0
    assert spec["triggers"][0]["authenticationRef"] == {
        "name": "redis-auth",
        "kind": "TriggerAuthentication",
    }
    assert spec["triggers"][0]["metadata"]["enableTLS"] == "true"


def test_networkpolicies_isolate_qdrant_to_the_api(docs: dict[str, dict[str, Any]]) -> None:
    deny = docs["NetworkPolicy/default-deny-all"]["spec"]
    assert deny == {
        "podSelector": {},
        "policyTypes": ["Ingress", "Egress"],
        "ingress": [],
        "egress": [],
    }
    qdrant = docs["NetworkPolicy/qdrant-allow-from-app"]["spec"]
    assert qdrant["podSelector"]["matchLabels"] == {
        "app.kubernetes.io/name": QDRANT,
        "app.kubernetes.io/component": "vector-store",
    }
    (rule,) = qdrant["ingress"]
    assert rule["from"] == [
        {
            "podSelector": {
                "matchLabels": {"app.kubernetes.io/name": API, "app.kubernetes.io/component": "api"}
            }
        }
    ]
    assert sorted(p["port"] for p in rule["ports"]) == [6333, 6334]
    dns = docs["NetworkPolicy/allow-dns-egress"]["spec"]["egress"][0]
    assert {(p["protocol"], p["port"]) for p in dns["ports"]} == {("UDP", 53), ("TCP", 53)}


def test_rendered_policies_pass_the_topology_solver(chart: Chart, rendered: RenderedChart) -> None:
    generator = validate_values(chart, rendered.values).generator
    report = TopologySolver(generator.topology(rendered.bundle())).verify(generator.intent())
    assert report.ok, report.violations


def test_opening_qdrant_is_caught_by_the_solver(chart_files: dict[str, str]) -> None:
    broken = with_template(
        chart_files,
        "templates/networkpolicies.yaml",
        "    - from:\n        - podSelector:\n            matchLabels:\n"
        '              {{- include "ai.selectorLabels" $api | nindent 14 }}\n      ports:\n'
        "        - protocol: TCP\n          port: {{ int .Values.qdrant.ports.rest }}",
        "    - from:\n        - podSelector: {}\n      ports:\n"
        "        - protocol: TCP\n          port: {{ int .Values.qdrant.ports.rest }}",
    )
    findings = lint_chart(broken).findings
    assert any("[exclusive-ingress] qdrant admits" in f for f in findings), findings


def test_notes_render_verification_steps(rendered: RenderedChart, chart: Chart) -> None:
    assert f"rollout status statefulset/{QDRANT}" in rendered.notes
    assert "get scaledobject inference-api" in rendered.notes
    assert "curl -fsS http://127.0.0.1:8080/readyz" in rendered.notes
    fixed = render_chart(chart, {"autoscaling": {"enabled": False}}).notes
    assert "Autoscaling is disabled: inference-api runs a fixed 2 replicas." in fixed
    assert "scaledobject" not in fixed


def test_release_name_and_namespace_flow_through(chart: Chart) -> None:
    release = Release(name="prod-ai", namespace="ml-serving", revision=3, is_upgrade=True)
    out = render_chart(chart, {"environment": "prod"}, release)
    labels = {d["metadata"]["labels"]["app.kubernetes.io/instance"] for d in out.documents()}
    assert labels == {"prod-ai"}
    assert {d["metadata"]["namespace"] for d in out.documents()} == {"ml-serving"}
    assert lint_chart(chart, {"prod": {"environment": "prod"}}, release).ok
    assert release.to_template()["IsUpgrade"] is True


# ---------------------------------------------------------------------------
# Parity with the core generator
# ---------------------------------------------------------------------------
OVERLAYS: dict[str, dict[str, Any]] = {
    "autoscaling-off": {"autoscaling": {"enabled": False}},
    "redis-ephemeral": {"redis": {"persistence": {"mode": "none"}}},
    "redis-rdb-aof": {
        "redis": {
            "maxmemory": "512Mi",
            "persistence": {"mode": "rdb+aof", "appendfsync": "no", "storageClassName": "fast"},
        }
    },
    "redis-rdb": {"redis": {"persistence": {"mode": "rdb"}, "port": 6380}},
    "scale-to-zero-tls": {
        "autoscaling": {
            "idleReplicas": 0,
            "minReplicas": 2,
            "maxReplicas": 20,
            "enableTLS": True,
            "authenticationRef": "redis-auth",
            "databaseIndex": 3,
            "listName": "jobs:high",
        }
    },
    "customized": {
        "environment": "staging",
        "api": {
            "name": "embedder",
            "image": {"digest": "sha256:" + "a" * 64},
            "containerPort": 9000,
            "service": {"port": 8080},
            "probes": {"livenessPath": "/live", "readinessPath": "/ready"},
            "env": [
                {"name": "MODEL_NAME", "value": "bge-small"},
                {"name": "API_KEY", "valueFrom": {"secretKeyRef": {"name": "api", "key": "k"}}},
            ],
            "labels": {"team": "ml", "cost-center": "1234"},
        },
        "qdrant": {
            "name": "vectors",
            "ports": {"rest": 7333, "grpc": 7334},
            "persistence": {"storage": {"size": "100Gi", "storageClassName": "gp3"}},
            "labels": {"tier": "data"},
        },
        "networkPolicy": {
            "ingressController": {"namespace": "gateway"},
            "kedaOperator": {"namespace": "keda-system", "podLabels": {"app": "keda", "x": "y"}},
        },
    },
}


@pytest.mark.parametrize("overlay", list(OVERLAYS.values()), ids=list(OVERLAYS))
def test_chart_matches_core_generator(chart: Chart, overlay: dict[str, Any]) -> None:
    values = merge_values(chart.values, overlay)
    expected = validate_values(chart, values).expected().to_documents()
    actual = render_chart(chart, overlay, strict=True).documents()
    assert diff_manifests(expected, actual) == []


def test_lint_passes_for_defaults_and_overlays(chart: Chart) -> None:
    report = lint_chart(chart, OVERLAYS)
    assert report.ok, report.findings
    report.raise_for_findings()


def test_overlay_variants_render_expected_objects(chart: Chart) -> None:
    kinds = {
        name: sorted(
            f"{d['kind']}/{d['metadata']['name']}" for d in render_chart(chart, o).documents()
        )
        for name, o in OVERLAYS.items()
    }
    assert f"ScaledObject/{API}" not in kinds["autoscaling-off"]
    assert f"PersistentVolumeClaim/{REDIS}-data" not in kinds["redis-ephemeral"]
    assert "Deployment/embedder" in kinds["customized"]
    ephemeral = {
        d["kind"] + d["metadata"]["name"]: d
        for d in render_chart(chart, OVERLAYS["redis-ephemeral"]).documents()
    }
    volumes = ephemeral[f"Deployment{REDIS}"]["spec"]["template"]["spec"]["volumes"]
    assert volumes == [{"name": "data", "emptyDir": {"medium": ""}}]


def test_diff_reports_every_kind_of_drift() -> None:
    base = {"kind": "Service", "metadata": {"name": "a", "namespace": "n", "labels": {"x": "1"}}}
    expected = [
        {**base, "spec": {"ports": [{"port": 80}], "type": "ClusterIP", "gone": 1}},
        {"kind": "Service", "metadata": {"name": "b", "namespace": "n"}},
    ]
    actual = [
        {**base, "spec": {"ports": [{"port": "80"}], "extra": True, "type": "ClusterIP"}},
        {**base, "spec": {"ports": []}},
        {"kind": "Pod", "metadata": {"name": "c", "namespace": "n"}},
    ]
    assert diff_manifests(expected, actual) == [
        "Service n/a: rendered more than once",
        "Service n/b: missing",
        "Pod n/c: not produced by the core generator",
        "Service n/a: spec.gone: missing, expected 1",
        "Service n/a: spec.ports: expected 1 items, got 0",
        "Service n/a: spec.type: missing, expected 'ClusterIP'",
    ]
    assert diff_manifests(expected[:1], actual[:1]) == [
        "Service n/a: spec.extra: unexpected True",
        "Service n/a: spec.gone: missing, expected 1",
        "Service n/a: spec.ports[0].port: expected 80, got '80'",
    ]


def test_release_labels_are_the_only_tolerated_drift() -> None:
    labels = {"helm.sh/chart": "c-1", "app.kubernetes.io/managed-by": "Helm", "team": "ml"}
    doc = {"metadata": {"labels": labels}, "items": [{"labels": {"helm.sh/chart": "x"}}]}
    assert without_release_labels(doc) == {"metadata": {"labels": {"team": "ml"}}, "items": [{}]}


# ---------------------------------------------------------------------------
# Lint failures and loader errors
# ---------------------------------------------------------------------------
def test_lint_flags_a_missing_security_context(chart_files: dict[str, str]) -> None:
    broken = with_template(
        chart_files,
        "templates/deployment-api.yaml",
        "          securityContext:\n"
        '            {{- include "ai.containerSecurityContext" . | nindent 12 }}\n',
        "",
    )
    (finding,) = lint_chart(broken).findings
    assert finding.startswith(
        f"[defaults] Deployment {NS}/{API}: "
        "spec.template.spec.containers[0].securityContext: missing"
    )


def test_lint_flags_missing_release_labels(chart_files: dict[str, str]) -> None:
    broken = with_template(
        chart_files,
        "templates/_helpers.tpl",
        "app.kubernetes.io/instance: {{ .Release.Name | quote }}\n",
        "",
    )
    findings = lint_chart(broken).findings
    assert len(findings) == 15
    assert all("label app.kubernetes.io/instance=None, expected 'ai'" in f for f in findings)


def test_lint_flags_template_typos_in_strict_mode(chart_files: dict[str, str]) -> None:
    broken = with_template(
        chart_files, "templates/service-api.yaml", "$api.service.port", "$api.service.prot"
    )
    assert render_chart(broken).manifests  # non-strict renders an empty port...
    (finding,) = lint_chart(broken).findings  # ...strict lint names the typo
    assert 'map has no entry for key "prot"' in finding
    assert "templates/service-api.yaml" in finding


def test_lint_flags_invalid_overlays_and_open_schemas(
    chart: Chart, chart_files: dict[str, str]
) -> None:
    report = lint_chart(chart, {"bad": {"redis": {"maxmemory": "4Gi"}}})
    assert not report.ok
    assert report.findings[0].startswith("[bad] values do not satisfy the chart contract")
    with pytest.raises(ChartError, match="chart lint failed"):
        report.raise_for_findings()
    schema = json.loads(chart_files["values.schema.json"])
    del schema["properties"]["api"]["additionalProperties"]
    opened = Chart.from_files({**chart_files, "values.schema.json": json.dumps(schema)})
    assert lint_chart(opened).findings == (
        "values.schema.json: #/properties/api: object with properties must set "
        "additionalProperties: false",
    )
    no_schema = {k: v for k, v in chart_files.items() if k != "values.schema.json"}
    assert lint_chart(Chart.from_files(no_schema)) == LintReport(("values.schema.json: missing",))
    with pytest.raises(ChartError, match=r"no values\.schema\.json"):
        validate_values(Chart.from_files(no_schema), chart.values)
    assert render_chart(Chart.from_files(no_schema)).manifests


def test_open_schema_objects_ignores_conditional_fragments() -> None:
    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"a": {"properties": {"b": {}}, "additionalProperties": True}},
        "if": {"properties": {"a": {"const": 1}}},
        "allOf": [{"properties": {"c": {}}}],
    }
    assert open_schema_objects(schema) == [
        "#/properties/a: object with properties must set additionalProperties: false",
        "#/allOf/0: object with properties must set additionalProperties: false",
    ]


def test_invalid_rendered_yaml_names_the_template(chart_files: dict[str, str]) -> None:
    broken = with_template(
        chart_files, "templates/service-api.yaml", "  type: ClusterIP", "  type: ["
    )
    with pytest.raises(ManifestRenderError, match=r"templates/service-api\.yaml: invalid YAML"):
        render_chart(broken).documents()
    findings = lint_chart(broken).findings
    assert findings[0].startswith("[defaults] templates/service-api.yaml: invalid YAML")


META = "apiVersion: {}\nname: x\nversion: {}\nappVersion: {}\ndescription: d\n"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"Chart.yaml": None}, "Chart.yaml not found"),
        ({"Chart.yaml": "apiVersion: [\n"}, "Chart.yaml: invalid YAML"),
        ({"Chart.yaml": "- a\n"}, "Chart.yaml: top level must be a mapping"),
        ({"Chart.yaml": META.format("v1", "1.0.0", "'1'")}, "Chart.yaml: apiVersion"),
        ({"Chart.yaml": META.format("v2", "'1.0'", "'1'")}, "Chart.yaml: version"),
        ({"Chart.yaml": META.format("v2", "1.0.0", "1.0")}, "Chart.yaml: appVersion"),
        ({"Chart.yaml": META.format("v2", "1.0.0", "'1'") + "dependencies: []\n"},
         "Chart.yaml: dependencies"),
        ({"values.schema.json": "{"}, "values.schema.json: Expecting property name"),
        ({"values.schema.json": '{"type": 5}'}, "values.schema.json: invalid schema"),
        ({"values.yaml": "a: [\n"}, "values.yaml: invalid YAML"),
    ],
)  # fmt: skip
def test_loader_rejects_malformed_charts(
    chart_files: dict[str, str], change: dict[str, str | None], message: str
) -> None:
    files = {**chart_files, **change}
    with pytest.raises(ChartError, match=message):
        Chart.from_files({k: v for k, v in files.items() if v is not None})


def test_load_requires_a_chart_directory(tmp_path: Path) -> None:
    with pytest.raises(ChartError, match=r"Chart\.yaml not found"):
        Chart.load(tmp_path)
    with pytest.raises(ChartValuesError, match="environment"):
        validate_values(Chart.load(CHART_DIR), {})


def test_empty_values_file_means_no_defaults(chart_files: dict[str, str]) -> None:
    assert Chart.from_files({**chart_files, "values.yaml": ""}).values == {}


def test_merge_values_follows_helm_coalescing() -> None:
    base = {"a": {"b": 1, "c": [1, 2]}, "d": 1, "e": {"f": 1}}
    merged = merge_values(base, {"a": {"c": [3]}, "d": None, "e": 5, "g": {"h": 1}})
    assert merged == {"a": {"b": 1, "c": [3]}, "e": 5, "g": {"h": 1}}
    assert base == {"a": {"b": 1, "c": [1, 2]}, "d": 1, "e": {"f": 1}}


def test_release_is_validated() -> None:
    with pytest.raises(ValueError, match="name"):
        Release(name="Bad_Name")
    assert Release().to_template() == {
        "Name": "ai",
        "Namespace": NS,
        "Revision": 1,
        "Service": "Helm",
        "IsInstall": True,
        "IsUpgrade": False,
    }


def test_errors_belong_to_the_core_hierarchy() -> None:
    assert issubclass(TemplateError, ManifestRenderError)
    assert issubclass(ChartValuesError, ChartError)
    assert issubclass(ChartError, K8sAiCoreError)


def test_tools_never_shell_out() -> None:
    sources = [
        p.read_text(encoding="utf-8") for p in (ROOT / "src/cloud_native_k8s_ai/tools").glob("*.py")
    ]
    for banned in ("subprocess", "os.system", "socket", "urllib", "httpx"):
        assert all(banned not in s for s in sources), banned


def test_typed_bundle_from_chart_matches_compile(chart: Chart, rendered: RenderedChart) -> None:
    stack = validate_values(chart, rendered.values)
    compiled = AIStackGenerator(stack.settings, stack.spec).compile()
    bundle = rendered.bundle()
    # Pod specs are identical; only labels differ (Helm owns managed-by on the chart side).
    for ours, theirs in zip(bundle.workloads(), compiled.workloads(), strict=True):
        assert ours.metadata.name == theirs.metadata.name
        assert ours.spec.template.spec == theirs.spec.template.spec
        assert ours.spec.selector == theirs.spec.selector
    sts = bundle.get(StatefulSet, QDRANT).spec
    assert (
        sts.volume_claim_templates == compiled.get(StatefulSet, QDRANT).spec.volume_claim_templates
    )
    assert {p.metadata.name for p in bundle.of_kind(NetworkPolicy)} == {
        p.metadata.name for p in compiled.of_kind(NetworkPolicy)
    }
    assert len(list(yaml.safe_load_all(rendered.to_yaml()))) == len(compiled)
