"""Offline Go ``text/template`` engine with the Sprig function subset Helm charts rely on.

Covers what a production chart uses: actions with ``{{-``/``-}}`` whitespace trimming,
comments, pipelines, variables, ``if``/``else if``/``with``/``range``/``define``/``template``
and Helm's ``include``. Value semantics follow Helm rather than Python:

* numbers read from values files are float64 (``helm_numbers``), so ``printf "%d"`` on one
  renders ``%!d(float64=...)`` and ``eq`` against an int literal fails, exactly as in Helm;
* a missing map key renders empty, or fails in strict mode (``helm lint --strict``);
* ``Struct`` values (``.Chart``) are Go structs: an unknown field is always an error.

Parse and execution failures raise ``TemplateError`` with the template name and line.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Collection, Iterator, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Final, cast

import yaml

from cloud_native_k8s_ai.core.errors import ManifestRenderError

MAX_INCLUDE_DEPTH: Final = 100


class TemplateError(ManifestRenderError):
    """A template failed to parse or execute; the message starts like Go's ``template:``."""

    def __init__(self, message: str, *, template: str | None = None, line: int | None = None):
        self.template = template
        self.line = line
        where = (
            "" if template is None else f"{template}:" if line is None else f"{template}:{line}:"
        )
        super().__init__(f"template: {where} {message}" if where else f"template: {message}")


class _ExecError(Exception):
    """Execution failure without a location; the executor adds template name and line."""


@dataclass(frozen=True, slots=True)
class Struct:
    """A Go struct value: unknown fields are an error instead of rendering empty."""

    type_name: str
    fields: Mapping[str, Any]


# ---------------------------------------------------------------------------
# Go value semantics
# ---------------------------------------------------------------------------
def helm_numbers(value: Any) -> Any:
    """Values as Helm sees them: every number from a values file is a float64."""
    if isinstance(value, dict):
        return {k: helm_numbers(v) for k, v in value.items()}
    if isinstance(value, list):
        return [helm_numbers(v) for v in value]
    if isinstance(value, int) and not isinstance(value, bool):
        return float(value)
    return value


def go_float(value: float) -> str:
    """``strconv.FormatFloat(v, 'g', -1, 64)``: ``6333``, ``0.5``, ``1e+06``."""
    if not math.isfinite(value):
        return "NaN" if math.isnan(value) else "+Inf" if value > 0 else "-Inf"
    if value == 0:
        return "0"
    sign, digit_tuple, exponent = Decimal(repr(value)).normalize().as_tuple()
    digits = "".join(map(str, digit_tuple))
    point = len(digits) + cast("int", exponent)  # decimal point position (finite value)
    prefix = "-" if sign else ""
    if not -4 <= point - 1 < 6:  # noqa: PLR2004 - Go switches to %e outside [-4, 6)
        mantissa = digits[0] + (f".{digits[1:]}" if len(digits) > 1 else "")
        return f"{prefix}{mantissa}e{'+' if point - 1 >= 0 else '-'}{abs(point - 1):02d}"
    if point <= 0:
        return f"{prefix}0.{'0' * -point}{digits}"
    if point >= len(digits):
        return f"{prefix}{digits}{'0' * (point - len(digits))}"
    return f"{prefix}{digits[:point]}.{digits[point:]}"


def format_value(value: Any) -> str:  # noqa: PLR0911 - one case per Go kind
    """``fmt.Sprint`` / ``%v`` formatting of a template value."""
    match value:
        case None:
            return "<nil>"
        case bool():
            return "true" if value else "false"
        case float():
            return go_float(value)
        case list():
            return "[" + " ".join(format_value(v) for v in value) + "]"
        case dict():
            return "map[" + " ".join(f"{k}:{format_value(value[k])}" for k in sorted(value)) + "]"
        case Struct():
            return "{" + " ".join(format_value(v) for v in value.fields.values()) + "}"
        case _:
            return str(value)


_GO_TYPES: Final = (
    (bool, "bool"),  # before int: bool is an int subclass
    (int, "int"),
    (float, "float64"),
    (str, "string"),
    (list, "[]interface {}"),
    (dict, "map[string]interface {}"),
)


def go_type(value: Any) -> str:
    """Go type name of a template value, as it appears in Go error messages."""
    if value is None:
        return "<nil>"
    if isinstance(value, Struct):
        return value.type_name
    return next((name for kind, name in _GO_TYPES if isinstance(value, kind)), "unknown")


def is_true(value: Any) -> bool:
    """Go template truth: false, 0, nil and empty strings/lists/maps are false."""
    if value is None:
        return False
    if isinstance(value, str | list | dict):
        return len(value) > 0
    if isinstance(value, int | float):
        return value != 0
    return True


_QUOTE_ESCAPES: Final = {
    '"': '\\"',
    "\\": "\\\\",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    "\a": "\\a",
    "\b": "\\b",
    "\f": "\\f",
    "\v": "\\v",
}


def go_quote(text: str) -> str:
    """``strconv.Quote``: double quotes, Go escapes for control characters."""
    escaped = (
        _QUOTE_ESCAPES.get(c) or (f"\\x{ord(c):02x}" if ord(c) < 0x20 or ord(c) == 0x7F else c)  # noqa: PLR2004
        for c in text
    )
    return '"' + "".join(escaped) + '"'


# ---------------------------------------------------------------------------
# Functions (Go builtins + Sprig/Helm subset)
# ---------------------------------------------------------------------------
def _expect_str(value: Any, func: str) -> str:
    if not isinstance(value, str):
        raise _ExecError(
            f"error calling {func}: wrong type for value; expected string; got {go_type(value)}"
        )
    return value


def _expect_int(value: Any, func: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise _ExecError(
            f"error calling {func}: wrong type for value; expected int; got {go_type(value)}"
        )
    return value


def _expect_map(value: Any, func: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _ExecError(
            f"error calling {func}: wrong type for value; "
            f"expected map[string]interface {{}}; got {go_type(value)}"
        )
    return value


def _strval(value: Any) -> str:
    return value if isinstance(value, str) else format_value(value)


def _kind(value: Any) -> str:
    if value is None:
        return "nil"
    if isinstance(value, bool | int | float | str):
        return go_type(value)
    return "complex"


def _equal(func: str, first: Any, *others: Any) -> bool:
    if _kind(first) == "complex" or any(_kind(o) == "complex" for o in others):
        raise _ExecError(f"error calling {func}: invalid type for comparison")
    for other in others:
        if _kind(first) != _kind(other):
            if first is None or other is None:
                continue
            raise _ExecError(f"error calling {func}: incompatible types for comparison")
        if first == other:
            return True
    return False


def _compare(func: str, left: Any, right: Any) -> int:
    kinds = {_kind(left), _kind(right)}
    if not kinds <= {"int", "float64", "string"}:
        raise _ExecError(f"error calling {func}: invalid type for comparison")
    if len(kinds) > 1:
        raise _ExecError(f"error calling {func}: incompatible types for comparison")
    return int(left > right) - int(left < right)


def _eq(first: Any, *others: Any) -> bool:
    return _equal("eq", first, *others)


def _ne(left: Any, right: Any) -> bool:
    return not _equal("ne", left, right)


def _lt(left: Any, right: Any) -> bool:
    return _compare("lt", left, right) < 0


def _le(left: Any, right: Any) -> bool:
    return _compare("le", left, right) <= 0


def _gt(left: Any, right: Any) -> bool:
    return _compare("gt", left, right) > 0


def _ge(left: Any, right: Any) -> bool:
    return _compare("ge", left, right) >= 0


def _not(value: Any) -> bool:
    return not is_true(value)


def _len(value: Any) -> int:
    if not isinstance(value, str | list | dict):
        raise _ExecError(f"error calling len: len of type {go_type(value)}")
    return len(value)


def _index(item: Any, *keys: Any) -> Any:
    for key in keys:
        match item:
            case list():
                if not isinstance(key, int) or isinstance(key, bool):
                    raise _ExecError(
                        f"error calling index: cannot index slice with type {go_type(key)}"
                    )
                if not 0 <= key < len(item):
                    raise _ExecError(f"error calling index: index out of range: {key}")
                item = item[key]
            case dict():
                item = item.get(_expect_str(key, "index"))
            case None:
                raise _ExecError("error calling index: index of untyped nil")
            case _:
                raise _ExecError(f"error calling index: can't index item of type {go_type(item)}")
    return item


def _sprint(*values: Any) -> str:
    """``fmt.Sprint``: a space between operands when neither is a string."""
    parts: list[str] = []
    for i, value in enumerate(values):
        if i and not isinstance(value, str) and not isinstance(values[i - 1], str):
            parts.append(" ")
        parts.append(format_value(value))
    return "".join(parts)


_DIRECTIVE_RE: Final = re.compile(r"%(\.[0-9]+)?(.?)")


def _verb(verb: str, precision: str | None, value: Any) -> str:  # noqa: PLR0911 - one per verb
    match verb:
        case "v":
            return format_value(value)
        case "s" if isinstance(value, str):
            return value
        case "q" if isinstance(value, str):
            return go_quote(value)
        case "d" if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
        case "t" if isinstance(value, bool):
            return format_value(value)
        case "f" if isinstance(value, float):
            return f"{value:.{int(precision[1:]) if precision else 6}f}"
    bad = "<nil>" if value is None else f"{go_type(value)}={format_value(value)}"
    return f"%!{verb}({bad})"


def _sprintf(template: Any, *values: Any) -> str:
    """``fmt.Sprintf`` for ``%v %s %q %d %t %f %%``, with Go's ``%!verb(...)`` markers."""
    text = _expect_str(template, "printf")
    out: list[str] = []
    pos = arg = 0
    for match in _DIRECTIVE_RE.finditer(text):
        out.append(text[pos : match.start()])
        pos = match.end()
        precision, verb = match.groups()
        if verb == "%" and precision is None:
            out.append("%")
            continue
        if verb not in {"v", "s", "q", "d", "t", "f"} or (precision and verb != "f"):
            raise _ExecError(
                f"error calling printf: unsupported directive %{precision or ''}{verb}"
            )
        if arg >= len(values):
            out.append(f"%!{verb}(MISSING)")
            continue
        out.append(_verb(verb, precision, values[arg]))
        arg += 1
    out.append(text[pos:])
    if arg < len(values):
        extra = ", ".join(f"{go_type(v)}={format_value(v)}" for v in values[arg:])
        out.append(f"%!(EXTRA {extra})")
    return "".join(out)


def _quote(*values: Any) -> str:
    return " ".join(go_quote(_strval(v)) for v in values if v is not None)


def _default(fallback: Any, *given: Any) -> Any:
    return fallback if not given or not is_true(given[0]) else given[0]


def _required(message: Any, value: Any) -> Any:
    if value is None or value == "":
        raise _ExecError(_expect_str(message, "required"))
    return value


def _fail(message: Any) -> Any:
    raise _ExecError(_expect_str(message, "fail"))


def _yaml_ready(value: Any) -> Any:
    """What ``sigs.k8s.io/yaml`` sees after its JSON round trip: integral floats are ints."""
    if isinstance(value, dict):
        return {k: _yaml_ready(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_yaml_ready(v) for v in value]
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _to_yaml(value: Any) -> str:
    """Helm's ``toYaml``: sorted keys, no trailing newline, errors swallowed to ``""``."""
    try:
        text = yaml.safe_dump(
            _yaml_ready(value), sort_keys=True, default_flow_style=False, width=10_000
        )
    except yaml.YAMLError:
        return ""
    text = text.removesuffix("...\n")
    return text.removesuffix("\n")


def _indent(width: Any, text: Any) -> str:
    pad = " " * _expect_int(width, "indent")
    return pad + _expect_str(text, "indent").replace("\n", "\n" + pad)


def _nindent(width: Any, text: Any) -> str:
    return "\n" + _indent(width, text)


def _trunc(count: Any, text: Any) -> str:
    n, s = _expect_int(count, "trunc"), _expect_str(text, "trunc")
    if n < 0:
        return s[len(s) + n :] if len(s) + n > 0 else s
    return s[:n]


def _trim_suffix(suffix: Any, text: Any) -> str:
    return _expect_str(text, "trimSuffix").removesuffix(_expect_str(suffix, "trimSuffix"))


def _replace(old: Any, new: Any, text: Any) -> str:
    return _expect_str(text, "replace").replace(
        _expect_str(old, "replace"), _expect_str(new, "replace")
    )


def _has_suffix(suffix: Any, text: Any) -> bool:
    return _expect_str(text, "hasSuffix").endswith(_expect_str(suffix, "hasSuffix"))


def _has_key(mapping: Any, key: Any) -> bool:
    return _expect_str(key, "hasKey") in _expect_map(mapping, "hasKey")


def _get(mapping: Any, key: Any) -> Any:
    return _expect_map(mapping, "get").get(_expect_str(key, "get"), "")


def _set(mapping: Any, key: Any, value: Any) -> dict[str, Any]:
    target = _expect_map(mapping, "set")
    target[_expect_str(key, "set")] = value
    return target


def _dict(*pairs: Any) -> dict[str, Any]:
    keys, values = pairs[::2], [*pairs[1::2], ""]
    return {_strval(k): v for k, v in zip(keys, values, strict=False)}


def _list(*values: Any) -> list[Any]:
    return list(values)


def _append(items: Any, value: Any) -> list[Any]:
    if not isinstance(items, list):
        raise _ExecError(f"error calling append: Cannot push on type {go_type(items)}")
    return [*items, value]


def _join(separator: Any, values: Any) -> str:
    sep = _expect_str(separator, "join")
    if values is None:
        return ""
    if isinstance(values, list):
        return sep.join(_strval(v) for v in values if v is not None)
    return _strval(values)


_ZERO_DECIMAL_RE: Final = re.compile(r"^(-?[0-9]+)\.0*$")


def _to_int(value: Any) -> int:
    """``cast.ToInt``: lenient, ``0`` on anything unparseable."""
    match value:
        case bool() | int():
            return int(value)
        case float():
            return 0 if math.isnan(value) or math.isinf(value) else int(value)
        case str():
            text = _ZERO_DECIMAL_RE.sub(r"\1", value)
            try:
                return int(text, 0)
            except ValueError:
                return 0
        case _:
            return 0


def _mul(first: Any, *others: Any) -> int:
    product = _to_int(first)
    for other in others:
        product *= _to_int(other)
    return product


def _empty(value: Any) -> bool:
    return not is_true(value)


@dataclass(frozen=True, slots=True)
class _Func:
    fn: Callable[..., Any]
    min_args: int
    max_args: int | None


FUNCTIONS: Final[Mapping[str, _Func]] = {
    # Go builtins (``and``/``or`` are lazy and live in the executor)
    "not": _Func(_not, 1, 1),
    "len": _Func(_len, 1, 1),
    "index": _Func(_index, 1, None),
    "print": _Func(_sprint, 0, None),
    "printf": _Func(_sprintf, 1, None),
    "eq": _Func(_eq, 2, None),
    "ne": _Func(_ne, 2, 2),
    "lt": _Func(_lt, 2, 2),
    "le": _Func(_le, 2, 2),
    "gt": _Func(_gt, 2, 2),
    "ge": _Func(_ge, 2, 2),
    # Sprig / Helm
    "quote": _Func(_quote, 0, None),
    "default": _Func(_default, 1, 2),
    "required": _Func(_required, 2, 2),
    "fail": _Func(_fail, 1, 1),
    "toYaml": _Func(_to_yaml, 1, 1),
    "indent": _Func(_indent, 2, 2),
    "nindent": _Func(_nindent, 2, 2),
    "trunc": _Func(_trunc, 2, 2),
    "trimSuffix": _Func(_trim_suffix, 2, 2),
    "replace": _Func(_replace, 3, 3),
    "hasSuffix": _Func(_has_suffix, 2, 2),
    "hasKey": _Func(_has_key, 2, 2),
    "get": _Func(_get, 2, 2),
    "set": _Func(_set, 3, 3),
    "dict": _Func(_dict, 0, None),
    "list": _Func(_list, 0, None),
    "append": _Func(_append, 2, 2),
    "join": _Func(_join, 2, 2),
    "int": _Func(_to_int, 1, 1),
    "int64": _Func(_to_int, 1, 1),
    "mul": _Func(_mul, 1, None),
    "toString": _Func(_strval, 1, 1),
    "empty": _Func(_empty, 1, 1),
}
_EXECUTOR_FUNCTIONS: Final = frozenset({"and", "or", "include"})


# ---------------------------------------------------------------------------
# Lexer
# ---------------------------------------------------------------------------
_TOKEN_RE: Final = re.compile(
    r"""(?P<space>\s+)
      |(?P<string>"(?:[^"\\\n]|\\.)*")
      |(?P<raw>`[^`]*`)
      |(?P<number>-?(?:0[xX][0-9a-fA-F]+|[0-9]+(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?))
      |(?P<field>(?:\.[A-Za-z_][A-Za-z0-9_]*)+)
      |(?P<var>\$[A-Za-z0-9_]*)
      |(?P<ident>[A-Za-z_][A-Za-z0-9_]*)
      |(?P<punct>:=|[()|,=.])""",
    re.VERBOSE,
)
_ESCAPE_RE: Final = re.compile(r"\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|[0-7]{3}|.)")
_SIMPLE_ESCAPES: Final = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "v": "\v",
    "\\": "\\",
    '"': '"',
    "'": "'",
}


@dataclass(frozen=True, slots=True)
class _Tok:
    kind: str
    text: str
    pos: int
    end: int


@dataclass(frozen=True, slots=True)
class _Text:
    text: str


@dataclass(frozen=True, slots=True)
class _Action:
    tokens: tuple[_Tok, ...]
    line: int


def _close_comment(src: str, pos: int) -> tuple[int, bool] | None:
    if src.startswith("}}", pos):
        return pos + 2, False
    if src[pos : pos + 1].isspace() and src.startswith("-}}", pos + 1):
        return pos + 4, True
    return None


def _lex(name: str, src: str) -> list[_Text | _Action]:
    items: list[_Text | _Action] = []
    pos, trim_next = 0, False
    while True:
        start = src.find("{{", pos)
        text = src[pos:] if start < 0 else src[pos:start]
        if trim_next:
            text = text.lstrip()
        if start < 0:
            if text:
                items.append(_Text(text))
            return items
        line = src.count("\n", 0, start) + 1
        k = start + 2
        if src.startswith("-", k) and src[k + 1 : k + 2].isspace():
            text, k = text.rstrip(), k + 2
        if text:
            items.append(_Text(text))
        if src.startswith("/*", k):
            end = src.find("*/", k + 2)
            closed = None if end < 0 else _close_comment(src, end + 2)
            if closed is None:
                raise TemplateError("unclosed comment", template=name, line=line)
            pos, trim_next = closed
            continue
        action, pos, trim_next = _lex_action(name, src, k, line)
        items.append(action)


def _lex_action(name: str, src: str, pos: int, line: int) -> tuple[_Action, int, bool]:
    """Tokens of one action starting at ``pos``; returns the action, end offset, right trim."""
    tokens: list[_Tok] = []
    while True:
        if src.startswith("}}", pos):
            return _Action(tuple(tokens), line), pos + 2, False
        if src.startswith("-}}", pos) and src[pos - 1].isspace():
            return _Action(tuple(tokens), line), pos + 3, True
        found = _TOKEN_RE.match(src, pos)
        if found is None:
            problem = "unclosed action" if pos >= len(src) else f"unexpected {src[pos]!r} in action"
            raise TemplateError(problem, template=name, line=line)
        if found.lastgroup != "space":
            tokens.append(_Tok(found.lastgroup or "", found.group(), pos, found.end()))
        pos = found.end()


def _unquote(tok: _Tok) -> str:
    if tok.kind == "raw":
        return tok.text[1:-1]

    def replace(match: re.Match[str]) -> str:
        code = match.group(1)
        if code in _SIMPLE_ESCAPES:
            return _SIMPLE_ESCAPES[code]
        if code[0] in "xu" and len(code) > 1:
            return chr(int(code[1:], 16))
        if len(code) == 3 and code.isdigit():  # noqa: PLR2004 - octal escape \NNN
            return chr(int(code, 8))
        raise ValueError(f"unknown escape sequence \\{code}")

    return _ESCAPE_RE.sub(replace, tok.text[1:-1])


def _declaration_end(tokens: Sequence[_Tok]) -> int | None:
    """Index of ``:=``/``=`` when the pipeline opens with ``$a[, $b] :=``, else ``None``."""
    index = 0
    while index + 1 < len(tokens) and tokens[index].kind == "var":
        follower = tokens[index + 1]
        if follower.kind != "punct" or follower.text not in {":=", "=", ","}:
            return None
        if follower.text != ",":
            return index + 1
        index += 2
    return None


def _keyword(action: _Action) -> str:
    head = action.tokens[0]
    return head.text if head.kind == "ident" else ""


def _matching_paren(tokens: Sequence[_Tok], start: int) -> int | None:
    depth = 0
    for index in range(start, len(tokens)):
        tok = tokens[index]
        if tok.kind == "punct" and tok.text in "()":
            depth += 1 if tok.text == "(" else -1
            if depth == 0:
                return index
    return None


# ---------------------------------------------------------------------------
# Parse tree
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class _Const:
    value: Any


@dataclass(frozen=True, slots=True)
class _Dot:
    pass


@dataclass(frozen=True, slots=True)
class _Field:
    chain: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Variable:
    name: str
    chain: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Ident:
    name: str


@dataclass(frozen=True, slots=True)
class _Paren:
    pipe: _Pipe
    chain: tuple[str, ...]


type _Operand = _Const | _Dot | _Field | _Variable | _Ident | _Paren


@dataclass(frozen=True, slots=True)
class _Pipe:
    decl: tuple[str, ...]
    assign: bool
    cmds: tuple[tuple[_Operand, ...], ...]
    line: int


@dataclass(frozen=True, slots=True)
class _TextNode:
    text: str


@dataclass(frozen=True, slots=True)
class _Output:
    pipe: _Pipe


@dataclass(frozen=True, slots=True)
class _Branch:
    kind: str  # "if" | "with"
    pipe: _Pipe
    body: tuple[_Node, ...]
    alt: tuple[_Node, ...]


@dataclass(frozen=True, slots=True)
class _Range:
    pipe: _Pipe
    body: tuple[_Node, ...]
    alt: tuple[_Node, ...]


@dataclass(frozen=True, slots=True)
class _Call:
    name: str
    pipe: _Pipe | None
    line: int


type _Node = _TextNode | _Output | _Branch | _Range | _Call


class _Parser:
    def __init__(self, name: str, items: Sequence[_Text | _Action], funcs: Collection[str]):
        self.name = name
        self.items = items
        self.funcs = funcs
        self.index = 0
        self.vars: list[str] = ["$"]
        self.defines: dict[str, tuple[_Node, ...]] = {}

    def error(self, message: str, line: int) -> TemplateError:
        return TemplateError(message, template=self.name, line=line)

    def parse(self) -> tuple[tuple[_Node, ...], dict[str, tuple[_Node, ...]]]:
        body, _ = self._list(None)
        return body, self.defines

    def _list(self, opener: _Action | None) -> tuple[tuple[_Node, ...], _Action]:
        """Nodes up to the matching ``end``/``else``; at top level (no opener) up to EOF."""
        nodes: list[_Node] = []
        while self.index < len(self.items):
            item = self.items[self.index]
            self.index += 1
            if isinstance(item, _Text):
                nodes.append(_TextNode(item.text))
                continue
            if not item.tokens:
                raise self.error("missing value for command", item.line)
            keyword = _keyword(item)
            if keyword in {"end", "else"}:
                if opener is None:
                    raise self.error(f"unexpected {{{{{keyword}}}}}", item.line)
                return tuple(nodes), item
            if keyword == "define" and opener is not None:
                raise self.error("define is only allowed at the top level", item.line)
            node = self._statement(keyword, item)
            if node is not None:
                nodes.append(node)
        if opener is not None:
            raise self.error(
                f"unexpected EOF: {{{{{opener.tokens[0].text}}}}} not closed", opener.line
            )
        return tuple(nodes), _Action((), 0)

    def _statement(self, keyword: str, action: _Action) -> _Node | None:
        match keyword:
            case "if" | "with":
                return self._branch(keyword, action)
            case "range":
                return self._range(action)
            case "define":
                self._define(action)
                return None
            case "template":
                return self._template(action)
            case "block" | "break" | "continue":
                raise self.error(f"{{{{{keyword}}}}} is not supported offline", action.line)
            case _:
                return _Output(self._pipe(action.tokens, action.line, max_decl=1))

    def _closed(self, opener: _Action) -> tuple[tuple[_Node, ...], tuple[_Node, ...], _Action]:
        """Body, plain ``else`` body (if any) and the action that ended the body."""
        body, stop = self._list(opener)
        if stop.tokens[0].text == "end" or len(stop.tokens) > 1:
            return body, (), stop
        alt, end = self._list(stop)
        if end.tokens[0].text != "end":
            raise self.error("expected {{end}}, found {{else}}", end.line)
        return body, alt, end

    def _branch(self, kind: str, action: _Action) -> _Branch:
        mark = len(self.vars)
        pipe = self._pipe(action.tokens[1:], action.line, max_decl=1)
        body, alt, stop = self._closed(action)
        if stop.tokens[0].text == "else":  # ``else if`` / ``else with`` chain
            nested = stop.tokens[1]
            if nested.kind != "ident" or nested.text not in {"if", "with"}:
                raise self.error(f"unexpected {nested.text!r} after else", stop.line)
            alt = (self._branch(nested.text, _Action(stop.tokens[1:], stop.line)),)
        del self.vars[mark:]
        return _Branch(kind, pipe, body, alt)

    def _range(self, action: _Action) -> _Range:
        mark = len(self.vars)
        pipe = self._pipe(action.tokens[1:], action.line, max_decl=2)
        if pipe.assign:
            raise self.error("range can only declare variables with :=", action.line)
        body, alt, stop = self._closed(action)
        if stop.tokens[0].text == "else":
            raise self.error("unexpected tokens after {{else}} in range", stop.line)
        del self.vars[mark:]
        return _Range(pipe, body, alt)

    def _define(self, action: _Action) -> None:
        args = action.tokens[1:]
        if len(args) != 1 or args[0].kind not in {"string", "raw"}:
            raise self.error("define expects exactly one quoted template name", action.line)
        name = _unquote(args[0])
        saved, self.vars = self.vars, ["$"]
        body, stop = self._list(action)
        self.vars = saved
        if stop.tokens[0].text != "end":
            raise self.error(f"unexpected {{{{else}}}} in define {name!r}", stop.line)
        if name in self.defines:
            raise self.error(f"template {name!r} defined twice", action.line)
        self.defines[name] = body

    def _template(self, action: _Action) -> _Call:
        args = action.tokens[1:]
        if not args or args[0].kind not in {"string", "raw"}:
            raise self.error("template expects a quoted template name", action.line)
        pipe = self._pipe(args[1:], action.line, max_decl=0) if len(args) > 1 else None
        return _Call(_unquote(args[0]), pipe, action.line)

    # -- pipelines ------------------------------------------------------
    def _pipe(self, tokens: Sequence[_Tok], line: int, *, max_decl: int) -> _Pipe:
        decl: tuple[str, ...] = ()
        assign = False
        split = _declaration_end(tokens)
        if split is not None:
            decl = tuple(t.text for t in tokens[:split:2])
            assign = tokens[split].text == "="
            if len(decl) > max_decl:
                raise self.error(f"too many declarations in {' '.join(decl)}", line)
            if assign:
                for var in decl:
                    self._check_var(var, line)
            tokens = tokens[split + 1 :]
        cmds: list[tuple[_Operand, ...]] = []
        current: list[_Operand] = []
        i = 0
        while i < len(tokens):
            if tokens[i].kind == "punct" and tokens[i].text == "|":
                cmds.append(self._command(current, len(cmds), line))
                current = []
                i += 1
                continue
            operand, i = self._operand(tokens, i, line)
            current.append(operand)
        cmds.append(self._command(current, len(cmds), line))
        if not assign:
            self.vars.extend(decl)
        return _Pipe(decl, assign, tuple(cmds), line)

    def _command(self, args: list[_Operand], stage: int, line: int) -> tuple[_Operand, ...]:
        if not args:
            raise self.error("missing value for command", line)
        head = args[0]
        if not isinstance(head, _Ident):
            if head == _Const(None):
                raise self.error("nil is not a command", line)
            if len(args) > 1:
                raise self.error("can't give argument to non-function", line)
            if stage:
                raise self.error(f"non executable command in pipeline stage {stage + 1}", line)
        return tuple(args)

    def _check_var(self, name: str, line: int) -> None:
        if name not in self.vars:
            raise self.error(f'undefined variable "{name}"', line)

    def _chain(self, tokens: Sequence[_Tok], i: int) -> tuple[tuple[str, ...], int]:
        """Field chain glued to the previous token (``$x.Name``, ``(...).Name``)."""
        if i < len(tokens) and tokens[i].kind == "field" and tokens[i].pos == tokens[i - 1].end:
            return tuple(tokens[i].text[1:].split(".")), i + 1
        return (), i

    def _operand(self, tokens: Sequence[_Tok], i: int, line: int) -> tuple[_Operand, int]:  # noqa: PLR0911
        tok = tokens[i]
        match tok.kind, tok.text:
            case "field", text:
                return _Field(tuple(text[1:].split("."))), i + 1
            case "var", name:
                self._check_var(name, line)
                chain, nxt = self._chain(tokens, i + 1)
                return _Variable(name, chain), nxt
            case (("string" | "raw"), _):
                try:
                    return _Const(_unquote(tok)), i + 1
                except ValueError as exc:
                    raise self.error(str(exc), line) from None
            case "number", text:
                is_int = re.fullmatch(r"-?(?:0[xX][0-9a-fA-F]+|[0-9]+)", text)
                return _Const(int(text, 0) if is_int else float(text)), i + 1
            case "ident", ("true" | "false" | "nil") as word:
                return _Const({"true": True, "false": False, "nil": None}[word]), i + 1
            case "ident", name:
                if name not in self.funcs:
                    raise self.error(f'function "{name}" not defined', line)
                return _Ident(name), i + 1
            case "punct", ".":
                return _Dot(), i + 1
            case "punct", "(":
                close = _matching_paren(tokens, i)
                if close is None:
                    raise self.error("unclosed left paren", line)
                inner = self._pipe(tokens[i + 1 : close], line, max_decl=0)
                chain, nxt = self._chain(tokens, close + 1)
                return _Paren(inner, chain), nxt
        raise self.error(f"unexpected {tok.text!r} in operand", line)


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------
_MISSING: Final = object()


class _Exec:
    def __init__(self, templates: TemplateSet, name: str, depth: int, data: Any) -> None:
        self.templates = templates
        self.name = name
        self.depth = depth
        self.vars: list[tuple[str, Any]] = [("$", data)]

    def run(self, nodes: Sequence[_Node], dot: Any, out: list[str]) -> None:
        for node in nodes:
            match node:
                case _TextNode(text):
                    out.append(text)
                case _Output(pipe):
                    value = self.pipe(pipe, dot)
                    if not pipe.decl:
                        out.append("" if value is None else format_value(value))
                case _Branch(kind, pipe, body, alt):
                    mark = len(self.vars)
                    value = self.pipe(pipe, dot)
                    if is_true(value):
                        self.run(body, value if kind == "with" else dot, out)
                    else:
                        self.run(alt, dot, out)
                    del self.vars[mark:]
                case _Range():
                    self.range(node, dot, out)
                case _:  # _Call: {{ template "name" pipeline }}
                    data = None if node.pipe is None else self.pipe(node.pipe, dot)
                    try:
                        out.append(self.templates.run(node.name, data, self.depth + 1))
                    except _ExecError as exc:
                        raise TemplateError(str(exc), template=self.name, line=node.line) from None

    def range(self, node: _Range, dot: Any, out: list[str]) -> None:
        mark = len(self.vars)
        value = self.pipe(node.pipe, dot, bind=False)
        match value:
            case None:
                items: list[tuple[Any, Any]] = []
            case list():
                items = list(enumerate(value))
            case dict():
                items = [(k, value[k]) for k in sorted(value)]
            case _:
                raise TemplateError(
                    f"range can't iterate over {format_value(value)}",
                    template=self.name,
                    line=node.pipe.line,
                )
        if not items:
            self.run(node.alt, dot, out)
        for key, element in items:
            del self.vars[mark:]
            bound = (key, element) if len(node.pipe.decl) == 2 else (element,)  # noqa: PLR2004
            self.vars.extend(zip(node.pipe.decl, bound, strict=False))
            self.run(node.body, element, out)
        del self.vars[mark:]

    def pipe(self, pipe: _Pipe, dot: Any, *, bind: bool = True) -> Any:
        value: Any = _MISSING
        try:
            for cmd in pipe.cmds:
                value = self.command(cmd, dot, value)
        except _ExecError as exc:
            raise TemplateError(str(exc), template=self.name, line=pipe.line) from None
        if bind and pipe.decl:
            name = pipe.decl[0]
            if pipe.assign:
                index = max(i for i, (n, _) in enumerate(self.vars) if n == name)
                self.vars[index] = (name, value)
            else:
                self.vars.append((name, value))
        return value

    def command(self, cmd: tuple[_Operand, ...], dot: Any, final: Any) -> Any:
        head = cmd[0]
        if isinstance(head, _Ident):
            return self.call(head.name, cmd[1:], dot, final)
        return self.operand(head, dot)

    def call(self, name: str, args: Sequence[_Operand], dot: Any, final: Any) -> Any:
        if name in {"and", "or"}:
            if not args and final is _MISSING:
                raise _ExecError(f"wrong number of args for {name}: want at least 1 got 0")
            value: Any = None
            for value in self._lazy(args, dot, final):
                if is_true(value) != (name == "and"):
                    return value
            return value
        values = [self.operand(arg, dot) for arg in args]
        if final is not _MISSING:
            values.append(final)
        if name == "include":
            if len(values) != 2:  # noqa: PLR2004
                raise _ExecError(f"wrong number of args for include: want 2 got {len(values)}")
            return self.templates.run(_expect_str(values[0], "include"), values[1], self.depth + 1)
        func = FUNCTIONS[name]
        if len(values) < func.min_args or (
            func.max_args is not None and len(values) > func.max_args
        ):
            want = (
                f"{func.min_args}"
                if func.max_args == func.min_args
                else f"at least {func.min_args}"
                if func.max_args is None
                else f"{func.min_args}-{func.max_args}"
            )
            raise _ExecError(f"wrong number of args for {name}: want {want} got {len(values)}")
        return func.fn(*values)

    def _lazy(self, args: Sequence[_Operand], dot: Any, final: Any) -> Iterator[Any]:
        for arg in args:
            yield self.operand(arg, dot)
        if final is not _MISSING:
            yield final

    def operand(self, op: _Operand, dot: Any) -> Any:
        match op:
            case _Const(value):
                return value
            case _Dot():
                return dot
            case _Field(chain):
                return self.fields(dot, chain)
            case _Variable(name, chain):
                value = next(v for n, v in reversed(self.vars) if n == name)
                return self.fields(value, chain)
            case _Paren(pipe, chain):
                return self.fields(self.pipe(pipe, dot), chain)
            case _:  # _Ident: a function used as an argument runs with no arguments
                return self.call(op.name, (), dot, _MISSING)

    def fields(self, value: Any, chain: Sequence[str]) -> Any:
        for name in chain:
            match value:
                case dict():
                    if name not in value and self.templates.strict:
                        raise _ExecError(f'map has no entry for key "{name}"')
                    value = value.get(name)
                case Struct():
                    if name not in value.fields:
                        raise _ExecError(f"can't evaluate field {name} in type {value.type_name}")
                    value = value.fields[name]
                case None:
                    raise _ExecError(f"nil pointer evaluating interface {{}}.{name}")
                case _:
                    raise _ExecError(f"can't evaluate field {name} in type {go_type(value)}")
        return value


class TemplateSet:
    """Templates parsed together, sharing one ``define`` namespace (like one Helm chart).

    Each source is registered under its own name; ``define`` blocks anywhere in the set
    are visible to every template. Redefining a name is an error rather than last-wins.
    """

    def __init__(self, sources: Mapping[str, str], *, strict: bool = False) -> None:
        self.strict = strict
        self._templates: dict[str, tuple[_Node, ...]] = {}
        known = frozenset(FUNCTIONS) | _EXECUTOR_FUNCTIONS
        for name in sorted(sources):
            body, defines = _Parser(name, _lex(name, sources[name]), known).parse()
            for template, nodes in ((name, body), *defines.items()):
                if template in self._templates:
                    raise TemplateError(
                        f"template {template!r} defined more than once", template=name
                    )
                self._templates[template] = nodes

    def __contains__(self, name: object) -> bool:
        return name in self._templates

    def execute(self, name: str, data: Any) -> str:
        """Render template ``name`` with ``data`` as both ``.`` and ``$``."""
        try:
            return self.run(name, data, 0)
        except _ExecError as exc:
            raise TemplateError(str(exc)) from None

    def run(self, name: str, data: Any, depth: int) -> str:
        if name not in self._templates:
            raise _ExecError(f'no template "{name}" associated with this chart')
        if depth > MAX_INCLUDE_DEPTH:
            raise _ExecError(f"rendering template has a nested reference name: {name}")
        out: list[str] = []
        _Exec(self, name, depth, data).run(self._templates[name], data, out)
        return "".join(out)
