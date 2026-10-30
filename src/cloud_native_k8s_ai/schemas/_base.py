"""Shared base models and constrained primitives used by every infrastructure schema.

Quantity, name and CIDR primitives are validated ``str`` aliases: they keep the exact
Kubernetes / Terraform spelling on the wire, and ``cpu_millicores`` / ``memory_bytes``
convert them to integers wherever two values must be compared.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping
from decimal import Decimal
from typing import Annotated, Any, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)
from pydantic.alias_generators import to_camel

MAX_PORT = 65535

_BINARY_SUFFIXES = {"Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40, "Pi": 2**50, "Ei": 2**60}
_DECIMAL_SUFFIXES = {"k": 10**3, "M": 10**6, "G": 10**9, "T": 10**12, "P": 10**15, "E": 10**18}
_BYTE_MULTIPLIERS = {"": 1, **_BINARY_SUFFIXES, **_DECIMAL_SUFFIXES}

_CPU_RE = re.compile(r"^(?:(?P<milli>[0-9]+)m|(?P<cores>[0-9]+(?:\.[0-9]{1,3})?))$")
_BYTES_RE = re.compile(r"^(?P<num>[0-9]+(?:\.[0-9]+)?)(?P<suffix>Ki|Mi|Gi|Ti|Pi|Ei|k|M|G|T|P|E)?$")
_IMAGE_RE = re.compile(
    r"^(?:[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]+)?/)?"  # optional registry[:port]/
    r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*"
    r"(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}))?"
    r"(?:@(?P<digest>sha256:[a-f0-9]{64}))?$"
)


class InfraModel(BaseModel):
    """Immutable, strictly validated base for every infrastructure contract.

    Strict mode means no type coercion in Python mode (``"3"`` is not an ``int``).
    Sequences are tuples so instances stay immutable; over the wire use
    ``to_wire``/``from_wire``, where JSON arrays become tuples.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    def to_wire(self) -> dict[str, Any]:
        """Plain JSON-compatible dict (aliases applied, unset optionals omitted)."""
        data: dict[str, Any] = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        return data

    @classmethod
    def from_wire(cls, data: Mapping[str, Any]) -> Self:
        """Validate a plain dict (e.g. parsed YAML) with JSON-mode strictness."""
        return cls.model_validate_json(json.dumps(data))


class K8sModel(InfraModel):
    """Kubernetes-shaped contract: snake_case in Python, camelCase on the wire."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        validate_by_name=True,
        validate_by_alias=True,
        serialize_by_alias=True,
    )

    def to_k8s(self) -> dict[str, Any]:
        """Manifest dict exactly as the Kubernetes API expects it."""
        return self.to_wire()


# ---------------------------------------------------------------------------
# Quantities
# ---------------------------------------------------------------------------
def cpu_millicores(quantity: str) -> int:
    """Convert a CPU quantity (``"500m"``, ``"2"``, ``"1.5"``) to millicores."""
    match = _CPU_RE.match(quantity)
    if match is None:
        raise ValueError(f"invalid CPU quantity {quantity!r}: use millicores ('500m') or cores")
    if match["milli"] is not None:
        return int(match["milli"])
    return int(Decimal(match["cores"]) * 1000)


def memory_bytes(quantity: str) -> int:
    """Convert a byte quantity (``"512Mi"``, ``"2Gi"``, ``"1G"``) to a whole number of bytes."""
    match = _BYTES_RE.match(quantity)
    if match is None:
        raise ValueError(
            f"invalid byte quantity {quantity!r}: use Ki/Mi/Gi/Ti/Pi/Ei or k/M/G/T/P/E suffixes"
        )
    value = Decimal(match["num"]) * _BYTE_MULTIPLIERS[match["suffix"] or ""]
    if value != value.to_integral_value():
        raise ValueError(f"byte quantity {quantity!r} is not a whole number of bytes")
    return int(value)


def _positive_cpu(value: str) -> str:
    if cpu_millicores(value) <= 0:
        raise ValueError("CPU quantity must be greater than zero")
    return value


def _positive_bytes(value: str) -> str:
    if memory_bytes(value) <= 0:
        raise ValueError("byte quantity must be greater than zero")
    return value


CpuQuantity = Annotated[str, AfterValidator(_positive_cpu)]
"""Positive CPU quantity: ``"250m"``, ``"1"``, ``"1.5"``; at most millicore precision."""

MemoryQuantity = Annotated[str, AfterValidator(_positive_bytes)]
"""Positive byte quantity: ``"512Mi"``, ``"2Gi"``; lowercase ``m`` (millibytes) is rejected."""

StorageQuantity = MemoryQuantity
"""Positive volume size, same grammar as ``MemoryQuantity`` (e.g. ``"50Gi"``)."""


# ---------------------------------------------------------------------------
# Names, labels, ports
# ---------------------------------------------------------------------------
DNS1123Label = Annotated[
    str, StringConstraints(min_length=1, max_length=63, pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
]
"""RFC 1123 label: object names, namespaces, container and port-less volume names."""

DNS1123Subdomain = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=253,
        pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
    ),
]
"""RFC 1123 subdomain: storage class and secret names."""

LabelKey = Annotated[
    str,
    StringConstraints(
        max_length=317,
        pattern=(
            r"^(?:[a-z0-9]([-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*/)?"
            r"[A-Za-z0-9](?:[-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$"
        ),
    ),
]
"""Label / annotation key: optional DNS subdomain prefix, ``/``, then a 63-char name."""

LabelValue = Annotated[
    str,
    StringConstraints(
        max_length=63, pattern=r"^(?:[A-Za-z0-9](?:[-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?)?$"
    ),
]

Labels = dict[LabelKey, LabelValue]

Port = Annotated[int, Field(ge=1, le=MAX_PORT)]
"""TCP/UDP port number in ``1..65535``."""


def _has_letter(value: str) -> str:
    if not any(c.isalpha() for c in value):
        raise ValueError(f"port name {value!r} must contain at least one letter")
    return value


PortName = Annotated[
    str,
    StringConstraints(max_length=15, pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"),
    AfterValidator(_has_letter),
]
"""IANA service name used for named container ports (``http``, ``grpc``)."""

Protocol = Literal["TCP", "UDP", "SCTP"]

AbsolutePath = Annotated[str, StringConstraints(min_length=1, max_length=4096, pattern=r"^/")]


# ---------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------
def _pinned_image(value: str) -> str:
    match = _IMAGE_RE.match(value)
    if match is None:
        raise ValueError(f"invalid container image reference {value!r}")
    if match["tag"] is None and match["digest"] is None:
        raise ValueError(f"image {value!r} must be pinned by tag or sha256 digest")
    if match["tag"] == "latest":
        raise ValueError(f"image {value!r} uses the mutable ':latest' tag")
    return value


ImageRef = Annotated[str, AfterValidator(_pinned_image)]
"""Container image pinned by an explicit tag (never ``latest``) and/or a sha256 digest."""


# ---------------------------------------------------------------------------
# CIDRs
# ---------------------------------------------------------------------------
def network(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse a validated CIDR string into an ``ipaddress`` network."""
    return ipaddress.ip_network(cidr, strict=True)


def _cidr(value: str) -> str:
    try:
        return str(network(value))
    except ValueError as exc:
        raise ValueError(f"invalid CIDR {value!r}: {exc}") from exc


def _ipv4_cidr(value: str) -> str:
    if network(value).version != 4:  # noqa: PLR2004 - IP version number
        raise ValueError(f"{value!r} is not an IPv4 CIDR")
    return value


Cidr = Annotated[str, AfterValidator(_cidr)]
"""IPv4 or IPv6 network in CIDR notation, host bits clear; normalized (``10.0.0.0/16``)."""

IPv4Cidr = Annotated[str, AfterValidator(_cidr), AfterValidator(_ipv4_cidr)]


# ---------------------------------------------------------------------------
# Shared Kubernetes building blocks
# ---------------------------------------------------------------------------
class ObjectMeta(K8sModel):
    name: DNS1123Label
    namespace: DNS1123Label | None = None
    labels: Labels | None = None
    annotations: dict[LabelKey, str] | None = None


class LabelSelectorRequirement(K8sModel):
    key: LabelKey
    operator: Literal["In", "NotIn", "Exists", "DoesNotExist"]
    values: tuple[LabelValue, ...] = ()

    @model_validator(mode="after")
    def _values_match_operator(self) -> Self:
        needs_values = self.operator in {"In", "NotIn"}
        if needs_values and not self.values:
            raise ValueError(f"operator {self.operator} requires at least one value")
        if not needs_values and self.values:
            raise ValueError(f"operator {self.operator} must not have values")
        return self


class LabelSelector(K8sModel):
    """Label selector; an empty selector (``{}``) selects every pod in the namespace."""

    match_labels: Labels | None = None
    match_expressions: tuple[LabelSelectorRequirement, ...] | None = None

    def matches(self, labels: Mapping[str, str]) -> bool:
        """Whether a pod carrying ``labels`` is selected."""
        if any(labels.get(k) != v for k, v in (self.match_labels or {}).items()):
            return False
        for req in self.match_expressions or ():
            present = req.key in labels
            ok = {
                "In": present and labels.get(req.key) in req.values,
                "NotIn": not present or labels.get(req.key) not in req.values,
                "Exists": present,
                "DoesNotExist": not present,
            }[req.operator]
            if not ok:
                return False
        return True
