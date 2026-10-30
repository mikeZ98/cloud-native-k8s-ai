"""Deterministic perturbations of compiled manifests and stack specs, with ground truth.

Every manifest operator mutates raw documents in place and returns the violation codes a
correct admission engine (configured for the stack, ``AdmissionEngine.for_stack``) must
report; benign operators return none. Operators declare the *slots* they touch, and a
sample never composes two operators sharing a slot, so the expected codes of a composed
sample are exactly the union of its parts. Identity-changing operators (label typos,
spoofing, clones, namespace leaks) and the operators editing Qdrant's policy share the
``identity`` slot: an identity change decides which pods count as the API or Qdrant.

Spec operators mutate the wire form of an ``AIStackSpec``; malicious ones must be
rejected by the contracts or the compiler, benign ones must compile and be admitted.

``epsilon`` in ``[0, 1]`` is the perturbation budget: a sample composes
``1 + floor(epsilon * (MAX_COMPOSITION - 1))`` operators.
"""

from __future__ import annotations

import copy
import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Final, Literal

from cloud_native_k8s_ai.evals.prng import Prng
from cloud_native_k8s_ai.schemas import cpu_millicores

type Docs = list[dict[str, Any]]
type Category = Literal["labels", "resources", "network", "security", "benign"]

MAX_COMPOSITION: Final = 5
COMPONENTS: Final = ("api", "vector-store", "broker")
NAME_LABEL: Final = "app.kubernetes.io/name"
COMPONENT_LABEL: Final = "app.kubernetes.io/component"
LEAK_NAMESPACE: Final = "leaked"
_ALNUM: Final = "abcdefghijklmnopqrstuvwxyz0123456789"


class PerturbationError(Exception):
    """The base manifests lack what an operator needs (not a stack this suite targets)."""


# ---------------------------------------------------------------------------
# Raw manifest access (the base is a core-compiled bundle)
# ---------------------------------------------------------------------------
def workload(docs: Docs, component: str) -> dict[str, Any]:
    """The workload whose *selector* names ``component``: selectors are immutable, so label
    mutations (typos, spoofing) never lose the target, and rogue clones have their own."""
    for document in docs:
        selector = document.get("spec", {}).get("selector", {}).get("matchLabels", {})
        if (
            document.get("kind") in {"Deployment", "StatefulSet"}
            and selector.get(COMPONENT_LABEL) == component
        ):
            return document
    raise PerturbationError(f"no workload selecting component {component!r}")


def pod(docs: Docs, component: str) -> dict[str, Any]:
    spec: dict[str, Any] = workload(docs, component)["spec"]["template"]["spec"]
    return spec


def container(docs: Docs, component: str) -> dict[str, Any]:
    first: dict[str, Any] = pod(docs, component)["containers"][0]
    return first


def policy(docs: Docs, selects: str, direction: str) -> dict[str, Any]:
    """The NetworkPolicy whose podSelector names ``selects`` for ``direction``."""
    for document in docs:
        spec = document.get("spec", {})
        labels = spec.get("podSelector", {}).get("matchLabels", {})
        if (
            document.get("kind") == "NetworkPolicy"
            and labels.get(COMPONENT_LABEL) == selects
            and direction in spec.get("policyTypes", ())
        ):
            return document
    raise PerturbationError(f"no {direction} policy selecting component {selects!r}")


def drop(docs: Docs, name: str) -> None:
    before = len(docs)
    docs[:] = [
        d for d in docs if not (d.get("kind") == "NetworkPolicy" and d["metadata"]["name"] == name)
    ]
    if len(docs) == before:
        raise PerturbationError(f"no NetworkPolicy {name!r}")


def typo(text: str, prng: Prng) -> str:
    """``text`` with one alphanumeric character replaced (still a valid label value)."""
    positions = [i for i, c in enumerate(text) if c in _ALNUM]
    index = prng.choice(positions)
    replacement = prng.choice([c for c in _ALNUM if c != text[index]])
    return text[:index] + replacement + text[index + 1 :]


# ---------------------------------------------------------------------------
# Operators
# ---------------------------------------------------------------------------
type Apply = Callable[[Docs, Prng, str], frozenset[str]]


@dataclass(frozen=True)
class Perturbation:
    name: str
    category: Category
    description: str
    apply: Apply
    targets: tuple[str, ...] = ("",)
    """Workload components the operator can hit (``""``: not workload-specific)."""
    slots: tuple[str, ...] = ()
    """Conflict keys; ``{target}`` is substituted. Defaults to ``(name:target,)``."""

    @property
    def malicious(self) -> bool:
        return self.category != "benign"

    def slot_keys(self, target: str) -> frozenset[str]:
        keys = self.slots or (f"{self.name}:{{target}}",)
        return frozenset(k.format(target=target) for k in keys)


def _codes(*codes: str) -> frozenset[str]:
    return frozenset(codes)


# -- labels -------------------------------------------------------------------
def _selector_label_typo(docs: Docs, prng: Prng, target: str) -> frozenset[str]:
    labels = workload(docs, target)["spec"]["template"]["metadata"]["labels"]
    labels[NAME_LABEL] = typo(labels[NAME_LABEL], prng)
    # A typo'd API is no longer "the API": Qdrant's API-only rule then admits nobody known.
    extra = ("qdrant-ingress-not-exclusive",) if target == "api" else ()
    return _codes("selector-template-mismatch", *extra)


def _component_spoof(docs: Docs, _: Prng, target: str) -> frozenset[str]:
    labels = workload(docs, target)["spec"]["template"]["metadata"]["labels"]
    labels[COMPONENT_LABEL] = "api"
    return _codes("selector-template-mismatch")


def _selector_clone(docs: Docs, prng: Prng, target: str) -> frozenset[str]:
    original = workload(docs, target)
    clone = copy.deepcopy(original)
    tag = f"rogue-{prng.randint(0, 9999)}"
    selector = original["spec"]["selector"]["matchLabels"]
    clone["metadata"] = {"name": tag, "namespace": original["metadata"]["namespace"]}
    clone["spec"]["selector"] = {"matchLabels": {"rogue": tag}}
    clone["spec"]["template"]["metadata"]["labels"] = {**selector, "rogue": tag}
    docs.append(clone)
    return _codes("workload-selector-overlap")


def _namespace_leak(docs: Docs, _: Prng, target: str) -> frozenset[str]:
    workload(docs, target)["metadata"]["namespace"] = LEAK_NAMESPACE
    extra = ("qdrant-not-isolated",) if target == "vector-store" else ()
    return _codes("missing-default-deny-ingress", "missing-default-deny-egress", *extra)


# -- resources ----------------------------------------------------------------
def _limit_below_request(docs: Docs, prng: Prng, target: str) -> frozenset[str]:
    resources = container(docs, target)["resources"]
    request = cpu_millicores(str(resources["requests"]["cpu"]))
    if request < 2:  # noqa: PLR2004 - nothing below 1m: shrink the memory limit instead
        resources["limits"]["memory"] = "1"
        resources["requests"]["memory"] = "2"
    else:
        resources["limits"]["cpu"] = f"{prng.randint(1, request - 1)}m"
    return _codes("requests-exceed-limits")


def _unit_degradation(docs: Docs, prng: Prng, target: str) -> frozenset[str]:
    resources = container(docs, target)["resources"]
    section = prng.choice(("requests", "limits"))
    amount = prng.randint(1, 4096)
    resources[section]["memory"] = prng.choice(
        (f"{amount}mi", f"{amount}MB", f"{amount} Mi", f"{amount}Mib", f"{amount}gb")
    )
    return _codes("invalid-resource-quantity")


def _drop_limits(docs: Docs, _: Prng, target: str) -> frozenset[str]:
    del container(docs, target)["resources"]["limits"]
    return _codes("missing-resource-limits")


def _best_effort(docs: Docs, _: Prng, target: str) -> frozenset[str]:
    del container(docs, target)["resources"]
    return _codes("best-effort-container")


# -- network ------------------------------------------------------------------
def _strip_default_deny(docs: Docs, _: Prng, __: str) -> frozenset[str]:
    drop(docs, "default-deny-all")
    return _codes("missing-default-deny-ingress", "missing-default-deny-egress")


def _strip_dns(docs: Docs, _: Prng, __: str) -> frozenset[str]:
    drop(docs, "allow-dns-egress")
    return _codes("missing-dns-egress")


def _widen_cidr(docs: Docs, prng: Prng, _: str) -> frozenset[str]:
    cidr = prng.choice(("0.0.0.0/0", "0.0.0.0/1", "10.0.0.0/8", "::/0", "100.64.0.0/10"))
    policy(docs, "api", "Egress")["spec"]["egress"].append({"to": [{"ipBlock": {"cidr": cidr}}]})
    return _codes("external-egress")


def _open_qdrant(docs: Docs, prng: Prng, _: str) -> frozenset[str]:
    rule = policy(docs, "vector-store", "Ingress")["spec"]["ingress"][0]
    rule["from"] = [
        prng.choice(
            ({"podSelector": {}}, {"podSelector": {"matchLabels": {COMPONENT_LABEL: "api"}}})
        )
    ]
    return _codes("qdrant-ingress-not-exclusive")


def _swap_qdrant_port(docs: Docs, _: Prng, __: str) -> frozenset[str]:
    redis_port = container(docs, "broker")["ports"][0]["containerPort"]
    policy(docs, "vector-store", "Ingress")["spec"]["ingress"][0]["ports"] = [
        {"protocol": "TCP", "port": redis_port}
    ]
    return _codes("qdrant-ingress-not-exclusive")


# -- securityContext ------------------------------------------------------------
def _context(docs: Docs, target: str) -> dict[str, Any]:
    context: dict[str, Any] = container(docs, target).setdefault("securityContext", {})
    return context


def _writable_rootfs(docs: Docs, _: Prng, target: str) -> frozenset[str]:
    _context(docs, target)["readOnlyRootFilesystem"] = False
    return _codes("writable-root-filesystem")


def _escalate(docs: Docs, prng: Prng, target: str) -> frozenset[str]:
    context = _context(docs, target)
    if prng.random() < 0.5:  # noqa: PLR2004
        context["allowPrivilegeEscalation"] = True
    else:
        context.pop("allowPrivilegeEscalation", None)  # Kubernetes defaults it to true
    return _codes("privilege-escalation-allowed")


def _privileged(docs: Docs, _: Prng, target: str) -> frozenset[str]:
    _context(docs, target)["privileged"] = True
    return _codes("privileged-container")


def _root_user(docs: Docs, _: Prng, target: str) -> frozenset[str]:
    _context(docs, target)["runAsUser"] = 0
    return _codes("run-as-root")


def _add_capability(docs: Docs, prng: Prng, target: str) -> frozenset[str]:
    capabilities = _context(docs, target).setdefault("capabilities", {})
    capabilities["add"] = [prng.choice(("SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "NET_RAW"))]
    return _codes("capabilities-added")


def _keep_capabilities(docs: Docs, _: Prng, target: str) -> frozenset[str]:
    _context(docs, target).setdefault("capabilities", {})["drop"] = []
    return _codes("capabilities-not-dropped")


def _host_namespace(docs: Docs, prng: Prng, target: str) -> frozenset[str]:
    pod(docs, target)[prng.choice(("hostNetwork", "hostPID", "hostIPC"))] = True
    return _codes("host-namespace")


# -- benign ---------------------------------------------------------------------
def _scale_replicas(docs: Docs, prng: Prng, _: str) -> frozenset[str]:
    scaled = next(d for d in docs if d.get("kind") == "ScaledObject")["spec"]
    workload(docs, "api")["spec"]["replicas"] = prng.randint(
        scaled["minReplicaCount"], scaled["maxReplicaCount"]
    )
    return _codes()


def _annotate(docs: Docs, prng: Prng, target: str) -> frozenset[str]:
    metadata = workload(docs, target)["metadata"]
    metadata.setdefault("annotations", {})["eval.k8s-ai/revision"] = str(prng.randint(1, 99))
    return _codes()


def _extra_pod_label(docs: Docs, prng: Prng, target: str) -> frozenset[str]:
    labels = workload(docs, target)["spec"]["template"]["metadata"]["labels"]
    labels["team"] = prng.choice(("ml", "search", "platform"))
    return _codes()


def _cpu_spelling(docs: Docs, _: Prng, target: str) -> frozenset[str]:
    requests = container(docs, target)["resources"]["requests"]
    millicores = cpu_millicores(str(requests["cpu"]))
    if str(requests["cpu"]).endswith("m"):
        requests["cpu"] = format((Decimal(millicores) / 1000).normalize(), "f")
    else:
        requests["cpu"] = f"{millicores}m"
    return _codes()


def _limit_equals_request(docs: Docs, _: Prng, target: str) -> frozenset[str]:
    resources = container(docs, target)["resources"]
    resources["requests"] = dict(resources["limits"])
    return _codes()


def _shuffle(docs: Docs, prng: Prng, _: str) -> frozenset[str]:
    docs[:] = prng.shuffled(docs)
    return _codes()


def _op(
    name: str,
    category: Category,
    description: str,
    apply: Apply,
    *,
    targets: tuple[str, ...] = ("",),
    slots: tuple[str, ...] = (),
) -> Perturbation:
    return Perturbation(name, category, description, apply, targets, slots)


IDENTITY: Final = ("identity",)
WORKLOADS: Final = COMPONENTS
STATELESS: Final = ("vector-store", "broker")

MANIFEST_PERTURBATIONS: Final[tuple[Perturbation, ...]] = (
    _op("selector-label-typo", "labels", "typo in a pod name label", _selector_label_typo,
        targets=WORKLOADS, slots=IDENTITY),
    _op("component-label-spoof", "labels", "pods relabelled component=api", _component_spoof,
        targets=STATELESS, slots=IDENTITY),
    _op("selector-clone", "labels", "rogue workload wearing another's selector", _selector_clone,
        targets=WORKLOADS, slots=IDENTITY),
    _op("namespace-leak", "labels", "workload moved to an unprotected namespace", _namespace_leak,
        targets=STATELESS, slots=IDENTITY),
    _op("limit-below-request", "resources", "cpu limit below the request", _limit_below_request,
        targets=WORKLOADS, slots=("resources:{target}",)),
    _op("unit-degradation", "resources", "memory quantity with a corrupted unit", _unit_degradation,
        targets=WORKLOADS, slots=("resources:{target}",)),
    _op("drop-limits", "resources", "resource limits removed", _drop_limits,
        targets=WORKLOADS, slots=("resources:{target}",)),
    _op("best-effort", "resources", "all resources removed (BestEffort)", _best_effort,
        targets=WORKLOADS, slots=("resources:{target}",)),
    # Mutually exclusive: with default deny gone, pods may not be egress-isolated at all,
    # and then nothing is stranded without DNS (found by the composition sweep).
    _op("strip-default-deny", "network", "default-deny-all deleted", _strip_default_deny,
        slots=("policy:baseline",)),
    _op("strip-dns", "network", "allow-dns-egress deleted", _strip_dns, slots=("policy:baseline",)),
    _op("widen-cidr", "network", "API egress widened to an external CIDR", _widen_cidr,
        slots=("policy:api-egress",)),
    _op("open-qdrant", "network", "Qdrant ingress opened beyond the API", _open_qdrant,
        slots=("policy:qdrant", *IDENTITY)),
    _op("swap-qdrant-port", "network", "Qdrant ingress port swapped for Redis'", _swap_qdrant_port,
        slots=("policy:qdrant", *IDENTITY)),
    _op("writable-rootfs", "security", "readOnlyRootFilesystem flipped off", _writable_rootfs,
        targets=WORKLOADS, slots=("security:{target}",)),
    _op("privilege-escalation", "security", "allowPrivilegeEscalation true or unset", _escalate,
        targets=WORKLOADS, slots=("security:{target}",)),
    _op("privileged", "security", "privileged container", _privileged,
        targets=WORKLOADS, slots=("security:{target}",)),
    _op("root-user", "security", "runAsUser 0", _root_user,
        targets=WORKLOADS, slots=("security:{target}",)),
    _op("add-capability", "security", "dangerous capability added", _add_capability,
        targets=WORKLOADS, slots=("security:{target}",)),
    _op("keep-capabilities", "security", "drop: [ALL] removed", _keep_capabilities,
        targets=WORKLOADS, slots=("security:{target}",)),
    _op("host-namespace", "security", "hostNetwork / hostPID / hostIPC enabled", _host_namespace,
        targets=WORKLOADS, slots=("pod:{target}",)),
    _op("scale-replicas", "benign", "API replicas changed within the KEDA bounds", _scale_replicas),
    _op("annotate", "benign", "workload annotation added", _annotate, targets=WORKLOADS),
    _op("extra-pod-label", "benign", "non-selector pod label added", _extra_pod_label,
        targets=WORKLOADS),
    _op("cpu-spelling", "benign", "cpu request respelled (250m <-> 0.25)", _cpu_spelling,
        targets=WORKLOADS, slots=("benign-resources:{target}",)),
    _op("limit-equals-request", "benign", "requests raised to the limits", _limit_equals_request,
        targets=WORKLOADS, slots=("benign-resources:{target}",)),
    _op("shuffle-documents", "benign", "document order permuted", _shuffle),
)  # fmt: skip


# ---------------------------------------------------------------------------
# Spec perturbations
# ---------------------------------------------------------------------------
type SpecApply = Callable[[dict[str, Any], Prng], None]


@dataclass(frozen=True)
class SpecPerturbation:
    name: str
    malicious: bool
    description: str
    apply: SpecApply


def _spec_maxmemory(spec: dict[str, Any], _: Prng) -> None:
    spec["redis"]["maxmemory"] = spec["redis"]["resources"]["limits"]["memory"]


def _spec_replicas(spec: dict[str, Any], prng: Prng) -> None:
    spec["app"]["replicas"] = spec["autoscaling"]["maxReplicas"] + prng.randint(1, 10)


def _spec_cooldown(spec: dict[str, Any], prng: Prng) -> None:
    polling = spec["autoscaling"]["pollingInterval"]
    spec["autoscaling"]["cooldownPeriod"] = prng.randint(0, polling - 1)


def _spec_port_collision(spec: dict[str, Any], _: Prng) -> None:
    spec["qdrant"]["grpcPort"] = spec["qdrant"]["restPort"]


def _spec_latest(spec: dict[str, Any], prng: Prng) -> None:
    component = prng.choice(("app", "qdrant", "redis"))
    image = spec[component]["image"].split("@")[0]
    spec[component]["image"] = image.rsplit(":", 1)[0] + ":latest"


def _spec_request_over_limit(spec: dict[str, Any], prng: Prng) -> None:
    resources = spec[prng.choice(("app", "qdrant"))]["resources"]
    limit = cpu_millicores(resources["limits"]["cpu"])
    resources["requests"]["cpu"] = f"{limit + prng.randint(1, 1000)}m"


def _spec_zero_threshold(spec: dict[str, Any], _: Prng) -> None:
    spec["autoscaling"]["listLength"] = 0


def _spec_name_clash(spec: dict[str, Any], _: Prng) -> None:
    spec["redis"]["name"] = spec["qdrant"]["name"]


def _spec_scale(spec: dict[str, Any], prng: Prng) -> None:
    low, high = spec["autoscaling"]["minReplicas"], spec["autoscaling"]["maxReplicas"]
    spec["app"]["replicas"] = prng.randint(low, high)


def _spec_cpu_spelling(spec: dict[str, Any], _: Prng) -> None:
    requests = spec["app"]["resources"]["requests"]
    millicores = cpu_millicores(requests["cpu"])
    requests["cpu"] = (
        format((Decimal(millicores) / 1000).normalize(), "f")
        if requests["cpu"].endswith("m")
        else f"{millicores}m"
    )


def _spec_extra_env(spec: dict[str, Any], prng: Prng) -> None:
    spec["app"]["env"] = [
        *spec["app"].get("env", []),
        {"name": "EVAL_FLAG", "value": str(prng.randint(0, 9))},
    ]


def _spec_raise_limits(spec: dict[str, Any], prng: Prng) -> None:
    limits = spec["qdrant"]["resources"]["limits"]
    limits["cpu"] = f"{cpu_millicores(limits['cpu']) + prng.randint(1, 4000)}m"


SPEC_PERTURBATIONS: Final[tuple[SpecPerturbation, ...]] = (
    SpecPerturbation(
        "spec-maxmemory-at-limit",
        malicious=True,
        description="Redis maxmemory without headroom",
        apply=_spec_maxmemory,
    ),
    SpecPerturbation(
        "spec-replicas-out-of-bounds",
        malicious=True,
        description="API replicas above maxReplicas",
        apply=_spec_replicas,
    ),
    SpecPerturbation(
        "spec-cooldown-below-polling",
        malicious=True,
        description="cooldown shorter than polling",
        apply=_spec_cooldown,
    ),
    SpecPerturbation(
        "spec-port-collision",
        malicious=True,
        description="Qdrant REST and gRPC on one port",
        apply=_spec_port_collision,
    ),
    SpecPerturbation(
        "spec-latest-image",
        malicious=True,
        description="an image re-tagged :latest",
        apply=_spec_latest,
    ),
    SpecPerturbation(
        "spec-request-over-limit",
        malicious=True,
        description="cpu request above its limit",
        apply=_spec_request_over_limit,
    ),
    SpecPerturbation(
        "spec-zero-threshold",
        malicious=True,
        description="listLength 0",
        apply=_spec_zero_threshold,
    ),
    SpecPerturbation(
        "spec-name-clash",
        malicious=True,
        description="Redis named like Qdrant",
        apply=_spec_name_clash,
    ),
    SpecPerturbation(
        "spec-scale-within-bounds",
        malicious=False,
        description="API replicas within bounds",
        apply=_spec_scale,
    ),
    SpecPerturbation(
        "spec-cpu-spelling",
        malicious=False,
        description="cpu request respelled",
        apply=_spec_cpu_spelling,
    ),
    SpecPerturbation(
        "spec-extra-env",
        malicious=False,
        description="extra API environment variable",
        apply=_spec_extra_env,
    ),
    SpecPerturbation(
        "spec-raise-limits",
        malicious=False,
        description="Qdrant cpu limit raised",
        apply=_spec_raise_limits,
    ),
)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PerturbedSample:
    documents: Docs
    applied: tuple[str, ...]
    """``operator`` or ``operator@target`` in application order."""
    expected: frozenset[str]
    malicious: bool


@dataclass(frozen=True)
class PerturbationEngine:
    """Seeded composition of perturbation operators within a budget ``epsilon``."""

    operators: Sequence[Perturbation] = MANIFEST_PERTURBATIONS
    epsilon: float = 0.3
    composition_cap: int = field(default=MAX_COMPOSITION)

    def __post_init__(self) -> None:
        if not 0.0 <= self.epsilon <= 1.0:
            raise ValueError(f"epsilon must lie in [0, 1], got {self.epsilon}")

    @property
    def budget(self) -> int:
        """Operators composed per sample."""
        return 1 + math.floor(self.epsilon * (self.composition_cap - 1))

    def sample(self, base: Docs, prng: Prng, *, malicious: bool) -> PerturbedSample:
        pool = [(op, t) for op in self.operators if op.malicious == malicious for t in op.targets]
        if not pool:
            raise PerturbationError(f"no {'malicious' if malicious else 'benign'} operators")
        documents = copy.deepcopy(base)
        used: set[str] = set()
        applied: list[str] = []
        expected: set[str] = set()
        for op, target in prng.shuffled(pool):
            if len(applied) == self.budget:
                break
            keys = op.slot_keys(target)
            if keys & used:
                continue
            used |= keys
            expected |= op.apply(documents, prng, target)
            applied.append(f"{op.name}@{target}" if target else op.name)
        return PerturbedSample(documents, tuple(applied), frozenset(expected), malicious)


def spec_sample(
    base: Mapping[str, Any],
    prng: Prng,
    operators: Sequence[SpecPerturbation],
    *,
    malicious: bool,
    budget: int,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """A perturbed copy of a spec's wire form and the operators applied to it."""
    pool = [op for op in operators if op.malicious == malicious]
    if not pool:
        raise PerturbationError(f"no {'malicious' if malicious else 'benign'} spec operators")
    spec = copy.deepcopy(dict(base))
    chosen = prng.shuffled(pool)[:budget]
    for op in chosen:
        op.apply(spec, prng)
    return spec, tuple(op.name for op in chosen)
