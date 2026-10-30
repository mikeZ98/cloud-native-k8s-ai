"""Zero-trust network critic: intercepts permissive NetworkPolicy sets before deployment.

The critic reads raw policies (the typed model rejects most of what it must catch, such
as rules without peers) together with the workloads they govern, and reports:

* namespaces with workloads but no default-deny ingress or egress policy;
* rules open to every source/destination, cross-namespace peers outside the trusted
  namespaces, and ``ipBlock`` peers outside the allow-listed CIDRs (non-whitelisted
  external traffic);
* Qdrant (vector-store) pods that are not isolated, or that admit anything other than
  the API pods' immutable selector on the Qdrant ports;
* egress-isolated namespaces where pods cannot resolve DNS;
* workloads whose pods carry another workload's selector labels: NetworkPolicy identity
  is labels, so such pods inherit every flow granted to the original (label spoofing).

Every finding carries a remediation; most are automatic (remove the permissive rule or
peer, replace Qdrant's ingress with the canonical rule, create the missing default-deny
or DNS policy), and ``NetworkCritic.loop`` applies them until the set is stable.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from cloud_native_k8s_ai.guardrails.catalog import NETWORK, violation
from cloud_native_k8s_ai.guardrails.models import (
    JsonPatchOp,
    ObjectRef,
    PolicyViolation,
    RemediationAdvice,
    RemediationResult,
)
from cloud_native_k8s_ai.guardrails.objects import (
    Workload,
    dig,
    mapping,
    namespace_of,
    pointer,
    selector,
    selects_everything,
    sequence,
    workloads,
)
from cloud_native_k8s_ai.guardrails.remediation import DEFAULT_MAX_ROUNDS, critic_loop
from cloud_native_k8s_ai.schemas import DNS_PORT, default_deny_policy, dns_egress_policy

POLICY: Final = NETWORK
NAMESPACE_NAME_LABEL: Final = "kubernetes.io/metadata.name"
KUBE_SYSTEM: Final = "kube-system"
_DIRECTIONS: Final = (("Ingress", "ingress", "from"), ("Egress", "egress", "to"))


def _matches(required: Mapping[str, str], labels: Mapping[str, str]) -> bool:
    return all(labels.get(k) == v for k, v in required.items())


def policy_types(policy: Mapping[str, Any]) -> list[str]:
    """Effective ``policyTypes`` (Kubernetes defaults them when omitted)."""
    spec = mapping(policy.get("spec"))
    declared = [str(t) for t in sequence(spec.get("policyTypes"))]
    return declared or ["Ingress", *(["Egress"] if "egress" in spec else [])]


def _selects(policy: Mapping[str, Any], workload: Workload) -> bool:
    parsed = selector(dig(policy, "spec", "podSelector"))
    return (
        namespace_of(policy) == workload.namespace
        and parsed is not None
        and parsed.matches(workload.pod_labels)
    )


@dataclass(frozen=True, eq=False)
class NetworkCritic:
    name: str = POLICY
    trusted_namespaces: frozenset[str] = frozenset({KUBE_SYSTEM, "ingress-nginx", "keda"})
    """Namespaces a peer may select besides the policy's own."""
    allowed_ingress_cidrs: tuple[str, ...] = ()
    allowed_egress_cidrs: tuple[str, ...] = ()
    vector_store_labels: Mapping[str, str] = field(
        default_factory=lambda: {"app.kubernetes.io/component": "vector-store"}
    )
    api_labels: Mapping[str, str] = field(
        default_factory=lambda: {"app.kubernetes.io/component": "api"}
    )

    def loop(
        self, documents: Sequence[Mapping[str, Any]], *, max_rounds: int = DEFAULT_MAX_ROUNDS
    ) -> RemediationResult:
        """The critic loop on its own: critique, auto-remediate, re-critique."""
        return critic_loop((self,), documents, max_rounds=max_rounds)

    def evaluate(self, documents: Sequence[Mapping[str, Any]]) -> list[PolicyViolation]:
        policies = [d for d in documents if d.get("kind") == "NetworkPolicy"]
        governed = workloads(documents)
        # Qdrant first: its fix replaces whole rule lists, superseding generic removals.
        violations = self._qdrant(policies, governed, documents)
        violations += self._impersonation(governed)
        for policy in policies:
            violations += self._rules(policy)
        for namespace in sorted({w.namespace for w in governed}):
            local = [p for p in policies if namespace_of(p) == namespace]
            violations += self._default_deny(namespace, local, documents)
            violations += self._dns(namespace, local, governed)
        return violations

    def _violation(
        self,
        code: str,
        target: ObjectRef,
        path: str,
        message: str,
        advice: RemediationAdvice,
    ) -> PolicyViolation:
        return violation(
            code, policy=self.name, target=target, path=path, message=message, remediation=advice
        )

    # -- generic permissiveness --------------------------------------------------
    def _rules(self, policy: Mapping[str, Any]) -> list[PolicyViolation]:
        ref = ObjectRef.of(policy)
        spec = mapping(policy.get("spec"))
        if selector(spec.get("podSelector")) is None:
            return [
                self._violation(
                    "invalid-pod-selector",
                    ref,
                    "/spec/podSelector",
                    "podSelector is not a valid label selector",
                    RemediationAdvice(summary="fix the podSelector", action="manual"),
                )
            ]
        violations: list[PolicyViolation] = []
        for direction, key, peer_key in _DIRECTIONS:
            for i, rule in enumerate(sequence(spec.get(key))):
                rule_path = pointer("spec", key, i)
                peers = sequence(mapping(rule).get(peer_key))
                drop_rule = RemediationAdvice(
                    summary=f"remove {key} rule {i}",
                    action="patch",
                    patch=(JsonPatchOp(op="remove", path=rule_path),),
                )
                if not peers:
                    code = "ingress-from-anywhere" if key == "ingress" else "egress-to-anywhere"
                    text = f"{key} rule {i} has no {peer_key!r}: it matches every peer"
                    violations.append(self._violation(code, ref, rule_path, text, drop_rule))
                    continue
                for j, peer in enumerate(peers):
                    peer_path = f"{rule_path}{pointer(peer_key, j)}"
                    found = self._peer_problem(direction, namespace_of(policy), mapping(peer))
                    if found is None:
                        continue
                    advice = drop_rule
                    if len(peers) > 1:
                        advice = RemediationAdvice(
                            summary=f"remove {peer_key} peer {j} of {key} rule {i}",
                            action="patch",
                            patch=(JsonPatchOp(op="remove", path=peer_path),),
                        )
                    violations.append(self._violation(found[0], ref, peer_path, found[1], advice))
        return violations

    def _peer_problem(  # noqa: PLR0911 - one exit per peer kind
        self, direction: str, namespace: str, peer: Mapping[str, Any]
    ) -> tuple[str, str] | None:
        lower = direction.lower()
        if "ipBlock" in peer:
            cidr = str(dig(peer, "ipBlock", "cidr"))
            allowed = (
                self.allowed_ingress_cidrs if lower == "ingress" else self.allowed_egress_cidrs
            )
            if _within(cidr, allowed):
                return None
            return (
                f"external-{lower}",
                f"ipBlock {cidr} is not in the allow-listed CIDRs {list(allowed)}",
            )
        if "namespaceSelector" in peer:
            target = self._selected_namespace(peer["namespaceSelector"])
            if target is not None and (target == namespace or target in self.trusted_namespaces):
                return None
            scope = "every namespace" if target is None else f"namespace {target!r}"
            return f"cross-namespace-{lower}", f"peer reaches {scope}, which is not trusted"
        if "podSelector" in peer:
            if selector(peer["podSelector"]) is None:
                return "invalid-peer", "peer podSelector is not a valid label selector"
            return None
        return "invalid-peer", "peer selects neither pods, namespaces nor an ipBlock"

    @staticmethod
    def _selected_namespace(raw: Any) -> str | None:
        """The single namespace a selector pins by name; ``None`` when it is broader."""
        parsed = selector(raw)
        if parsed is None or parsed.match_expressions or not parsed.match_labels:
            return None
        labels = parsed.match_labels
        return labels.get(NAMESPACE_NAME_LABEL) if set(labels) == {NAMESPACE_NAME_LABEL} else None

    # -- default deny and DNS ------------------------------------------------------
    def _default_deny(
        self,
        namespace: str,
        policies: Sequence[Mapping[str, Any]],
        documents: Sequence[Mapping[str, Any]],
    ) -> list[PolicyViolation]:
        canonical = default_deny_policy(namespace).to_k8s()
        taken = {ObjectRef.of(d) for d in documents}
        if ObjectRef.of(canonical) in taken:
            canonical["metadata"]["name"] = "guardrail-default-deny-all"
        advice = RemediationAdvice(
            summary=f"create NetworkPolicy {canonical['metadata']['name']} (deny all traffic)",
            action="create",
            document=canonical,
        )
        violations = []
        for direction, key, _ in _DIRECTIONS:
            denies = any(
                selects_everything(dig(p, "spec", "podSelector"))
                and direction in policy_types(p)
                and not sequence(dig(p, "spec", key))
                for p in policies
            )
            if not denies:
                violations.append(
                    self._violation(
                        f"missing-default-deny-{key}",
                        ObjectRef(kind="Namespace", name=namespace),
                        "",
                        f"no default-deny {key} policy: unlisted {key} flows are allowed",
                        advice,
                    )
                )
        return violations

    def _dns(
        self, namespace: str, policies: Sequence[Mapping[str, Any]], governed: Sequence[Workload]
    ) -> list[PolicyViolation]:
        isolated = [
            w
            for w in governed
            if w.namespace == namespace
            and any(_selects(p, w) and "Egress" in policy_types(p) for p in policies)
        ]
        stranded = [
            w.ref.name
            for w in isolated
            if not any(_selects(p, w) and _allows_dns(p) for p in policies)
        ]
        if not stranded:
            return []
        return [
            self._violation(
                "missing-dns-egress",
                ObjectRef(kind="Namespace", name=namespace),
                "",
                f"egress-isolated workloads {stranded} cannot resolve names (UDP/{DNS_PORT})",
                RemediationAdvice(
                    summary="create NetworkPolicy allow-dns-egress (UDP/TCP 53 to kube-dns)",
                    action="create",
                    document=dns_egress_policy(namespace).to_k8s(),
                ),
            )
        ]

    # -- identity ----------------------------------------------------------------------
    def _impersonation(self, governed: Sequence[Workload]) -> list[PolicyViolation]:
        violations: list[PolicyViolation] = []
        for owner in governed:
            if not owner.selector_labels:
                continue
            for other in governed:
                if other is owner or other.namespace != owner.namespace:
                    continue
                if not _matches(owner.selector_labels, other.pod_labels):
                    continue
                labels_path = f"{other.pod_path.removesuffix('/spec')}/metadata/labels"
                violations.append(
                    self._violation(
                        "workload-selector-overlap",
                        other.ref,
                        labels_path,
                        f"pods of {other.ref} carry the selector labels of {owner.ref} "
                        f"{dict(owner.selector_labels)}: they inherit its traffic and every "
                        "NetworkPolicy grant made to it",
                        RemediationAdvice(
                            summary="give every workload unique selector labels "
                            "(app.kubernetes.io/name + app.kubernetes.io/component)",
                            action="manual",
                        ),
                    )
                )
        return violations

    # -- Qdrant isolation ------------------------------------------------------------
    def _qdrant(
        self,
        policies: Sequence[Mapping[str, Any]],
        governed: Sequence[Workload],
        documents: Sequence[Mapping[str, Any]],
    ) -> list[PolicyViolation]:
        violations: list[PolicyViolation] = []
        for store in (w for w in governed if _matches(self.vector_store_labels, w.pod_labels)):
            local = [w for w in governed if w.namespace == store.namespace]
            apis = [w for w in local if _matches(self.api_labels, w.pod_labels)]
            canonical = self._canonical_rules(store, apis)
            selecting = [p for p in policies if _selects(p, store) and "Ingress" in policy_types(p)]
            admitted = flagged = False
            for policy in selecting:
                rules = [mapping(r) for r in sequence(dig(policy, "spec", "ingress"))]
                verdicts = [self._exclusive(rule, store, apis, local) for rule in rules]
                admitted = admitted or any(verdicts)
                if all(verdicts):
                    continue
                # A policy that also governs other pods must never receive Qdrant's rule:
                # it would open those pods to the API too. Drop the offending rules there
                # (a dedicated Qdrant policy follows if needed); rewrite dedicated ones.
                shared = any(
                    _selects(policy, w)
                    for w in local
                    if not _matches(self.vector_store_labels, w.pod_labels)
                )
                if shared:
                    kept: list[Any] = [r for r, ok in zip(rules, verdicts, strict=True) if ok]
                    summary = "remove the rules that open Qdrant (the policy governs other pods)"
                else:
                    kept, flagged = canonical, True  # installs the API-only rule
                    summary = "replace the ingress rules with the API-only Qdrant rule"
                violations.append(
                    self._violation(
                        "qdrant-ingress-not-exclusive",
                        ObjectRef.of(policy),
                        "/spec/ingress",
                        f"{store.ref.name} admits peers other than the API pods "
                        f"{[a.ref.name for a in apis]} on its own ports",
                        RemediationAdvice(
                            summary=summary,
                            action="patch",
                            patch=(JsonPatchOp(op="replace", path="/spec/ingress", value=kept),),
                        ),
                    )
                )
            if selecting and (admitted or flagged or not apis):
                continue
            create = self._isolation_policy(store, canonical, documents)
            if not selecting:
                code = "qdrant-not-isolated"
                text = f"no ingress policy selects {store.ref.name}: every pod can reach it"
            else:
                code = "qdrant-unreachable-from-api"
                text = f"no policy admits the API pods into {store.ref.name}"
            violations.append(self._violation(code, store.ref, "", text, create))
        return violations

    def _exclusive(
        self,
        rule: Mapping[str, Any],
        store: Workload,
        apis: Sequence[Workload],
        local: Sequence[Workload],
    ) -> bool:
        """Only API pods (by their immutable selector), only on Qdrant's own ports."""
        peers = [mapping(p) for p in sequence(rule.get("from"))]
        ports = [mapping(p) for p in sequence(rule.get("ports"))]
        if not peers or not ports:
            return False
        known_ports = store.container_ports()
        if any(
            p.get("port") not in known_ports or "endPort" in p or p.get("protocol", "TCP") != "TCP"
            for p in ports
        ):
            return False
        others = [w for w in local if w not in apis]
        for peer in peers:
            parsed = selector(peer.get("podSelector"))
            if set(peer) != {"podSelector"} or parsed is None:
                return False
            labels = parsed.match_labels or {}
            if not any(a.selector_labels.items() <= labels.items() for a in apis):
                return False
            if any(parsed.matches(w.pod_labels) for w in others):
                return False
        return True

    @staticmethod
    def _canonical_rules(store: Workload, apis: Sequence[Workload]) -> list[dict[str, Any]]:
        if not apis:
            return []
        numbers = sorted(set(store.container_ports().values()))
        return [
            {
                "from": [{"podSelector": {"matchLabels": dict(a.selector_labels)}} for a in apis],
                "ports": [{"protocol": "TCP", "port": n} for n in numbers],
            }
        ]

    @staticmethod
    def _isolation_policy(
        store: Workload, rules: list[dict[str, Any]], documents: Sequence[Mapping[str, Any]]
    ) -> RemediationAdvice:
        name = f"{store.ref.name}-allow-from-api"
        if any(
            ObjectRef.of(d) == ObjectRef(kind="NetworkPolicy", namespace=store.namespace, name=name)
            for d in documents
        ):
            name = f"guardrail-{name}"
        document = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": store.namespace},
            "spec": {
                "podSelector": {"matchLabels": dict(store.selector_labels)},
                "policyTypes": ["Ingress"],
                "ingress": rules,
                "egress": [],
            },
        }
        return RemediationAdvice(
            summary=f"create NetworkPolicy {name}: {store.ref.name} admits only the API pods",
            action="create",
            document=document,
        )


def _allows_dns(policy: Mapping[str, Any]) -> bool:
    for rule in sequence(dig(policy, "spec", "egress")):
        for port in sequence(mapping(rule).get("ports")):
            entry = mapping(port)
            if entry.get("port") == DNS_PORT and entry.get("protocol", "TCP") == "UDP":
                return True
    return False


def _within(cidr: str, allowed: Sequence[str]) -> bool:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return any(
            network.version == (outer := ipaddress.ip_network(a, strict=False)).version
            and network.subnet_of(outer)  # type: ignore[arg-type]
            for a in allowed
        )
    except ValueError:
        return False
