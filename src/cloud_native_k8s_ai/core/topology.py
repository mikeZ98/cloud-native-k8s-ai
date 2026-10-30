"""Zero-trust topology solver: an in-memory evaluator of Kubernetes NetworkPolicy semantics.

The solver never talks to a cluster. It models a finite universe of endpoints (the
managed workloads plus synthetic probes: kube-dns, the KEDA operator, an ingress
controller, same-namespace intruders, cross-namespace look-alikes and an Internet host)
and decides every ``(source, destination, protocol, port)`` flow the way the API server's
NetworkPolicy contract defines it:

* a pod is *isolated* for a direction once any policy selecting it lists that type;
* an isolated pod admits a flow only if some rule of a selecting policy matches both the
  peer and the port; policies are additive (a union, never an intersection);
* a connection needs the source's egress **and** the destination's ingress to allow it.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from itertools import product
from typing import TYPE_CHECKING, Literal

from cloud_native_k8s_ai.core.errors import TopologyConflictError, Violation
from cloud_native_k8s_ai.schemas import (
    DNS_PORT,
    NetworkPolicy,
    NetworkPolicyPeer,
    NetworkPolicyPort,
    ip_network,
)

if TYPE_CHECKING:
    from cloud_native_k8s_ai.core.generator import ManifestBundle

Protocol = Literal["TCP", "UDP", "SCTP"]
Direction = Literal["Ingress", "Egress"]
PortKey = tuple[Protocol, int]

NAMESPACE_NAME_LABEL = "kubernetes.io/metadata.name"
SENTINEL_PORTS: tuple[int, ...] = (1, 22, 80, 443, 3306, 5432, 6335, 8080, 9090, 65535)
"""Ports no managed workload should expose; probed to catch port-wildcard rules."""


@dataclass(frozen=True, slots=True, eq=False)
class Endpoint:
    """A pod (``namespace`` set) or a cluster-external host (``ip`` set)."""

    name: str
    namespace: str | None = None
    labels: Mapping[str, str] = field(default_factory=dict)
    namespace_labels: Mapping[str, str] = field(default_factory=dict)
    ports: Mapping[str, PortKey] = field(default_factory=dict)
    """Named container ports, resolved when a policy references a port by name."""
    ip: str | None = None
    managed: bool = False
    requires_dns: bool = False

    def __post_init__(self) -> None:
        if (self.namespace is None) == (self.ip is None):
            raise TopologyConflictError(f"endpoint {self.name!r} needs a namespace xor an IP")
        if self.namespace is not None and NAMESPACE_NAME_LABEL not in self.namespace_labels:
            # The API server stamps this label on every namespace.
            labels = {**self.namespace_labels, NAMESPACE_NAME_LABEL: self.namespace}
            object.__setattr__(self, "namespace_labels", labels)

    @property
    def is_pod(self) -> bool:
        return self.namespace is not None


@dataclass(frozen=True, slots=True, order=True)
class Flow:
    src: str
    dst: str
    protocol: Protocol
    port: int

    def __str__(self) -> str:
        return f"{self.src} -> {self.dst} {self.protocol}/{self.port}"


@dataclass(frozen=True, slots=True)
class ExclusiveIngress:
    """``dst`` must admit ingress only from ``sources`` and only on ``ports``.

    Checked on the destination's ingress policies alone, so the guarantee holds even if a
    source's egress policy is later widened (defense in depth).
    """

    dst: str
    sources: frozenset[str]
    ports: frozenset[PortKey]


@dataclass(frozen=True, slots=True)
class ZeroTrustIntent:
    """What the topology is supposed to allow."""

    required: frozenset[Flow] = frozenset()
    """Flows that must work (blocked → ``blocked-flow``). DNS is required per endpoint via
    ``Endpoint.requires_dns`` instead (→ ``missing-dns-egress``)."""
    permitted: frozenset[Flow] = frozenset()
    """Flows that may work; anything else that is reachable is a violation."""
    exclusive_ingress: tuple[ExclusiveIngress, ...] = ()
    dns_endpoint: str = "kube-dns"


@dataclass(frozen=True, slots=True)
class TopologyReport:
    violations: tuple[Violation, ...]
    reachable: frozenset[Flow]

    @property
    def ok(self) -> bool:
        return not self.violations

    def codes(self) -> set[str]:
        return {v.code for v in self.violations}

    def raise_for_violations(self) -> None:
        if self.violations:
            raise TopologyConflictError("zero-trust topology violated", self.violations)


class NetworkTopology:
    """Endpoints plus the NetworkPolicies that govern them."""

    def __init__(self, policies: Sequence[NetworkPolicy], endpoints: Sequence[Endpoint]) -> None:
        names = [e.name for e in endpoints]
        if len(set(names)) != len(names):
            raise TopologyConflictError("endpoint names must be unique")
        for policy in policies:
            if policy.metadata.namespace is None:
                raise TopologyConflictError(
                    f"NetworkPolicy {policy.metadata.name!r} has no namespace"
                )
        self.policies = tuple(policies)
        self.endpoints: dict[str, Endpoint] = {e.name: e for e in endpoints}
        self.governed_namespaces = {p.metadata.namespace for p in self.policies} | {
            e.namespace for e in endpoints if e.managed
        }

    @classmethod
    def from_bundle(
        cls,
        bundle: ManifestBundle,
        extra_endpoints: Iterable[Endpoint] = (),
        *,
        dns_clients: Iterable[str] = (),
    ) -> NetworkTopology:
        """Managed endpoints from the bundle's workloads, plus synthetic probe endpoints.

        ``dns_clients`` names the workloads that must be able to resolve cluster DNS.
        """
        clients = set(dns_clients)
        managed: list[Endpoint] = []
        for workload in bundle.workloads():
            namespace = workload.metadata.namespace
            if namespace is None:
                raise TopologyConflictError(f"workload {workload.metadata.name!r} has no namespace")
            pod = workload.spec.template
            managed.append(
                Endpoint(
                    name=workload.metadata.name,
                    namespace=namespace,
                    labels=dict(pod.metadata.labels or {}),
                    ports={
                        p.name: (p.protocol, p.container_port)
                        for c in pod.spec.containers
                        for p in c.ports
                    },
                    managed=True,
                    requires_dns=workload.metadata.name in clients,
                )
            )
        if unknown := clients - {e.name for e in managed}:
            raise TopologyConflictError(f"unknown DNS clients: {sorted(unknown)}")
        return cls(bundle.of_kind(NetworkPolicy), [*managed, *extra_endpoints])

    def endpoint(self, name: str) -> Endpoint:
        try:
            return self.endpoints[name]
        except KeyError:
            raise TopologyConflictError(f"unknown endpoint {name!r}") from None

    # ------------------------------------------------------------------
    # NetworkPolicy semantics
    # ------------------------------------------------------------------
    def selecting(self, pod: Endpoint, direction: Direction) -> list[NetworkPolicy]:
        """Policies in the pod's namespace that select it and constrain ``direction``."""
        if not pod.is_pod:
            return []
        return [
            p
            for p in self.policies
            if p.metadata.namespace == pod.namespace
            and direction in p.spec.policy_types
            and p.spec.pod_selector.matches(pod.labels)
        ]

    def is_isolated(self, pod: Endpoint, direction: Direction) -> bool:
        return bool(self.selecting(pod, direction))

    def ingress_allowed(self, src: Endpoint, dst: Endpoint, protocol: Protocol, port: int) -> bool:
        policies = self.selecting(dst, "Ingress")
        if not dst.is_pod or not policies:
            return True  # external hosts and non-isolated pods accept everything
        return any(
            self._peers_match(rule.from_, src, policy)
            and self._ports_match(rule.ports, dst, protocol, port)
            for policy in policies
            for rule in policy.spec.ingress
        )

    def egress_allowed(self, src: Endpoint, dst: Endpoint, protocol: Protocol, port: int) -> bool:
        policies = self.selecting(src, "Egress")
        if not policies:
            return True
        return any(
            self._peers_match(rule.to, dst, policy)
            and self._ports_match(rule.ports, dst, protocol, port)
            for policy in policies
            for rule in policy.spec.egress
        )

    def allows(self, flow: Flow) -> bool:
        src, dst = self.endpoint(flow.src), self.endpoint(flow.dst)
        return self.egress_allowed(src, dst, flow.protocol, flow.port) and self.ingress_allowed(
            src, dst, flow.protocol, flow.port
        )

    def reachable(self, ports: Iterable[PortKey]) -> frozenset[Flow]:
        """Every allowed flow touching a governed namespace, over the probed ports."""
        keys = sorted(set(ports))
        flows: set[Flow] = set()
        for src, dst in product(self.endpoints.values(), repeat=2):
            if src is dst or not (self._governed(src) or self._governed(dst)):
                continue
            for protocol, port in keys:
                flow = Flow(src.name, dst.name, protocol, port)
                if self.allows(flow):
                    flows.add(flow)
        return frozenset(flows)

    def _governed(self, endpoint: Endpoint) -> bool:
        return endpoint.namespace in self.governed_namespaces

    @staticmethod
    def _peers_match(
        peers: Sequence[NetworkPolicyPeer], other: Endpoint, policy: NetworkPolicy
    ) -> bool:
        for peer in peers:
            if peer.ip_block is not None:
                if other.ip is None:
                    continue
                address = ipaddress.ip_address(other.ip)
                block = peer.ip_block
                if address in ip_network(block.cidr) and not any(
                    address in ip_network(e) for e in block.except_
                ):
                    return True
                continue
            if not other.is_pod:
                continue
            if peer.namespace_selector is None:
                ns_ok = other.namespace == policy.metadata.namespace
            else:
                ns_ok = peer.namespace_selector.matches(other.namespace_labels)
            pod_ok = peer.pod_selector is None or peer.pod_selector.matches(other.labels)
            if ns_ok and pod_ok:
                return True
        return False

    @staticmethod
    def _ports_match(
        ports: Sequence[NetworkPolicyPort], dst: Endpoint, protocol: Protocol, port: int
    ) -> bool:
        if not ports:
            return True  # a rule without ports covers every port and protocol
        for rule in ports:
            if rule.protocol != protocol:
                continue
            if rule.port is None:
                return True
            if isinstance(rule.port, str):
                if dst.ports.get(rule.port) == (protocol, port):
                    return True
                continue
            if rule.port <= port <= (rule.end_port or rule.port):
                return True
        return False


class TopologySolver:
    """Check a ``NetworkTopology`` against a ``ZeroTrustIntent``."""

    def __init__(self, topology: NetworkTopology) -> None:
        self.topology = topology

    def probe_ports(self, intent: ZeroTrustIntent) -> frozenset[PortKey]:
        ports: set[PortKey] = {(f.protocol, f.port) for f in intent.required | intent.permitted}
        for rule in intent.exclusive_ingress:
            ports |= rule.ports
        for endpoint in self.topology.endpoints.values():
            ports |= set(endpoint.ports.values())
        protocols: tuple[Protocol, ...] = ("TCP", "UDP")
        ports |= set(product(protocols, (*SENTINEL_PORTS, DNS_PORT)))
        return frozenset(ports)

    def verify(self, intent: ZeroTrustIntent) -> TopologyReport:
        ports = self.probe_ports(intent)
        reachable = self.topology.reachable(ports)
        violations = [
            *self._default_deny(),
            *self._exclusive_ingress(intent, ports),
            *self._dns_egress(intent),
        ]
        violations += [
            Violation("unauthorized-flow", f"{flow} is reachable but not intended")
            for flow in sorted(reachable - intent.required - intent.permitted)
        ]
        violations += [
            Violation("blocked-flow", f"{flow} is required but blocked")
            for flow in sorted(intent.required - reachable)
        ]
        return TopologyReport(tuple(violations), reachable)

    def _default_deny(self) -> list[Violation]:
        topo = self.topology
        managed = [e for e in topo.endpoints.values() if e.managed]
        namespaces = sorted({e.namespace for e in managed if e.namespace is not None})
        violations = [
            Violation(
                "missing-default-deny",
                f"namespace {namespace} has no default-deny ingress+egress policy",
            )
            for namespace in namespaces
            if not any(
                p.metadata.namespace == namespace and p.spec.denies_all and _selects_all(p)
                for p in topo.policies
            )
        ]
        directions: tuple[Direction, ...] = ("Ingress", "Egress")
        violations.extend(
            Violation("not-isolated", f"{endpoint.name} is not isolated for {direction.lower()}")
            for endpoint in managed
            for direction in directions
            if not topo.is_isolated(endpoint, direction)
        )
        return violations

    def _exclusive_ingress(
        self, intent: ZeroTrustIntent, ports: frozenset[PortKey]
    ) -> list[Violation]:
        topo = self.topology
        violations: list[Violation] = []
        for rule in intent.exclusive_ingress:
            dst = topo.endpoint(rule.dst)
            for src in topo.endpoints.values():
                if src is dst:
                    continue
                for protocol, port in sorted(ports):
                    if not topo.ingress_allowed(src, dst, protocol, port):
                        continue
                    if src.name not in rule.sources or (protocol, port) not in rule.ports:
                        violations.append(
                            Violation(
                                "exclusive-ingress",
                                f"{dst.name} admits {src.name} on {protocol}/{port}",
                            )
                        )
            for src_name, key in product(sorted(rule.sources), sorted(rule.ports)):
                if not topo.ingress_allowed(topo.endpoint(src_name), dst, *key):
                    violations.append(
                        Violation(
                            "exclusive-ingress",
                            f"{dst.name} does not admit {src_name} on {key[0]}/{key[1]}",
                        )
                    )
        return violations

    def _dns_egress(self, intent: ZeroTrustIntent) -> list[Violation]:
        topo = self.topology
        clients = [e for e in topo.endpoints.values() if e.requires_dns]
        if not clients:
            return []
        dns = topo.endpoint(intent.dns_endpoint)
        return [
            Violation(
                "missing-dns-egress", f"{client.name} cannot resolve names ({protocol}/{DNS_PORT})"
            )
            for client in clients
            for protocol in ("UDP", "TCP")
            if not topo.allows(Flow(client.name, dns.name, protocol, DNS_PORT))
        ]


def _selects_all(policy: NetworkPolicy) -> bool:
    selector = policy.spec.pod_selector
    return not selector.match_labels and not selector.match_expressions
