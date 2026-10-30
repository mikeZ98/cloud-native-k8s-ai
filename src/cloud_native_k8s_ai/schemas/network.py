"""Zero-trust NetworkPolicy contracts: default deny, DNS egress and Qdrant isolation.

Rules must name their peers explicitly: an ingress rule without ``from`` (or an egress
rule without ``to``) would allow every source/destination and is rejected.
"""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from cloud_native_k8s_ai.schemas._base import (
    Cidr,
    DNS1123Label,
    K8sModel,
    Labels,
    LabelSelector,
    ObjectMeta,
    Port,
    PortName,
    Protocol,
    ip_network,
)
from cloud_native_k8s_ai.schemas.storage import QDRANT_GRPC_PORT, QDRANT_REST_PORT

PolicyType = Literal["Ingress", "Egress"]

DNS_PORT = 53
KUBE_SYSTEM_NAMESPACE_LABEL = {"kubernetes.io/metadata.name": "kube-system"}
KUBE_DNS_POD_LABEL = {"k8s-app": "kube-dns"}


class IPBlock(K8sModel):
    cidr: Cidr
    except_: tuple[Cidr, ...] = Field(default=(), alias="except")

    @model_validator(mode="after")
    def _exceptions_inside_block(self) -> Self:
        outer = ip_network(self.cidr)
        for item in self.except_:
            inner = ip_network(item)
            if inner.version != outer.version or not inner.subnet_of(outer):  # type: ignore[arg-type]
                raise ValueError(f"except {item} is not inside {self.cidr}")
            if inner == outer:
                raise ValueError(f"except {item} would exclude the whole block")
        return self


class NetworkPolicyPeer(K8sModel):
    """Selects pods (optionally in other namespaces) or an IP block, never both."""

    pod_selector: LabelSelector | None = None
    namespace_selector: LabelSelector | None = None
    ip_block: IPBlock | None = None

    @model_validator(mode="after")
    def _one_kind(self) -> Self:
        selectors = self.pod_selector is not None or self.namespace_selector is not None
        if selectors == (self.ip_block is not None):
            raise ValueError("peer needs podSelector/namespaceSelector or ipBlock (exclusive)")
        return self


class NetworkPolicyPort(K8sModel):
    protocol: Protocol = "TCP"
    port: Port | PortName | None = None
    end_port: Port | None = None

    @model_validator(mode="after")
    def _valid_range(self) -> Self:
        if self.end_port is not None and (
            not isinstance(self.port, int) or self.end_port < self.port
        ):
            raise ValueError("endPort requires a numeric port and must be >= port")
        return self


class NetworkPolicyIngressRule(K8sModel):
    from_: tuple[NetworkPolicyPeer, ...] = Field(alias="from", min_length=1)
    ports: tuple[NetworkPolicyPort, ...] = ()


class NetworkPolicyEgressRule(K8sModel):
    to: tuple[NetworkPolicyPeer, ...] = Field(min_length=1)
    ports: tuple[NetworkPolicyPort, ...] = ()


class NetworkPolicySpec(K8sModel):
    pod_selector: LabelSelector
    """Pods this policy applies to; ``{}`` selects every pod in the namespace."""
    policy_types: tuple[PolicyType, ...] = Field(min_length=1, max_length=2)
    ingress: tuple[NetworkPolicyIngressRule, ...] = ()
    egress: tuple[NetworkPolicyEgressRule, ...] = ()

    @model_validator(mode="after")
    def _rules_match_types(self) -> Self:
        if len(set(self.policy_types)) != len(self.policy_types):
            raise ValueError("duplicate policyTypes")
        if self.ingress and "Ingress" not in self.policy_types:
            raise ValueError("ingress rules require policyType Ingress")
        if self.egress and "Egress" not in self.policy_types:
            raise ValueError("egress rules require policyType Egress")
        return self

    @property
    def denies_all(self) -> bool:
        """Isolates selected pods in both directions without allowing anything."""
        both = set(self.policy_types) == {"Ingress", "Egress"}
        return both and not self.ingress and not self.egress


class NetworkPolicy(K8sModel):
    api_version: Literal["networking.k8s.io/v1"] = "networking.k8s.io/v1"
    kind: Literal["NetworkPolicy"] = "NetworkPolicy"
    metadata: ObjectMeta
    spec: NetworkPolicySpec


# ---------------------------------------------------------------------------
# Baseline policies
# ---------------------------------------------------------------------------
def default_deny_policy(namespace: DNS1123Label) -> NetworkPolicy:
    """Deny all ingress and egress for every pod in ``namespace``."""
    return NetworkPolicy(
        metadata=ObjectMeta(name="default-deny-all", namespace=namespace),
        spec=NetworkPolicySpec(pod_selector=LabelSelector(), policy_types=("Ingress", "Egress")),
    )


def dns_egress_policy(namespace: DNS1123Label) -> NetworkPolicy:
    """Allow every pod in ``namespace`` to resolve names via kube-dns (UDP/TCP 53)."""
    return NetworkPolicy(
        metadata=ObjectMeta(name="allow-dns-egress", namespace=namespace),
        spec=NetworkPolicySpec(
            pod_selector=LabelSelector(),
            policy_types=("Egress",),
            egress=(
                NetworkPolicyEgressRule(
                    to=(
                        NetworkPolicyPeer(
                            namespace_selector=LabelSelector(
                                match_labels=dict(KUBE_SYSTEM_NAMESPACE_LABEL)
                            ),
                            pod_selector=LabelSelector(match_labels=dict(KUBE_DNS_POD_LABEL)),
                        ),
                    ),
                    ports=(
                        NetworkPolicyPort(protocol="UDP", port=DNS_PORT),
                        NetworkPolicyPort(protocol="TCP", port=DNS_PORT),
                    ),
                ),
            ),
        ),
    )


def qdrant_ingress_policy(
    namespace: DNS1123Label,
    *,
    qdrant_labels: Labels,
    app_labels: Labels,
    rest_port: Port = QDRANT_REST_PORT,
    grpc_port: Port = QDRANT_GRPC_PORT,
) -> NetworkPolicy:
    """Admit traffic to Qdrant only from FastAPI app pods in the same namespace."""
    if not qdrant_labels or not app_labels:
        raise ValueError("Qdrant isolation needs non-empty Qdrant and app pod labels")
    return NetworkPolicy(
        metadata=ObjectMeta(name="qdrant-allow-from-app", namespace=namespace),
        spec=NetworkPolicySpec(
            pod_selector=LabelSelector(match_labels=dict(qdrant_labels)),
            policy_types=("Ingress",),
            ingress=(
                NetworkPolicyIngressRule(
                    from_=(
                        NetworkPolicyPeer(
                            pod_selector=LabelSelector(match_labels=dict(app_labels))
                        ),
                    ),
                    ports=(
                        NetworkPolicyPort(port=rest_port),
                        NetworkPolicyPort(port=grpc_port),
                    ),
                ),
            ),
        ),
    )
