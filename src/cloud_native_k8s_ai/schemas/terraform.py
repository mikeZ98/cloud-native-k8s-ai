"""Terraform bootstrap variables for EKS / GKE clusters (snake_case, as in ``*.tfvars.json``).

These models validate inputs before Terraform ever runs: provider-specific region and
machine-type formats, supported Kubernetes versions, node-pool autoscaling bounds and a
non-overlapping VPC / subnet / secondary-range layout.
"""

from __future__ import annotations

import re
from itertools import combinations
from typing import Annotated, Literal, Self

from pydantic import AfterValidator, Field, StringConstraints, model_validator

from cloud_native_k8s_ai.schemas._base import DNS1123Label, InfraModel, IPv4Cidr, LabelKey, network

CloudProvider = Literal["eks", "gke"]

MIN_KUBERNETES_MINOR = 31
"""Oldest Kubernetes minor version accepted for new clusters (``1.31``)."""

MAX_TOTAL_NODES = 1000
VPC_PREFIX_RANGE = (16, 24)

_K8S_VERSION_RE = re.compile(r"^1\.(?P<minor>[0-9]{2})$")
_REGION_RE: dict[CloudProvider, re.Pattern[str]] = {
    "eks": re.compile(r"^(?:us|eu|ap|sa|ca|me|af|il|mx)(?:-gov)?-[a-z]+-[0-9]$"),
    "gke": re.compile(r"^[a-z]+-[a-z]+[0-9]$"),
}
_MACHINE_TYPE_RE: dict[CloudProvider, re.Pattern[str]] = {
    "eks": re.compile(r"^[a-z][a-z0-9-]*\.[a-z0-9]+$"),  # m6i.xlarge, g5.2xlarge
    "gke": re.compile(r"^[a-z][a-z0-9]*-[a-z0-9-]+$"),  # e2-standard-4, g2-standard-8
}


def _supported_version(value: str) -> str:
    match = _K8S_VERSION_RE.match(value)
    if match is None:
        raise ValueError(f"invalid Kubernetes version {value!r}: expected '1.<minor>'")
    if int(match["minor"]) < MIN_KUBERNETES_MINOR:
        raise ValueError(f"Kubernetes {value} is older than 1.{MIN_KUBERNETES_MINOR}")
    return value


KubernetesVersion = Annotated[str, AfterValidator(_supported_version)]
TagKey = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,62}$")]
TagValue = Annotated[str, StringConstraints(pattern=r"^[a-z0-9_-]{0,63}$")]


class Taint(InfraModel):
    key: LabelKey
    value: Annotated[str, StringConstraints(max_length=63)] = ""
    effect: Literal["NoSchedule", "PreferNoSchedule", "NoExecute"]


class NodePool(InfraModel):
    """Managed node group / node pool with cluster-autoscaler bounds."""

    name: DNS1123Label
    machine_type: Annotated[str, StringConstraints(min_length=3, max_length=64)]
    min_size: int = Field(ge=0, le=MAX_TOTAL_NODES)
    max_size: int = Field(ge=1, le=MAX_TOTAL_NODES)
    desired_size: int = Field(ge=0, le=MAX_TOTAL_NODES)
    disk_size_gb: int = Field(default=100, ge=20, le=4000)
    capacity_type: Literal["on_demand", "spot"] = "on_demand"
    accelerator_type: Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]*$")] | None = (
        None
    )
    accelerator_count: int = Field(default=0, ge=0, le=16)
    labels: dict[LabelKey, str] = Field(default_factory=dict)
    taints: tuple[Taint, ...] = ()

    @model_validator(mode="after")
    def _bounds(self) -> Self:
        if not self.min_size <= self.desired_size <= self.max_size:
            raise ValueError(
                f"node pool {self.name}: need min_size <= desired_size <= max_size, got "
                f"{self.min_size} / {self.desired_size} / {self.max_size}"
            )
        if (self.accelerator_type is None) != (self.accelerator_count == 0):
            raise ValueError(
                f"node pool {self.name}: accelerator_type and accelerator_count go together"
            )
        return self


class VpcConfig(InfraModel):
    cidr: IPv4Cidr
    private_subnets: tuple[IPv4Cidr, ...] = Field(min_length=1)
    public_subnets: tuple[IPv4Cidr, ...] = ()
    pods_cidr: IPv4Cidr | None = None
    """GKE secondary range for pods (VPC-native); outside the VPC primary range."""
    services_cidr: IPv4Cidr | None = None
    """Cluster service range (GKE secondary range / EKS ``service_ipv4_cidr``)."""

    @model_validator(mode="after")
    def _layout(self) -> Self:
        vpc = network(self.cidr)
        low, high = VPC_PREFIX_RANGE
        if not low <= vpc.prefixlen <= high:
            raise ValueError(f"VPC CIDR {self.cidr} must be between /{low} and /{high}")
        subnets = (*self.private_subnets, *self.public_subnets)
        for subnet in subnets:
            if not network(subnet).subnet_of(vpc):  # type: ignore[arg-type]
                raise ValueError(f"subnet {subnet} is outside VPC {self.cidr}")
        secondary = tuple(c for c in (self.pods_cidr, self.services_cidr) if c is not None)
        for cidr in secondary:
            if network(cidr).overlaps(vpc):
                raise ValueError(f"secondary range {cidr} overlaps VPC {self.cidr}")
        for a, b in combinations((*subnets, *secondary), 2):
            if network(a).overlaps(network(b)):
                raise ValueError(f"CIDRs {a} and {b} overlap")
        return self


class ClusterBootstrapVars(InfraModel):
    """Root module variables for the EKS/GKE bootstrap (rendered to ``*.tfvars.json``)."""

    provider: CloudProvider
    region: Annotated[str, StringConstraints(min_length=4, max_length=32)]
    cluster_name: Annotated[DNS1123Label, StringConstraints(max_length=40)]
    kubernetes_version: KubernetesVersion
    vpc: VpcConfig
    node_pools: tuple[NodePool, ...] = Field(min_length=1)
    max_total_nodes: int = Field(default=100, ge=1, le=MAX_TOTAL_NODES)
    endpoint_public_access: bool = False
    authorized_cidrs: tuple[IPv4Cidr, ...] = ()
    tags: dict[TagKey, TagValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _provider_rules(self) -> Self:
        if not _REGION_RE[self.provider].match(self.region):
            raise ValueError(f"{self.region!r} is not a valid {self.provider} region")
        for pool in self.node_pools:
            if not _MACHINE_TYPE_RE[self.provider].match(pool.machine_type):
                raise ValueError(
                    f"node pool {pool.name}: {pool.machine_type!r} is not a {self.provider} "
                    "machine type"
                )
        names = [p.name for p in self.node_pools]
        if len(set(names)) != len(names):
            raise ValueError("node pool names must be unique")
        if (total := sum(p.max_size for p in self.node_pools)) > self.max_total_nodes:
            raise ValueError(f"node pools may scale to {total} nodes > max_total_nodes")
        if self.provider == "gke" and (
            self.vpc.pods_cidr is None or self.vpc.services_cidr is None
        ):
            raise ValueError("GKE (VPC-native) requires vpc.pods_cidr and vpc.services_cidr")
        if self.provider == "eks" and len(self.vpc.private_subnets) < 2:  # noqa: PLR2004
            raise ValueError("EKS requires private subnets in at least two availability zones")
        if self.endpoint_public_access:
            if not self.authorized_cidrs:
                raise ValueError("a public API endpoint requires authorized_cidrs")
            if any(network(c).prefixlen == 0 for c in self.authorized_cidrs):
                raise ValueError("authorized_cidrs must not include 0.0.0.0/0")
        return self

    def to_tfvars(self) -> dict[str, object]:
        """Variables as written to ``terraform.tfvars.json``."""
        return dict(self.to_wire())
