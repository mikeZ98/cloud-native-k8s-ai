"""Workload contracts: containers, probes, resources, Deployments, Services and the FastAPI app.

Every container must declare CPU and memory requests and limits, readiness and liveness
probes, and a restricted security context (non-root, read-only root filesystem, no
privilege escalation, all capabilities dropped).
"""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import Field, StringConstraints, model_validator

from cloud_native_k8s_ai.schemas._base import (
    AbsolutePath,
    CpuQuantity,
    DNS1123Label,
    DNS1123Subdomain,
    ImageRef,
    K8sModel,
    LabelKey,
    Labels,
    LabelSelector,
    MemoryQuantity,
    ObjectMeta,
    Port,
    PortName,
    Protocol,
    cpu_millicores,
    memory_bytes,
)

FASTAPI_DEFAULT_PORT = 8000

EnvVarName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$", max_length=253)]
IntOrPercent = int | Annotated[str, StringConstraints(pattern=r"^(100|[1-9]?[0-9])%$")]
NonNegativeInt = Annotated[int, Field(ge=0)]


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------
class ResourceList(K8sModel):
    cpu: CpuQuantity
    memory: MemoryQuantity


class ResourceRequirements(K8sModel):
    """Requests and limits; both CPU and memory are mandatory and requests must fit limits."""

    requests: ResourceList
    limits: ResourceList

    @model_validator(mode="after")
    def _requests_within_limits(self) -> Self:
        if cpu_millicores(self.requests.cpu) > cpu_millicores(self.limits.cpu):
            raise ValueError(f"cpu request {self.requests.cpu} exceeds limit {self.limits.cpu}")
        if memory_bytes(self.requests.memory) > memory_bytes(self.limits.memory):
            raise ValueError(
                f"memory request {self.requests.memory} exceeds limit {self.limits.memory}"
            )
        return self


# ---------------------------------------------------------------------------
# Ports & probes
# ---------------------------------------------------------------------------
class ContainerPort(K8sModel):
    name: PortName
    container_port: Port
    protocol: Protocol = "TCP"


class HTTPGetAction(K8sModel):
    path: AbsolutePath
    port: Port | PortName
    scheme: Literal["HTTP", "HTTPS"] = "HTTP"


class TCPSocketAction(K8sModel):
    port: Port | PortName


class GRPCAction(K8sModel):
    port: Port
    service: str | None = None


class Probe(K8sModel):
    """Exactly one handler (``httpGet``, ``tcpSocket`` or ``grpc``) plus timing thresholds."""

    http_get: HTTPGetAction | None = None
    tcp_socket: TCPSocketAction | None = None
    grpc: GRPCAction | None = None
    initial_delay_seconds: NonNegativeInt = 0
    period_seconds: int = Field(default=10, ge=1, le=3600)
    timeout_seconds: int = Field(default=1, ge=1, le=3600)
    success_threshold: int = Field(default=1, ge=1, le=100)
    failure_threshold: int = Field(default=3, ge=1, le=100)

    @model_validator(mode="after")
    def _exactly_one_handler(self) -> Self:
        handlers = [h for h in (self.http_get, self.tcp_socket, self.grpc) if h is not None]
        if len(handlers) != 1:
            raise ValueError("probe needs exactly one of httpGet, tcpSocket or grpc")
        return self

    @property
    def port(self) -> int | str:
        """Port of the single configured handler (guaranteed by ``_exactly_one_handler``)."""
        handlers = (self.http_get, self.tcp_socket, self.grpc)
        return next(h for h in handlers if h is not None).port


# ---------------------------------------------------------------------------
# Security contexts
# ---------------------------------------------------------------------------
class SeccompProfile(K8sModel):
    type: Literal["RuntimeDefault", "Localhost"] = "RuntimeDefault"
    localhost_profile: str | None = None

    @model_validator(mode="after")
    def _localhost_needs_profile(self) -> Self:
        if (self.type == "Localhost") != (self.localhost_profile is not None):
            raise ValueError("localhostProfile is required for, and only for, type Localhost")
        return self


class Capabilities(K8sModel):
    drop: tuple[Literal["ALL"]] = ("ALL",)
    add: tuple[Literal["NET_BIND_SERVICE"], ...] = ()


class SecurityContext(K8sModel):
    """Container security context pinned to the Pod Security ``restricted`` profile."""

    run_as_non_root: Literal[True] = True
    run_as_user: int = Field(default=10001, ge=1)
    run_as_group: int = Field(default=10001, ge=1)
    read_only_root_filesystem: Literal[True] = True
    allow_privilege_escalation: Literal[False] = False
    privileged: Literal[False] = False
    capabilities: Capabilities = Field(default_factory=Capabilities)
    seccomp_profile: SeccompProfile = Field(default_factory=SeccompProfile)


class PodSecurityContext(K8sModel):
    run_as_non_root: Literal[True] = True
    run_as_user: int = Field(default=10001, ge=1)
    run_as_group: int = Field(default=10001, ge=1)
    fs_group: int = Field(default=10001, ge=1)
    fs_group_change_policy: Literal["OnRootMismatch", "Always"] = "OnRootMismatch"
    seccomp_profile: SeccompProfile = Field(default_factory=SeccompProfile)


# ---------------------------------------------------------------------------
# Environment & volumes
# ---------------------------------------------------------------------------
class SecretKeySelector(K8sModel):
    name: DNS1123Subdomain
    key: Annotated[str, StringConstraints(pattern=r"^[-._A-Za-z0-9]+$", max_length=253)]


class EnvVarSource(K8sModel):
    secret_key_ref: SecretKeySelector


class EnvVar(K8sModel):
    """Plain value or secret reference, never both; secrets never appear inline."""

    name: EnvVarName
    value: str | None = None
    value_from: EnvVarSource | None = None

    @model_validator(mode="after")
    def _one_source(self) -> Self:
        if (self.value is None) == (self.value_from is None):
            raise ValueError(f"env var {self.name} needs exactly one of value or valueFrom")
        return self


class VolumeMount(K8sModel):
    name: DNS1123Label
    mount_path: AbsolutePath
    read_only: bool = False
    sub_path: str | None = None


class EmptyDirVolumeSource(K8sModel):
    medium: Literal["", "Memory"] = ""
    size_limit: MemoryQuantity | None = None


class ConfigMapVolumeSource(K8sModel):
    name: DNS1123Subdomain
    default_mode: int = Field(default=0o444, ge=0, le=0o777)


class PersistentVolumeClaimVolumeSource(K8sModel):
    claim_name: DNS1123Subdomain
    read_only: bool = False


class Volume(K8sModel):
    name: DNS1123Label
    empty_dir: EmptyDirVolumeSource | None = None
    config_map: ConfigMapVolumeSource | None = None
    persistent_volume_claim: PersistentVolumeClaimVolumeSource | None = None

    @model_validator(mode="after")
    def _exactly_one_source(self) -> Self:
        sources = (self.empty_dir, self.config_map, self.persistent_volume_claim)
        if sum(s is not None for s in sources) != 1:
            raise ValueError(f"volume {self.name} needs exactly one source")
        return self


# ---------------------------------------------------------------------------
# Containers & pods
# ---------------------------------------------------------------------------
class Container(K8sModel):
    name: DNS1123Label
    image: ImageRef
    image_pull_policy: Literal["IfNotPresent", "Always"] = "IfNotPresent"
    args: tuple[str, ...] | None = None
    ports: tuple[ContainerPort, ...] = ()
    env: tuple[EnvVar, ...] = ()
    resources: ResourceRequirements
    readiness_probe: Probe
    liveness_probe: Probe
    startup_probe: Probe | None = None
    volume_mounts: tuple[VolumeMount, ...] = ()
    security_context: SecurityContext = Field(default_factory=SecurityContext)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        names = [p.name for p in self.ports]
        numbers = [(p.container_port, p.protocol) for p in self.ports]
        if len(set(names)) != len(names) or len(set(numbers)) != len(numbers):
            raise ValueError(f"container {self.name} declares duplicate ports")
        env_names = [e.name for e in self.env]
        if len(set(env_names)) != len(env_names):
            raise ValueError(f"container {self.name} declares duplicate env vars")
        mount_paths = [m.mount_path for m in self.volume_mounts]
        if len(set(mount_paths)) != len(mount_paths):
            raise ValueError(f"container {self.name} mounts two volumes at the same path")
        if self.liveness_probe.success_threshold != 1:
            raise ValueError("livenessProbe.successThreshold must be 1")
        for probe in (self.readiness_probe, self.liveness_probe, self.startup_probe):
            if probe is not None and isinstance(probe.port, str) and probe.port not in names:
                raise ValueError(f"probe references unknown port name {probe.port!r}")
        return self


class PodSpec(K8sModel):
    containers: tuple[Container, ...] = Field(min_length=1)
    volumes: tuple[Volume, ...] = ()
    service_account_name: DNS1123Subdomain | None = None
    automount_service_account_token: bool = False
    security_context: PodSecurityContext = Field(default_factory=PodSecurityContext)
    termination_grace_period_seconds: int = Field(default=30, ge=0, le=3600)
    node_selector: dict[LabelKey, str] | None = None

    @model_validator(mode="after")
    def _unique_names(self) -> Self:
        for kind, names in (
            ("container", [c.name for c in self.containers]),
            ("volume", [v.name for v in self.volumes]),
        ):
            if len(set(names)) != len(names):
                raise ValueError(f"duplicate {kind} names in pod spec")
        return self

    def mounted_volume_names(self) -> set[str]:
        return {m.name for c in self.containers for m in c.volume_mounts}


class PodTemplateSpec(K8sModel):
    metadata: ObjectMeta
    spec: PodSpec


def check_selector_matches_template(selector: LabelSelector, template: PodTemplateSpec) -> None:
    """Workload controllers reject selectors that do not select their own pod template."""
    if not selector.matches(template.metadata.labels or {}):
        raise ValueError("selector does not match the pod template labels")


# ---------------------------------------------------------------------------
# Deployment & Service
# ---------------------------------------------------------------------------
class RollingUpdate(K8sModel):
    max_surge: IntOrPercent = "25%"
    max_unavailable: IntOrPercent = 0

    @model_validator(mode="after")
    def _can_progress(self) -> Self:
        for value in (self.max_surge, self.max_unavailable):
            if isinstance(value, int) and value < 0:
                raise ValueError("rolling update bounds must be non-negative")
        if self.max_surge in (0, "0%") and self.max_unavailable in (0, "0%"):
            raise ValueError("maxSurge and maxUnavailable cannot both be zero")
        return self


class DeploymentStrategy(K8sModel):
    type: Literal["RollingUpdate", "Recreate"] = "RollingUpdate"
    rolling_update: RollingUpdate | None = None
    """Unset means the API server defaults (25% / 25%); ``DeploymentSpec`` sets explicit ones."""

    @model_validator(mode="after")
    def _rolling_update_only_for_rolling(self) -> Self:
        if self.type == "Recreate" and self.rolling_update is not None:
            raise ValueError("rollingUpdate must be unset for the Recreate strategy")
        return self


class DeploymentSpec(K8sModel):
    replicas: int = Field(default=2, ge=0, le=1000)
    revision_history_limit: int = Field(default=5, ge=0, le=100)
    selector: LabelSelector
    strategy: DeploymentStrategy = Field(
        default_factory=lambda: DeploymentStrategy(rolling_update=RollingUpdate())
    )
    template: PodTemplateSpec

    @model_validator(mode="after")
    def _well_formed(self) -> Self:
        check_selector_matches_template(self.selector, self.template)
        declared = {v.name for v in self.template.spec.volumes}
        if missing := self.template.spec.mounted_volume_names() - declared:
            raise ValueError(f"volume mounts reference undeclared volumes: {sorted(missing)}")
        return self


class Deployment(K8sModel):
    api_version: Literal["apps/v1"] = "apps/v1"
    kind: Literal["Deployment"] = "Deployment"
    metadata: ObjectMeta
    spec: DeploymentSpec


class ServicePort(K8sModel):
    name: PortName
    port: Port
    target_port: Port | PortName
    protocol: Protocol = "TCP"


class ServiceSpec(K8sModel):
    type: Literal["ClusterIP", "NodePort", "LoadBalancer"] = "ClusterIP"
    cluster_ip: Literal["None"] | None = Field(default=None, alias="clusterIP")
    """``"None"`` makes the service headless (StatefulSet peer discovery)."""
    selector: Labels = Field(min_length=1)
    ports: tuple[ServicePort, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_ports(self) -> Self:
        names = [p.name for p in self.ports]
        numbers = [(p.port, p.protocol) for p in self.ports]
        if len(set(names)) != len(names) or len(set(numbers)) != len(numbers):
            raise ValueError("service declares duplicate ports")
        if self.cluster_ip == "None" and self.type != "ClusterIP":
            raise ValueError("only ClusterIP services can be headless")
        return self


class Service(K8sModel):
    api_version: Literal["v1"] = "v1"
    kind: Literal["Service"] = "Service"
    metadata: ObjectMeta
    spec: ServiceSpec


# ---------------------------------------------------------------------------
# FastAPI inference service (domain input for manifest generation)
# ---------------------------------------------------------------------------
class FastAPIAppSpec(K8sModel):
    """High-level contract for the FastAPI inference microservice."""

    name: DNS1123Label = "inference-api"
    image: ImageRef
    replicas: int = Field(default=2, ge=0, le=1000)
    container_port: Port = FASTAPI_DEFAULT_PORT
    service_port: Port = 80
    resources: ResourceRequirements
    liveness_path: AbsolutePath = "/healthz"
    readiness_path: AbsolutePath = "/readyz"
    env: tuple[EnvVar, ...] = ()
    labels: Labels = Field(default_factory=dict)
