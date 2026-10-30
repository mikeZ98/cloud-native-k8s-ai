"""Manifest generator: deterministic multi-document YAML for the full AI stack.

``ManifestBundle`` is an immutable, ordered set of Kubernetes objects with a YAML engine
that emits manifests in a stable kind order and canonical key order, using only plain
YAML (safe dumper, double quotes where quoting is required, no tags or anchors).
``AIStackGenerator`` builds the FastAPI, Qdrant, Redis, KEDA and NetworkPolicy objects
from ``InfraSettings`` and an ``AIStackSpec``; ``compile`` also runs the zero-trust solver.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Final

import yaml
from pydantic import Field, ValidationError

from cloud_native_k8s_ai.core.autoscaler import (
    AutoscalingPolicy,
    AutoscalingResolver,
    ResourceBudget,
    service_host,
)
from cloud_native_k8s_ai.core.errors import ManifestRenderError, ResourceConstraintError
from cloud_native_k8s_ai.core.topology import (
    NAMESPACE_NAME_LABEL,
    Endpoint,
    ExclusiveIngress,
    Flow,
    NetworkTopology,
    TopologySolver,
    ZeroTrustIntent,
)
from cloud_native_k8s_ai.schemas import (
    DNS_PORT,
    Container,
    ContainerPort,
    Deployment,
    DeploymentSpec,
    DeploymentStrategy,
    DNS1123Label,
    EmptyDirVolumeSource,
    EnvVar,
    FastAPIAppSpec,
    HTTPGetAction,
    InfraSettings,
    K8sModel,
    Labels,
    LabelSelector,
    NetworkPolicy,
    NetworkPolicyEgressRule,
    NetworkPolicyIngressRule,
    NetworkPolicyPeer,
    NetworkPolicyPort,
    NetworkPolicySpec,
    ObjectMeta,
    PersistentVolumeClaim,
    PersistentVolumeClaimSpec,
    PersistentVolumeClaimTemplate,
    PersistentVolumeClaimVolumeSource,
    PodSpec,
    PodTemplateSpec,
    Probe,
    QdrantSpec,
    RedisSpec,
    ScaledObject,
    Service,
    ServicePort,
    ServiceSpec,
    StatefulSet,
    StatefulSetSpec,
    StorageRequest,
    TCPSocketAction,
    Volume,
    VolumeMount,
    VolumeResourceRequirements,
    default_deny_policy,
    dns_egress_policy,
    qdrant_ingress_policy,
)

type Manifest = (
    Deployment | Service | StatefulSet | PersistentVolumeClaim | ScaledObject | NetworkPolicy
)
type Workload = Deployment | StatefulSet

MANIFEST_TYPES: Final[tuple[type[K8sModel], ...]] = (
    NetworkPolicy,
    PersistentVolumeClaim,
    Service,
    Deployment,
    StatefulSet,
    ScaledObject,
)
"""Apply order: isolate the namespace first, then storage, services, workloads, scalers."""

TOP_LEVEL_ORDER: Final = ("apiVersion", "kind", "metadata", "spec", "data", "status")
_STRING_MAPS: Final = frozenset(
    {"labels", "matchLabels", "annotations", "selector", "nodeSelector"}
)

SCRATCH_PATH: Final = "/scratch"
"""Writable emptyDir for temp files; the root filesystem is read-only."""

_KIND_RANK: Final = {cls.model_fields["kind"].default: i for i, cls in enumerate(MANIFEST_TYPES)}
_REGISTRY: Final[dict[tuple[str, str], type[K8sModel]]] = {
    (cls.model_fields["api_version"].default, cls.model_fields["kind"].default): cls
    for cls in MANIFEST_TYPES
}


# ---------------------------------------------------------------------------
# YAML engine
# ---------------------------------------------------------------------------
class _ManifestDumper(yaml.SafeDumper):
    """Safe dumper: indented sequences, double-quoted strings, no anchors/aliases."""

    # PyYAML's signature: positional booleans; ``indentless`` is overridden on purpose.
    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:  # noqa: ARG002, FBT001, FBT002
        super().increase_indent(flow=flow, indentless=False)

    def choose_scalar_style(self) -> str:
        style: str = super().choose_scalar_style()
        return '"' if style == "'" else style

    def ignore_aliases(self, data: Any) -> bool:  # noqa: ARG002 - never emit anchors
        return True


def canonical(document: Mapping[str, Any]) -> dict[str, Any]:
    """Kubernetes key order at the top level; string maps (labels, selectors) sorted."""
    head = [k for k in TOP_LEVEL_ORDER if k in document]
    tail = [k for k in document if k not in TOP_LEVEL_ORDER]
    return {k: _normalize(k, document[k]) for k in (*head, *tail)}


def _normalize(key: str, value: Any) -> Any:
    if isinstance(value, dict):
        if key in _STRING_MAPS and all(isinstance(v, str) for v in value.values()):
            return {k: value[k] for k in sorted(value)}
        return {k: _normalize(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize("", item) for item in value]
    return value


def render_yaml(documents: Sequence[Mapping[str, Any]]) -> str:
    """Multi-document YAML (``---`` before every document)."""
    try:
        return yaml.dump_all(
            [canonical(d) for d in documents],
            Dumper=_ManifestDumper,
            explicit_start=True,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=True,
            width=100,
        )
    except yaml.YAMLError as exc:
        raise ManifestRenderError(f"cannot serialize manifests: {exc}") from exc


def parse_yaml(text: str) -> list[dict[str, Any]]:
    """Parse multi-document YAML with ``yaml.safe_load_all``; empty documents are skipped."""
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise ManifestRenderError(f"invalid YAML: {exc}") from exc
    parsed: list[dict[str, Any]] = []
    for index, document in enumerate(documents):
        if document is None:
            continue
        if not isinstance(document, dict):
            raise ManifestRenderError(f"document {index} is not a mapping")
        parsed.append(document)
    return parsed


MAX_YAML_DEPTH: Final = 64
"""Deepest collection nesting accepted from clients (real manifests stay below ~20)."""


def screen_untrusted_yaml(text: str) -> None:
    """Refuse YAML that is dangerous to load, scanning the event stream only.

    Anchors/aliases are refused (expanding them on serialization is a billion-laughs
    bomb), and so is nesting beyond ``MAX_YAML_DEPTH``: PyYAML builds objects
    recursively, so a few kilobytes of ``[[[[...`` would exhaust the stack. The parser
    itself is iterative, so screening stops at the first offending event.
    """
    depth = 0
    try:
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                raise ManifestRenderError("YAML anchors and aliases are not accepted")
            if isinstance(event, yaml.CollectionStartEvent):
                depth += 1
                if depth > MAX_YAML_DEPTH:
                    raise ManifestRenderError(
                        f"YAML nesting deeper than {MAX_YAML_DEPTH} levels is not accepted"
                    )
            elif isinstance(event, yaml.CollectionEndEvent):
                depth -= 1
    except yaml.YAMLError as exc:
        raise ManifestRenderError(f"invalid YAML: {exc}") from exc


def parse_untrusted_yaml(text: str) -> list[dict[str, Any]]:
    """``parse_yaml`` for client-supplied text, after ``screen_untrusted_yaml``."""
    screen_untrusted_yaml(text)
    return parse_yaml(text)


@contextmanager
def _rendering(what: str) -> Iterator[None]:
    try:
        yield
    except ValidationError as exc:
        raise ManifestRenderError(f"cannot render {what}: {exc}") from exc


# ---------------------------------------------------------------------------
# Bundle
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ManifestBundle:
    """Immutable set of manifests, unique by ``(kind, namespace, name)``."""

    resources: tuple[Manifest, ...] = ()

    def __post_init__(self) -> None:
        seen: set[tuple[str, str | None, str]] = set()
        for resource in self.resources:
            key = (resource.kind, resource.metadata.namespace, resource.metadata.name)
            if key in seen:
                raise ManifestRenderError(
                    f"duplicate {resource.kind} {resource.metadata.namespace}/"
                    f"{resource.metadata.name}"
                )
            seen.add(key)

    def __len__(self) -> int:
        return len(self.resources)

    def __iter__(self) -> Iterator[Manifest]:
        return iter(self.ordered())

    def add(self, *resources: Manifest) -> ManifestBundle:
        return ManifestBundle((*self.resources, *resources))

    def of_kind[M: K8sModel](self, kind: type[M]) -> tuple[M, ...]:
        return tuple(r for r in self.ordered() if isinstance(r, kind))

    def get[M: K8sModel](self, kind: type[M], name: str) -> M:
        for resource in self.ordered():
            if isinstance(resource, kind) and resource.metadata.name == name:
                return resource
        raise ManifestRenderError(f"no {kind.__name__} named {name!r} in bundle")

    def workloads(self) -> tuple[Workload, ...]:
        return tuple(r for r in self.ordered() if isinstance(r, Deployment | StatefulSet))

    def ordered(self) -> tuple[Manifest, ...]:
        return tuple(
            sorted(
                self.resources,
                key=lambda r: (_KIND_RANK[r.kind], r.metadata.namespace or "", r.metadata.name),
            )
        )

    def to_documents(self) -> list[dict[str, Any]]:
        return [canonical(r.to_k8s()) for r in self.ordered()]

    def to_yaml(self) -> str:
        return render_yaml(self.to_documents())

    @classmethod
    def from_yaml(cls, text: str) -> ManifestBundle:
        resources: list[Manifest] = []
        for document in parse_yaml(text):
            key = (document.get("apiVersion"), document.get("kind"))
            model = _REGISTRY.get(key)  # type: ignore[arg-type]
            if model is None:
                raise ManifestRenderError(f"unsupported manifest type {key[0]}/{key[1]}")
            name = document.get("metadata", {}).get("name", "?")
            with _rendering(f"{key[1]} {name}"):
                resources.append(model.from_wire(document))  # type: ignore[arg-type]
        return cls(tuple(resources))


# ---------------------------------------------------------------------------
# AI stack
# ---------------------------------------------------------------------------
class AIStackSpec(K8sModel):
    """Everything the generator needs beyond ``InfraSettings``."""

    app: FastAPIAppSpec
    qdrant: QdrantSpec
    redis: RedisSpec
    autoscaling: AutoscalingPolicy = Field(default_factory=AutoscalingPolicy)
    budget: ResourceBudget | None = None
    ingress_namespace: DNS1123Label = "ingress-nginx"
    """Namespace of the ingress controller allowed to reach the API."""
    keda_namespace: DNS1123Label = "keda"
    keda_operator_labels: Labels = Field(default_factory=lambda: {"app": "keda-operator"})
    """Pod labels of the KEDA operator, which polls Redis for the queue length."""


COMPONENT_LABEL = "app.kubernetes.io/component"
NAME_LABEL = "app.kubernetes.io/name"
KUBE_DNS_LABELS: Final = {"k8s-app": "kube-dns"}
INGRESS_CONTROLLER_LABELS: Final = {"app.kubernetes.io/name": "ingress-nginx"}
UNTRUSTED_NAMESPACE = "untrusted"
INTERNET_PROBE_IP = "203.0.113.10"  # TEST-NET-3 (RFC 5737): never routable


class AIStackGenerator:
    """Builds and verifies the full AI stack for one namespace."""

    def __init__(self, settings: InfraSettings, stack: AIStackSpec) -> None:
        self.settings = settings
        self.stack = stack
        self.namespace = settings.namespace
        names = [stack.app.name, stack.qdrant.name, stack.redis.name]
        if len(set(names)) != len(names):
            raise ManifestRenderError(f"component names must be distinct, got {names}")
        if stack.qdrant.replicas != 1:
            raise ResourceConstraintError(
                "Qdrant must run with exactly 1 replica: distributed mode (p2p port 6335, "
                "consensus) is not generated"
            )

    # -- labels ---------------------------------------------------------
    def selector(self, name: str, component: str) -> Labels:
        """Immutable selector labels (never change them on a live workload)."""
        return {NAME_LABEL: name, COMPONENT_LABEL: component}

    def labels(self, name: str, component: str, extra: Mapping[str, str]) -> Labels:
        selector = self.selector(name, component)
        reserved = {**self.settings.common_labels, **selector}
        if clash := sorted(k for k in extra if k in reserved and extra[k] != reserved[k]):
            raise ManifestRenderError(f"{name}: labels {clash} are managed by the generator")
        return {**self.settings.common_labels, **extra, **selector}

    @property
    def app_selector(self) -> Labels:
        return self.selector(self.stack.app.name, "api")

    @property
    def qdrant_selector(self) -> Labels:
        return self.selector(self.stack.qdrant.name, "vector-store")

    @property
    def redis_selector(self) -> Labels:
        return self.selector(self.stack.redis.name, "broker")

    def _meta(self, name: str, labels: Labels) -> ObjectMeta:
        return ObjectMeta(name=name, namespace=self.namespace, labels=labels)

    # -- FastAPI --------------------------------------------------------
    def app_env(self) -> tuple[EnvVar, ...]:
        """Connection settings injected into the API container."""
        q, r, policy = self.stack.qdrant, self.stack.redis, self.stack.autoscaling
        scheme = "rediss" if policy.enable_tls else "redis"
        redis_url = (
            f"{scheme}://{service_host(r.name, self.namespace)}:{r.port}/{policy.database_index}"
        )
        return (
            EnvVar(name="QDRANT_HOST", value=service_host(q.name, self.namespace)),
            EnvVar(name="QDRANT_HTTP_PORT", value=str(q.rest_port)),
            EnvVar(name="QDRANT_GRPC_PORT", value=str(q.grpc_port)),
            EnvVar(name="REDIS_URL", value=redis_url),
            EnvVar(name="REDIS_QUEUE", value=policy.list_name),
            EnvVar(name="TMPDIR", value=SCRATCH_PATH),
        )

    def app_deployment(self) -> Deployment:
        app = self.stack.app
        labels = self.labels(app.name, "api", app.labels)
        with _rendering(f"Deployment {app.name}"):
            container = Container(
                name="api",
                image=app.image,
                ports=(ContainerPort(name="http", container_port=app.container_port),),
                env=(*self.app_env(), *app.env),
                resources=app.resources,
                readiness_probe=Probe(
                    http_get=HTTPGetAction(path=app.readiness_path, port="http"),
                    period_seconds=10,
                ),
                liveness_probe=Probe(
                    http_get=HTTPGetAction(path=app.liveness_path, port="http"),
                    period_seconds=20,
                ),
                # Model loading can take minutes; liveness only starts once this succeeds.
                startup_probe=Probe(
                    http_get=HTTPGetAction(path=app.liveness_path, port="http"),
                    period_seconds=5,
                    failure_threshold=60,
                ),
                volume_mounts=(VolumeMount(name="scratch", mount_path=SCRATCH_PATH),),
            )
            return Deployment(
                metadata=self._meta(app.name, labels),
                spec=DeploymentSpec(
                    replicas=app.replicas,
                    selector=LabelSelector(match_labels=self.app_selector),
                    template=PodTemplateSpec(
                        metadata=ObjectMeta(name=app.name, labels=labels),
                        spec=PodSpec(
                            containers=(container,),
                            volumes=(_scratch_volume(),),
                        ),
                    ),
                ),
            )

    def app_service(self) -> Service:
        app = self.stack.app
        with _rendering(f"Service {app.name}"):
            return Service(
                metadata=self._meta(app.name, self.labels(app.name, "api", app.labels)),
                spec=ServiceSpec(
                    selector=self.app_selector,
                    ports=(ServicePort(name="http", port=app.service_port, target_port="http"),),
                ),
            )

    # -- Qdrant ---------------------------------------------------------
    @property
    def qdrant_headless_name(self) -> str:
        return f"{self.stack.qdrant.name}-headless"

    def qdrant_statefulset(self) -> StatefulSet:
        q = self.stack.qdrant
        labels = self.labels(q.name, "vector-store", q.labels)
        with _rendering(f"StatefulSet {q.name}"):
            container = Container(
                name="qdrant",
                image=q.image,
                ports=(
                    ContainerPort(name="rest", container_port=q.rest_port),
                    ContainerPort(name="grpc", container_port=q.grpc_port),
                ),
                env=(
                    EnvVar(name="QDRANT__SERVICE__HTTP_PORT", value=str(q.rest_port)),
                    EnvVar(name="QDRANT__SERVICE__GRPC_PORT", value=str(q.grpc_port)),
                    EnvVar(name="QDRANT__STORAGE__STORAGE_PATH", value=q.storage.mount_path),
                    EnvVar(name="QDRANT__STORAGE__SNAPSHOTS_PATH", value=q.snapshots.mount_path),
                    EnvVar(name="TMPDIR", value=SCRATCH_PATH),
                ),
                resources=q.resources,
                readiness_probe=Probe(http_get=HTTPGetAction(path="/readyz", port="rest")),
                liveness_probe=Probe(
                    http_get=HTTPGetAction(path="/livez", port="rest"), period_seconds=20
                ),
                # WAL replay after a restart can be slow on large collections.
                startup_probe=Probe(
                    http_get=HTTPGetAction(path="/livez", port="rest"),
                    period_seconds=10,
                    failure_threshold=60,
                ),
                volume_mounts=(
                    VolumeMount(name="storage", mount_path=q.storage.mount_path),
                    VolumeMount(name="snapshots", mount_path=q.snapshots.mount_path),
                    VolumeMount(name="scratch", mount_path=SCRATCH_PATH),
                ),
            )
            return StatefulSet(
                metadata=self._meta(q.name, labels),
                spec=StatefulSetSpec(
                    service_name=self.qdrant_headless_name,
                    replicas=q.replicas,
                    selector=LabelSelector(match_labels=self.qdrant_selector),
                    template=PodTemplateSpec(
                        metadata=ObjectMeta(name=q.name, labels=labels),
                        spec=PodSpec(
                            containers=(container,),
                            volumes=(_scratch_volume(),),
                            termination_grace_period_seconds=60,
                        ),
                    ),
                    volume_claim_templates=(
                        _claim_template("storage", q.storage.size, q.storage.storage_class_name),
                        _claim_template(
                            "snapshots", q.snapshots.size, q.snapshots.storage_class_name
                        ),
                    ),
                ),
            )

    def qdrant_services(self) -> tuple[Service, Service]:
        """Headless service (stable pod DNS for the StatefulSet) and the client service."""
        q = self.stack.qdrant
        labels = self.labels(q.name, "vector-store", q.labels)
        ports = (
            ServicePort(name="rest", port=q.rest_port, target_port="rest"),
            ServicePort(name="grpc", port=q.grpc_port, target_port="grpc"),
        )
        with _rendering(f"Services for {q.name}"):
            headless = Service(
                metadata=self._meta(self.qdrant_headless_name, labels),
                spec=ServiceSpec(cluster_ip="None", selector=self.qdrant_selector, ports=ports),
            )
            client = Service(
                metadata=self._meta(q.name, labels),
                spec=ServiceSpec(selector=self.qdrant_selector, ports=ports),
            )
        return headless, client

    # -- Redis ----------------------------------------------------------
    @property
    def redis_claim_name(self) -> str:
        return f"{self.stack.redis.name}-data"

    def redis_pvc(self) -> PersistentVolumeClaim | None:
        r = self.stack.redis
        if r.persistence.volume_size is None:
            return None
        with _rendering(f"PersistentVolumeClaim {self.redis_claim_name}"):
            return PersistentVolumeClaim(
                metadata=self._meta(self.redis_claim_name, self.labels(r.name, "broker", r.labels)),
                spec=_claim_spec(r.persistence.volume_size, r.persistence.storage_class_name),
            )

    def redis_deployment(self) -> Deployment:
        r = self.stack.redis
        labels = self.labels(r.name, "broker", r.labels)
        with _rendering(f"Deployment {r.name}"):
            if r.persistence.volume_size is None:
                data = Volume(name="data", empty_dir=EmptyDirVolumeSource())
            else:
                data = Volume(
                    name="data",
                    persistent_volume_claim=PersistentVolumeClaimVolumeSource(
                        claim_name=self.redis_claim_name
                    ),
                )
            container = Container(
                name="redis",
                image=r.image,
                args=r.server_args(),
                ports=(ContainerPort(name="redis", container_port=r.port),),
                resources=r.resources,
                readiness_probe=Probe(tcp_socket=TCPSocketAction(port="redis"), period_seconds=5),
                liveness_probe=Probe(
                    tcp_socket=TCPSocketAction(port="redis"),
                    initial_delay_seconds=10,
                    period_seconds=10,
                ),
                volume_mounts=(VolumeMount(name="data", mount_path=r.data_mount_path),),
            )
            return Deployment(
                metadata=self._meta(r.name, labels),
                spec=DeploymentSpec(
                    replicas=1,
                    # A single writer on a ReadWriteOnce volume: never run two pods at once.
                    strategy=DeploymentStrategy(type="Recreate", rolling_update=None),
                    selector=LabelSelector(match_labels=self.redis_selector),
                    template=PodTemplateSpec(
                        metadata=ObjectMeta(name=r.name, labels=labels),
                        spec=PodSpec(containers=(container,), volumes=(data,)),
                    ),
                ),
            )

    def redis_service(self) -> Service:
        r = self.stack.redis
        with _rendering(f"Service {r.name}"):
            return Service(
                metadata=self._meta(r.name, self.labels(r.name, "broker", r.labels)),
                spec=ServiceSpec(
                    selector=self.redis_selector,
                    ports=(ServicePort(name="redis", port=r.port, target_port="redis"),),
                ),
            )

    # -- NetworkPolicies ------------------------------------------------
    def network_policies(self) -> tuple[NetworkPolicy, ...]:
        app, q, r, stack = self.stack.app, self.stack.qdrant, self.stack.redis, self.stack
        ns = self.namespace
        app_pods = NetworkPolicyPeer(pod_selector=LabelSelector(match_labels=self.app_selector))
        with _rendering("NetworkPolicies"):
            return (
                default_deny_policy(ns),
                dns_egress_policy(ns),
                qdrant_ingress_policy(
                    ns,
                    qdrant_labels=self.qdrant_selector,
                    app_labels=self.app_selector,
                    rest_port=q.rest_port,
                    grpc_port=q.grpc_port,
                ),
                NetworkPolicy(
                    metadata=ObjectMeta(name=f"{app.name}-allow-ingress", namespace=ns),
                    spec=NetworkPolicySpec(
                        pod_selector=LabelSelector(match_labels=self.app_selector),
                        policy_types=("Ingress",),
                        ingress=(
                            NetworkPolicyIngressRule(
                                from_=(_namespace_peer(stack.ingress_namespace),),
                                ports=(NetworkPolicyPort(port=app.container_port),),
                            ),
                        ),
                    ),
                ),
                NetworkPolicy(
                    metadata=ObjectMeta(name=f"{app.name}-allow-egress", namespace=ns),
                    spec=NetworkPolicySpec(
                        pod_selector=LabelSelector(match_labels=self.app_selector),
                        policy_types=("Egress",),
                        egress=(
                            NetworkPolicyEgressRule(
                                to=(
                                    NetworkPolicyPeer(
                                        pod_selector=LabelSelector(
                                            match_labels=self.qdrant_selector
                                        )
                                    ),
                                ),
                                ports=(
                                    NetworkPolicyPort(port=q.rest_port),
                                    NetworkPolicyPort(port=q.grpc_port),
                                ),
                            ),
                            NetworkPolicyEgressRule(
                                to=(
                                    NetworkPolicyPeer(
                                        pod_selector=LabelSelector(match_labels=self.redis_selector)
                                    ),
                                ),
                                ports=(NetworkPolicyPort(port=r.port),),
                            ),
                        ),
                    ),
                ),
                NetworkPolicy(
                    metadata=ObjectMeta(name=f"{r.name}-allow-ingress", namespace=ns),
                    spec=NetworkPolicySpec(
                        pod_selector=LabelSelector(match_labels=self.redis_selector),
                        policy_types=("Ingress",),
                        ingress=(
                            NetworkPolicyIngressRule(
                                from_=(
                                    app_pods,
                                    _namespace_peer(
                                        stack.keda_namespace, dict(stack.keda_operator_labels)
                                    ),
                                ),
                                ports=(NetworkPolicyPort(port=r.port),),
                            ),
                        ),
                    ),
                ),
            )

    # -- assembly -------------------------------------------------------
    def workloads_bundle(self) -> ManifestBundle:
        """Every object except the ScaledObject."""
        pvc = self.redis_pvc()
        return ManifestBundle(
            (
                *self.network_policies(),
                *((pvc,) if pvc is not None else ()),
                self.app_service(),
                *self.qdrant_services(),
                self.redis_service(),
                self.app_deployment(),
                self.redis_deployment(),
                self.qdrant_statefulset(),
            )
        )

    def build(self) -> ManifestBundle:
        """All manifests, with the KEDA ScaledObject bound to the API and the Redis broker."""
        return AutoscalingResolver(self.workloads_bundle()).bind(
            self.stack.autoscaling,
            target=self.stack.app.name,
            broker=self.stack.redis.name,
            budget=self.stack.budget,
        )

    def probe_endpoints(self) -> tuple[Endpoint, ...]:
        """Synthetic peers used to test the policies: infrastructure plus adversaries."""
        stack = self.stack
        mimics = [
            Endpoint(name=f"mimic-{name}", namespace=UNTRUSTED_NAMESPACE, labels=labels)
            for name, labels in (
                (stack.app.name, self.app_selector),
                (stack.qdrant.name, self.qdrant_selector),
                (stack.redis.name, self.redis_selector),
            )
        ]
        return (
            Endpoint(
                name="kube-dns",
                namespace="kube-system",
                labels=dict(KUBE_DNS_LABELS),
                ports={"dns": ("UDP", DNS_PORT), "dns-tcp": ("TCP", DNS_PORT)},
            ),
            Endpoint(
                name="keda-operator",
                namespace=stack.keda_namespace,
                labels=dict(stack.keda_operator_labels),
            ),
            Endpoint(
                name="ingress-controller",
                namespace=stack.ingress_namespace,
                labels=dict(INGRESS_CONTROLLER_LABELS),
            ),
            Endpoint(
                name="intruder",
                namespace=self.namespace,
                labels={NAME_LABEL: "intruder", COMPONENT_LABEL: "api"},
            ),
            *mimics,
            Endpoint(name="internet", ip=INTERNET_PROBE_IP),
        )

    def intent(self) -> ZeroTrustIntent:
        """The flows this stack is designed to allow, derived from the spec alone."""
        app, q, r = self.stack.app, self.stack.qdrant, self.stack.redis
        in_namespace = [app.name, q.name, r.name, "intruder"]
        return ZeroTrustIntent(
            required=frozenset(
                {
                    Flow("ingress-controller", app.name, "TCP", app.container_port),
                    Flow(app.name, q.name, "TCP", q.rest_port),
                    Flow(app.name, q.name, "TCP", q.grpc_port),
                    Flow(app.name, r.name, "TCP", r.port),
                    Flow("keda-operator", r.name, "TCP", r.port),
                }
            ),
            # The namespace-wide DNS policy lets every pod resolve names.
            permitted=frozenset(
                Flow(src, "kube-dns", protocol, DNS_PORT)
                for src in in_namespace
                for protocol in ("UDP", "TCP")
            ),
            exclusive_ingress=(
                ExclusiveIngress(
                    dst=q.name,
                    sources=frozenset({app.name}),
                    ports=frozenset({("TCP", q.rest_port), ("TCP", q.grpc_port)}),
                ),
                ExclusiveIngress(
                    dst=r.name,
                    sources=frozenset({app.name, "keda-operator"}),
                    ports=frozenset({("TCP", r.port)}),
                ),
                ExclusiveIngress(
                    dst=app.name,
                    sources=frozenset({"ingress-controller"}),
                    ports=frozenset({("TCP", app.container_port)}),
                ),
            ),
        )

    def topology(self, bundle: ManifestBundle) -> NetworkTopology:
        return NetworkTopology.from_bundle(
            bundle, self.probe_endpoints(), dns_clients={self.stack.app.name}
        )

    def compile(self) -> ManifestBundle:
        """Build every manifest and refuse to return them unless the topology is zero-trust."""
        bundle = self.build()
        TopologySolver(self.topology(bundle)).verify(self.intent()).raise_for_violations()
        return bundle


def build_ai_stack(settings: InfraSettings, stack: AIStackSpec) -> ManifestBundle:
    return AIStackGenerator(settings, stack).build()


def compile_ai_stack(settings: InfraSettings, stack: AIStackSpec) -> ManifestBundle:
    return AIStackGenerator(settings, stack).compile()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _scratch_volume() -> Volume:
    return Volume(name="scratch", empty_dir=EmptyDirVolumeSource(size_limit="1Gi"))


def _claim_spec(size: str, storage_class: str | None) -> PersistentVolumeClaimSpec:
    return PersistentVolumeClaimSpec(
        storage_class_name=storage_class,
        resources=VolumeResourceRequirements(requests=StorageRequest(storage=size)),
    )


def _claim_template(
    name: str, size: str, storage_class: str | None
) -> PersistentVolumeClaimTemplate:
    return PersistentVolumeClaimTemplate(
        metadata=ObjectMeta(name=name), spec=_claim_spec(size, storage_class)
    )


def _namespace_peer(namespace: str, pod_labels: Labels | None = None) -> NetworkPolicyPeer:
    return NetworkPolicyPeer(
        namespace_selector=LabelSelector(match_labels={NAMESPACE_NAME_LABEL: namespace}),
        pod_selector=LabelSelector(match_labels=pod_labels) if pod_labels else None,
    )
