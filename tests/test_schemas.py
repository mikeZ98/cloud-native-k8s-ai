"""Phase 2 verification: strict infrastructure contracts for K8s workloads, storage, KEDA,
NetworkPolicies, Terraform bootstrap variables and settings.

Hermetic: pure in-memory validation, no files, network, subprocesses or clusters.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Iterator
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from cloud_native_k8s_ai import schemas
from cloud_native_k8s_ai.schemas import (
    DEFAULT_NAMESPACE,
    QDRANT_GRPC_PORT,
    QDRANT_REST_PORT,
    ClusterBootstrapVars,
    Container,
    ContainerPort,
    Deployment,
    DeploymentSpec,
    DeploymentStrategy,
    EmptyDirVolumeSource,
    EnvVar,
    EnvVarSource,
    FastAPIAppSpec,
    GRPCAction,
    HTTPGetAction,
    InfraModel,
    InfraSettings,
    IPBlock,
    LabelSelector,
    LabelSelectorRequirement,
    NetworkPolicy,
    NetworkPolicyEgressRule,
    NetworkPolicyIngressRule,
    NetworkPolicyPeer,
    NetworkPolicyPort,
    NetworkPolicySpec,
    NodePool,
    ObjectMeta,
    PersistentVolumeClaim,
    PersistentVolumeClaimSpec,
    PersistentVolumeClaimTemplate,
    PodSpec,
    PodTemplateSpec,
    Probe,
    QdrantSpec,
    QdrantVolume,
    RedisListTrigger,
    RedisListTriggerMetadata,
    RedisPersistence,
    RedisSpec,
    RedisStreamTrigger,
    RedisStreamTriggerMetadata,
    ResourceList,
    ResourceRequirements,
    RollingUpdate,
    ScaledObject,
    ScaledObjectSpec,
    ScaleTargetRef,
    SeccompProfile,
    SecretKeySelector,
    SecurityContext,
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
    VpcConfig,
    cpu_millicores,
    default_deny_policy,
    dns_egress_policy,
    memory_bytes,
    qdrant_ingress_policy,
)
from cloud_native_k8s_ai.schemas.storage import RdbSavePoint

NS = DEFAULT_NAMESPACE
APP_LABELS = {"app.kubernetes.io/name": "inference-api"}
QDRANT_LABELS = {"app.kubernetes.io/name": "qdrant"}
IMAGE = "ghcr.io/mikez98/inference-api:0.1.0"
QDRANT_IMAGE = "docker.io/qdrant/qdrant:v1.15.4"
REDIS_IMAGE = "docker.io/library/redis:7.4.2-alpine"
SNAKE_KEY = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)+$")


# ---------------------------------------------------------------------------
# Builders (valid baseline objects; tests derive invalid variants from them)
# ---------------------------------------------------------------------------
def resources(
    req_cpu: str = "250m", req_mem: str = "256Mi", lim_cpu: str = "1", lim_mem: str = "1Gi"
) -> ResourceRequirements:
    return ResourceRequirements(
        requests=ResourceList(cpu=req_cpu, memory=req_mem),
        limits=ResourceList(cpu=lim_cpu, memory=lim_mem),
    )


def http_probe(path: str = "/readyz", port: int | str = "http", **kw: Any) -> Probe:
    return Probe(http_get=HTTPGetAction(path=path, port=port), **kw)


def app_container(**overrides: Any) -> Container:
    fields: dict[str, Any] = {
        "name": "api",
        "image": IMAGE,
        "ports": (ContainerPort(name="http", container_port=8000),),
        "env": (
            EnvVar(name="LOG_LEVEL", value="INFO"),
            EnvVar(
                name="REDIS_PASSWORD",
                value_from=EnvVarSource(
                    secret_key_ref=SecretKeySelector(name="redis-auth", key="password")
                ),
            ),
        ),
        "resources": resources(),
        "readiness_probe": http_probe("/readyz"),
        "liveness_probe": http_probe("/healthz", period_seconds=20),
        "volume_mounts": (VolumeMount(name="tmp", mount_path="/tmp"),),  # noqa: S108
    }
    fields.update(overrides)
    return Container(**fields)


def pod_template(container: Container | None = None, **spec: Any) -> PodTemplateSpec:
    spec.setdefault("volumes", (Volume(name="tmp", empty_dir=EmptyDirVolumeSource()),))
    return PodTemplateSpec(
        metadata=ObjectMeta(name="inference-api", labels=dict(APP_LABELS)),
        spec=PodSpec(containers=(container or app_container(),), **spec),
    )


def deployment(**spec: Any) -> Deployment:
    spec.setdefault("selector", LabelSelector(match_labels=dict(APP_LABELS)))
    spec.setdefault("template", pod_template())
    return Deployment(
        metadata=ObjectMeta(name="inference-api", namespace=NS, labels=dict(APP_LABELS)),
        spec=DeploymentSpec(**spec),
    )


def service() -> Service:
    return Service(
        metadata=ObjectMeta(name="inference-api", namespace=NS),
        spec=ServiceSpec(
            selector=dict(APP_LABELS),
            ports=(ServicePort(name="http", port=80, target_port="http"),),
        ),
    )


def qdrant_container() -> Container:
    return Container(
        name="qdrant",
        image=QDRANT_IMAGE,
        ports=(
            ContainerPort(name="rest", container_port=QDRANT_REST_PORT),
            ContainerPort(name="grpc", container_port=QDRANT_GRPC_PORT),
        ),
        resources=resources("500m", "1Gi", "2", "4Gi"),
        readiness_probe=http_probe("/readyz", "rest"),
        liveness_probe=Probe(tcp_socket=TCPSocketAction(port="rest")),
        volume_mounts=(
            VolumeMount(name="storage", mount_path="/qdrant/storage"),
            VolumeMount(name="snapshots", mount_path="/qdrant/snapshots"),
        ),
    )


def claim(name: str, size: str = "20Gi", storage_class: str | None = "gp3") -> Any:
    return PersistentVolumeClaimTemplate(
        metadata=ObjectMeta(name=name),
        spec=PersistentVolumeClaimSpec(
            storage_class_name=storage_class,
            resources=VolumeResourceRequirements(requests=StorageRequest(storage=size)),
        ),
    )


def statefulset(**spec: Any) -> StatefulSet:
    spec.setdefault("service_name", "qdrant-headless")
    spec.setdefault("selector", LabelSelector(match_labels=dict(QDRANT_LABELS)))
    spec.setdefault(
        "template",
        PodTemplateSpec(
            metadata=ObjectMeta(name="qdrant", labels=dict(QDRANT_LABELS)),
            spec=PodSpec(containers=(qdrant_container(),)),
        ),
    )
    spec.setdefault("volume_claim_templates", (claim("storage"), claim("snapshots", "10Gi")))
    return StatefulSet(
        metadata=ObjectMeta(name="qdrant", namespace=NS), spec=StatefulSetSpec(**spec)
    )


def redis_trigger(**metadata: Any) -> RedisListTrigger:
    fields: dict[str, Any] = {
        "address": "redis.ai-system.svc.cluster.local:6379",
        "list_name": "inference-jobs",
    }
    fields.update(metadata)
    return RedisListTrigger(metadata=RedisListTriggerMetadata(**fields))


def scaled_object(**spec: Any) -> ScaledObject:
    spec.setdefault("scale_target_ref", ScaleTargetRef(name="inference-api"))
    spec.setdefault("triggers", (redis_trigger(),))
    return ScaledObject(
        metadata=ObjectMeta(name="inference-api", namespace=NS), spec=ScaledObjectSpec(**spec)
    )


def node_pool(**overrides: Any) -> NodePool:
    fields: dict[str, Any] = {
        "name": "general",
        "machine_type": "m6i.xlarge",
        "min_size": 1,
        "max_size": 5,
        "desired_size": 2,
    }
    fields.update(overrides)
    return NodePool(**fields)


def eks_vars(**overrides: Any) -> ClusterBootstrapVars:
    fields: dict[str, Any] = {
        "provider": "eks",
        "region": "eu-central-1",
        "cluster_name": "ai-cluster",
        "kubernetes_version": "1.33",
        "vpc": VpcConfig(
            cidr="10.0.0.0/16",
            private_subnets=("10.0.0.0/19", "10.0.32.0/19"),
            public_subnets=("10.0.128.0/24", "10.0.129.0/24"),
        ),
        "node_pools": (
            node_pool(),
            node_pool(
                name="gpu",
                machine_type="g5.2xlarge",
                min_size=0,
                max_size=4,
                desired_size=0,
                capacity_type="spot",
                accelerator_type="nvidia-a10g",
                accelerator_count=1,
                taints=({"key": "nvidia.com/gpu", "value": "true", "effect": "NoSchedule"},),
            ),
        ),
        "tags": {"project": "cloud-native-k8s-ai", "env": "prod"},
    }
    fields.update(overrides)
    return ClusterBootstrapVars(**fields)


def gke_vars(**overrides: Any) -> ClusterBootstrapVars:
    fields: dict[str, Any] = {
        "provider": "gke",
        "region": "europe-west4",
        "cluster_name": "ai-cluster",
        "kubernetes_version": "1.34",
        "vpc": VpcConfig(
            cidr="10.10.0.0/20",
            private_subnets=("10.10.0.0/22",),
            pods_cidr="10.64.0.0/14",
            services_cidr="10.68.0.0/20",
        ),
        "node_pools": (node_pool(machine_type="e2-standard-4"),),
        "endpoint_public_access": True,
        "authorized_cidrs": ("203.0.113.0/24",),
    }
    fields.update(overrides)
    return ClusterBootstrapVars(**fields)


def walk(node: Any, path: str = "$") -> Iterator[tuple[str, Any, Any]]:
    """Yield ``(path, key, value)`` for every mapping entry in a JSON-like tree."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield path, key, value
            yield from walk(value, f"{path}.{key}")
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from walk(item, f"{path}[{i}]")


K8S_BUILDERS: dict[str, Callable[[], InfraModel]] = {
    "deployment": deployment,
    "service": service,
    "statefulset": statefulset,
    "pvc": lambda: PersistentVolumeClaim(
        metadata=ObjectMeta(name="redis-data", namespace=NS), spec=claim("data").spec
    ),
    "scaledobject": scaled_object,
    "default-deny": lambda: default_deny_policy(NS),
    "dns-egress": lambda: dns_egress_policy(NS),
    "qdrant-ingress": lambda: qdrant_ingress_policy(
        NS, qdrant_labels=QDRANT_LABELS, app_labels=APP_LABELS
    ),
}
ALL_BUILDERS: dict[str, Callable[[], InfraModel]] = {
    **K8S_BUILDERS,
    "fastapi-app": lambda: FastAPIAppSpec(image=IMAGE, resources=resources()),
    "qdrant-spec": lambda: QdrantSpec(image=QDRANT_IMAGE, resources=resources()),
    "redis-spec": lambda: RedisSpec(image=REDIS_IMAGE, resources=resources(), maxmemory="512Mi"),
    "stream-trigger": lambda: scaled_object(
        triggers=(
            RedisStreamTrigger(
                name="jobs",
                metadata=RedisStreamTriggerMetadata(
                    address="redis:6379", stream="jobs", consumer_group="workers", enable_tls=True
                ),
            ),
        )
    ),
    "eks-vars": eks_vars,
    "gke-vars": gke_vars,
}


# ---------------------------------------------------------------------------
# Quantities
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("quantity", "millicores"),
    [("500m", 500), ("1", 1000), ("2", 2000), ("0.5", 500), ("1.25", 1250), ("1500m", 1500)],
)
def test_cpu_quantity_parsing(quantity: str, millicores: int) -> None:
    assert cpu_millicores(quantity) == millicores
    assert ResourceList(cpu=quantity, memory="1Gi").cpu == quantity


@pytest.mark.parametrize(
    "quantity", ["500M", "500mi", "0", "0m", "-1", "1.2345", "abc", "", "1 m", "2Gi", " 1"]
)
def test_invalid_cpu_quantity_rejected(quantity: str) -> None:
    with pytest.raises(ValidationError, match="CPU quantity"):
        ResourceList(cpu=quantity, memory="1Gi")


@pytest.mark.parametrize(
    ("quantity", "size"),
    [
        ("512Mi", 512 * 2**20),
        ("2Gi", 2 * 2**30),
        ("1.5Gi", 3 * 2**29),
        ("1G", 10**9),
        ("128974848", 128_974_848),
        ("64Ki", 65_536),
    ],
)
def test_memory_quantity_parsing(quantity: str, size: int) -> None:
    assert memory_bytes(quantity) == size
    assert ResourceList(cpu="1", memory=quantity).memory == quantity


@pytest.mark.parametrize(
    ("quantity", "reason"),
    [
        ("2GB", "invalid byte quantity"),
        ("2gi", "invalid byte quantity"),
        ("512m", "invalid byte quantity"),  # millibytes: the classic typo for 512Mi
        ("Gi", "invalid byte quantity"),
        ("-1Gi", "invalid byte quantity"),
        ("0Gi", "greater than zero"),
        ("1.5", "whole number of bytes"),
    ],
)
def test_invalid_memory_quantity_rejected(quantity: str, reason: str) -> None:
    with pytest.raises(ValidationError, match=reason):
        ResourceList(cpu="1", memory=quantity)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"req_cpu": "2", "lim_cpu": "1500m"}, "cpu request 2 exceeds limit 1500m"),
        ({"req_mem": "2Gi", "lim_mem": "1Gi"}, "memory request 2Gi exceeds limit 1Gi"),
    ],
)
def test_requests_must_fit_limits(kwargs: dict[str, str], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        resources(**kwargs)


def test_resources_require_cpu_and_memory() -> None:
    with pytest.raises(ValidationError, match="memory"):
        ResourceList.from_wire({"cpu": "1"})


# ---------------------------------------------------------------------------
# Ports, replicas and strictness
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("port", [1, 8000, 65535])
def test_valid_ports(port: int) -> None:
    assert ContainerPort(name="http", container_port=port).container_port == port
    assert ServicePort(name="http", port=port, target_port=port).port == port


@pytest.mark.parametrize("port", [0, -1, 65536, 100_000])
def test_invalid_port_range_rejected(port: int) -> None:
    with pytest.raises(ValidationError):
        ContainerPort(name="http", container_port=port)
    with pytest.raises(ValidationError):
        ServicePort(name="http", port=port, target_port="http")
    with pytest.raises(ValidationError):
        QdrantSpec(image=QDRANT_IMAGE, resources=resources(), rest_port=port)


@pytest.mark.parametrize("name", ["HTTP", "-http", "http-", "1234", "a" * 16, "web_port"])
def test_invalid_port_names_rejected(name: str) -> None:
    with pytest.raises(ValidationError):
        ContainerPort(name=name, container_port=8000)


@pytest.mark.parametrize(
    "build",
    [
        lambda: deployment(replicas=-1),
        lambda: statefulset(replicas=-1),
        lambda: FastAPIAppSpec(image=IMAGE, resources=resources(), replicas=-3),
        lambda: QdrantSpec(image=QDRANT_IMAGE, resources=resources(), replicas=0),
        lambda: scaled_object(min_replica_count=-1),
    ],
)
def test_negative_replicas_rejected(build: Callable[[], object]) -> None:
    with pytest.raises(ValidationError):
        build()


def test_strict_mode_rejects_coercion() -> None:
    with pytest.raises(ValidationError, match="int"):
        ContainerPort(name="http", container_port="8000")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        ContainerPort(name="http", container_port=True)
    with pytest.raises(ValidationError):
        ContainerPort.from_wire({"name": "http", "containerPort": "8000"})
    with pytest.raises(ValidationError):
        ContainerPort.from_wire({"name": "http", "containerPort": 8000.5})


def test_unknown_fields_rejected() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        DeploymentSpec.from_wire({**deployment().spec.to_k8s(), "replica": 3})


# ---------------------------------------------------------------------------
# Serialization fidelity
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", list(ALL_BUILDERS))
def test_wire_roundtrip_is_exact(name: str) -> None:
    model = ALL_BUILDERS[name]()
    wire = model.to_wire()
    assert type(model).from_wire(wire) == model
    assert type(model).model_validate_json(model.model_dump_json()) == model
    assert json.loads(json.dumps(wire)) == wire


@pytest.mark.parametrize("name", list(ALL_BUILDERS))
def test_yaml_roundtrip_is_exact(name: str) -> None:
    model = ALL_BUILDERS[name]()
    document = yaml.safe_dump(model.to_wire(), sort_keys=False)
    assert type(model).from_wire(yaml.safe_load(document)) == model


@pytest.mark.parametrize("name", list(K8S_BUILDERS))
def test_manifests_are_kubernetes_shaped(name: str) -> None:
    manifest = K8S_BUILDERS[name]().to_wire()
    assert set(manifest) == {"apiVersion", "kind", "metadata", "spec"}
    for path, key, value in walk(manifest):
        assert value is not None, f"{path}.{key} is null"
        if not path.endswith(("labels", "matchLabels", "selector", "annotations")):
            assert not SNAKE_KEY.match(key), f"snake_case key {path}.{key}"


def test_deployment_manifest_matches_kubernetes_schema() -> None:
    manifest = deployment().to_wire()
    assert manifest["apiVersion"] == "apps/v1"
    assert manifest["kind"] == "Deployment"
    spec = manifest["spec"]
    assert spec["replicas"] == 2
    assert spec["selector"] == {"matchLabels": APP_LABELS}
    assert spec["strategy"] == {
        "type": "RollingUpdate",
        "rollingUpdate": {"maxSurge": "25%", "maxUnavailable": 0},
    }
    pod = spec["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert pod["securityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}
    assert pod["volumes"] == [{"name": "tmp", "emptyDir": {"medium": ""}}]
    container = pod["containers"][0]
    assert container["ports"] == [{"name": "http", "containerPort": 8000, "protocol": "TCP"}]
    assert container["resources"] == {
        "requests": {"cpu": "250m", "memory": "256Mi"},
        "limits": {"cpu": "1", "memory": "1Gi"},
    }
    assert container["readinessProbe"] == {
        "httpGet": {"path": "/readyz", "port": "http", "scheme": "HTTP"},
        "initialDelaySeconds": 0,
        "periodSeconds": 10,
        "timeoutSeconds": 1,
        "successThreshold": 1,
        "failureThreshold": 3,
    }
    assert container["env"] == [
        {"name": "LOG_LEVEL", "value": "INFO"},
        {
            "name": "REDIS_PASSWORD",
            "valueFrom": {"secretKeyRef": {"name": "redis-auth", "key": "password"}},
        },
    ]
    assert container["securityContext"] == {
        "runAsNonRoot": True,
        "runAsUser": 10001,
        "runAsGroup": 10001,
        "readOnlyRootFilesystem": True,
        "allowPrivilegeEscalation": False,
        "privileged": False,
        "capabilities": {"drop": ["ALL"], "add": []},
        "seccompProfile": {"type": "RuntimeDefault"},
    }


def test_service_manifest() -> None:
    assert service().to_k8s()["spec"] == {
        "type": "ClusterIP",
        "selector": APP_LABELS,
        "ports": [{"name": "http", "port": 80, "targetPort": "http", "protocol": "TCP"}],
    }
    headless = ServiceSpec(
        cluster_ip="None",
        selector=QDRANT_LABELS,
        ports=(ServicePort(name="rest", port=6333, target_port=6333),),
    )
    assert headless.to_k8s()["clusterIP"] == "None"
    assert ServiceSpec.from_wire(headless.to_k8s()) == headless


def test_statefulset_manifest() -> None:
    spec = statefulset().to_k8s()["spec"]
    assert spec["serviceName"] == "qdrant-headless"
    assert spec["podManagementPolicy"] == "OrderedReady"
    assert spec["persistentVolumeClaimRetentionPolicy"] == {
        "whenDeleted": "Retain",
        "whenScaled": "Retain",
    }
    assert spec["volumeClaimTemplates"][0] == {
        "metadata": {"name": "storage"},
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "storageClassName": "gp3",
            "resources": {"requests": {"storage": "20Gi"}},
        },
    }
    ports = spec["template"]["spec"]["containers"][0]["ports"]
    assert [p["containerPort"] for p in ports] == [6333, 6334]


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("build", "field", "value"),
    [
        (deployment, "kind", "StatefulSet"),
        (lambda: deployment().spec, "replicas", 10),
        (lambda: resources().limits, "cpu", "8"),
        (statefulset, "metadata", ObjectMeta(name="other")),
        (scaled_object, "spec", None),
        (lambda: default_deny_policy(NS).spec, "policy_types", ("Ingress",)),
        (eks_vars, "kubernetes_version", "1.35"),
        (InfraSettings, "namespace", "default"),
    ],
)
def test_models_are_frozen(build: Callable[[], Any], field: str, value: object) -> None:
    model = build()
    with pytest.raises(ValidationError, match="frozen"):
        setattr(model, field, value)


def test_sequences_are_immutable_tuples() -> None:
    spec = deployment().spec.template.spec
    assert isinstance(spec.containers, tuple)
    assert isinstance(spec.containers[0].ports, tuple)
    assert isinstance(default_deny_policy(NS).spec.policy_types, tuple)


def test_frozen_models_hash_and_compare_by_value() -> None:
    assert resources().limits == resources().limits
    assert hash(resources().limits) == hash(resources().limits)
    assert ContainerPort(name="http", container_port=8000) != ContainerPort(
        name="http", container_port=8001
    )


# ---------------------------------------------------------------------------
# Workload invariants
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("image", "ok"),
    [
        (IMAGE, True),
        ("redis:7.4", True),
        ("registry.local:5000/team/app:1.2.3", True),
        ("ghcr.io/mikez98/api@sha256:" + "a" * 64, True),
        ("ghcr.io/mikez98/api:1.0@sha256:" + "b" * 64, True),
        ("ghcr.io/mikez98/api:latest", False),
        ("ghcr.io/mikez98/api", False),
        ("Ghcr.io/Mikez98/API:1.0", False),
        ("api:", False),
        ("api@sha256:short", False),
    ],
)
def test_image_must_be_pinned(image: str, ok: bool) -> None:
    if ok:
        assert app_container(image=image).image == image
    else:
        with pytest.raises(ValidationError, match="image"):
            app_container(image=image)


@pytest.mark.parametrize(
    "context",
    [
        {"runAsNonRoot": False},
        {"readOnlyRootFilesystem": False},
        {"allowPrivilegeEscalation": True},
        {"privileged": True},
        {"runAsUser": 0},
        {"capabilities": {"drop": []}},
        {"capabilities": {"drop": ["ALL"], "add": ["SYS_ADMIN"]}},
    ],
)
def test_security_context_cannot_be_weakened(context: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SecurityContext.from_wire(context)


def test_seccomp_localhost_requires_profile() -> None:
    profile = SeccompProfile(type="Localhost", localhost_profile="profiles/api.json")
    assert profile.to_k8s() == {"type": "Localhost", "localhostProfile": "profiles/api.json"}
    with pytest.raises(ValidationError, match="localhostProfile"):
        SeccompProfile(type="Localhost")
    with pytest.raises(ValidationError, match="localhostProfile"):
        SeccompProfile(localhost_profile="profiles/api.json")


@pytest.mark.parametrize(
    ("handlers", "ok"),
    [
        ({"http_get": HTTPGetAction(path="/healthz", port=8000)}, True),
        ({"tcp_socket": TCPSocketAction(port=8000)}, True),
        ({"grpc": GRPCAction(port=9000)}, True),
        ({}, False),
        ({"http_get": HTTPGetAction(path="/h", port=1), "grpc": GRPCAction(port=2)}, False),
    ],
)
def test_probe_needs_exactly_one_handler(handlers: dict[str, Any], ok: bool) -> None:
    if ok:
        assert Probe(**handlers).port in (8000, 9000)
    else:
        with pytest.raises(ValidationError, match="exactly one"):
            Probe(**handlers)


def test_probe_path_must_be_absolute() -> None:
    with pytest.raises(ValidationError):
        HTTPGetAction(path="healthz", port=8000)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"liveness_probe": http_probe("/healthz", success_threshold=2)}, "successThreshold"),
        ({"readiness_probe": http_probe(port="metrics")}, "unknown port name 'metrics'"),
        (
            {
                "ports": (
                    ContainerPort(name="http", container_port=8000),
                    ContainerPort(name="http", container_port=8001),
                )
            },
            "duplicate ports",
        ),
        (
            {
                "ports": (
                    ContainerPort(name="http", container_port=8000),
                    ContainerPort(name="alt", container_port=8000),
                )
            },
            "duplicate ports",
        ),
        (
            {"env": (EnvVar(name="A", value="1"), EnvVar(name="A", value="2"))},
            "duplicate env vars",
        ),
        (
            {
                "volume_mounts": (
                    VolumeMount(name="a", mount_path="/data"),
                    VolumeMount(name="b", mount_path="/data"),
                )
            },
            "same path",
        ),
    ],
)
def test_container_invariants(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        app_container(**overrides)


def test_container_requires_resources_and_probes() -> None:
    wire = app_container().to_k8s()
    for field in ("resources", "readinessProbe", "livenessProbe"):
        with pytest.raises(ValidationError, match=field):
            Container.from_wire({k: v for k, v in wire.items() if k != field})


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"name": "LOG_LEVEL"}, "exactly one of value or valueFrom"),
        (
            {
                "name": "LOG_LEVEL",
                "value": "x",
                "value_from": EnvVarSource(secret_key_ref=SecretKeySelector(name="s", key="k")),
            },
            "exactly one of value or valueFrom",
        ),
        ({"name": "1BAD", "value": "x"}, "pattern"),
    ],
)
def test_env_var_needs_exactly_one_source(kwargs: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        EnvVar(**kwargs)


@pytest.mark.parametrize(
    "volume",
    [{"name": "v"}, {"name": "v", "emptyDir": {}, "configMap": {"name": "cfg"}}],
)
def test_volume_needs_exactly_one_source(volume: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="exactly one source"):
        Volume.from_wire(volume)


def test_pod_spec_rejects_duplicate_names() -> None:
    with pytest.raises(ValidationError, match="duplicate container"):
        PodSpec(containers=(app_container(), app_container()))
    tmp = Volume(name="tmp", empty_dir=EmptyDirVolumeSource())
    with pytest.raises(ValidationError, match="duplicate volume"):
        PodSpec(containers=(app_container(),), volumes=(tmp, tmp))


def test_deployment_selector_must_match_template() -> None:
    with pytest.raises(ValidationError, match="selector does not match"):
        deployment(selector=LabelSelector(match_labels={"app.kubernetes.io/name": "other"}))


def test_deployment_mounts_need_declared_volumes() -> None:
    with pytest.raises(ValidationError, match=r"undeclared volumes: \['tmp'\]"):
        deployment(template=pod_template(volumes=()))


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"max_surge": 0, "max_unavailable": "0%"}, "both be zero"),
        ({"max_surge": -1}, "non-negative"),
        ({"max_surge": "150%"}, "pattern"),
    ],
)
def test_rolling_update_bounds(kwargs: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        RollingUpdate(**kwargs)


def test_recreate_strategy_forbids_rolling_update() -> None:
    recreate = DeploymentStrategy(type="Recreate")
    assert recreate.to_k8s() == {"type": "Recreate"}
    with pytest.raises(ValidationError, match="Recreate"):
        DeploymentStrategy(type="Recreate", rolling_update=RollingUpdate())


@pytest.mark.parametrize(
    "strategy",
    [
        DeploymentStrategy(type="Recreate"),
        DeploymentStrategy(),
        DeploymentStrategy(rolling_update=RollingUpdate(max_surge=1, max_unavailable="10%")),
    ],
)
def test_strategy_roundtrip(strategy: DeploymentStrategy) -> None:
    assert DeploymentStrategy.from_wire(strategy.to_k8s()) == strategy
    spec = deployment(strategy=strategy).spec
    assert DeploymentSpec.from_wire(spec.to_k8s()) == spec


def test_ip_network_helper_is_exported_not_shadowed() -> None:
    # ``schemas.network`` is a submodule; the helper must not share its name.
    assert callable(schemas.ip_network)
    assert schemas.ip_network("10.0.0.0/8").prefixlen == 8


def test_service_invariants() -> None:
    port = ServicePort(name="http", port=80, target_port=8000)
    with pytest.raises(ValidationError, match="duplicate ports"):
        ServiceSpec(selector=APP_LABELS, ports=(port, port))
    with pytest.raises(ValidationError, match="headless"):
        ServiceSpec(type="NodePort", cluster_ip="None", selector=APP_LABELS, ports=(port,))
    with pytest.raises(ValidationError):
        ServiceSpec(selector={}, ports=(port,))
    with pytest.raises(ValidationError):
        ServiceSpec(selector=APP_LABELS, ports=())


@pytest.mark.parametrize(
    "meta",
    [
        {"name": "Inference_API"},
        {"name": "a" * 64},
        {"name": "api", "namespace": "AI-System"},
        {"name": "api", "labels": {"app": "-bad"}},
        {"name": "api", "labels": {"bad key": "v"}},
        {"name": "api", "labels": {"app": "x" * 64}},
    ],
)
def test_invalid_object_metadata_rejected(meta: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ObjectMeta.from_wire(meta)


def test_fastapi_app_defaults() -> None:
    app = FastAPIAppSpec(image=IMAGE, resources=resources())
    assert (app.name, app.container_port, app.replicas) == ("inference-api", 8000, 2)
    assert (app.liveness_path, app.readiness_path) == ("/healthz", "/readyz")
    assert app.to_wire()["containerPort"] == 8000


# ---------------------------------------------------------------------------
# Label selectors
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("operator", "values", "labels", "matches"),
    [
        ("In", ("a", "b"), {"tier": "a"}, True),
        ("In", ("a",), {"tier": "c"}, False),
        ("In", ("a",), {}, False),
        ("NotIn", ("a",), {"tier": "b"}, True),
        ("NotIn", ("a",), {}, True),
        ("NotIn", ("a",), {"tier": "a"}, False),
        ("Exists", (), {"tier": "x"}, True),
        ("Exists", (), {}, False),
        ("DoesNotExist", (), {}, True),
        ("DoesNotExist", (), {"tier": "x"}, False),
    ],
)
def test_label_selector_expressions(
    operator: Any, values: tuple[str, ...], labels: dict[str, str], matches: bool
) -> None:
    selector = LabelSelector(
        match_expressions=(LabelSelectorRequirement(key="tier", operator=operator, values=values),)
    )
    assert selector.matches(labels) is matches


def test_label_selector_match_labels_and_empty() -> None:
    assert LabelSelector().matches({"anything": "goes"})
    assert LabelSelector().to_k8s() == {}
    assert not LabelSelector(match_labels=APP_LABELS).matches(QDRANT_LABELS)


@pytest.mark.parametrize(
    ("operator", "values"), [("In", ()), ("NotIn", ()), ("Exists", ("x",)), ("Bogus", ())]
)
def test_label_selector_requirement_validation(operator: Any, values: tuple[str, ...]) -> None:
    with pytest.raises(ValidationError):
        LabelSelectorRequirement(key="tier", operator=operator, values=values)


# ---------------------------------------------------------------------------
# Storage: StatefulSet, Qdrant, Redis
# ---------------------------------------------------------------------------
def test_statefulset_mounts_need_claims_or_volumes() -> None:
    with pytest.raises(ValidationError, match=r"undeclared volumes: \['snapshots'\]"):
        statefulset(volume_claim_templates=(claim("storage"),))


def test_statefulset_claim_names_unique_and_not_shadowing() -> None:
    with pytest.raises(ValidationError, match="duplicate volumeClaimTemplate"):
        statefulset(volume_claim_templates=(claim("storage"), claim("storage"), claim("snapshots")))
    template = PodTemplateSpec(
        metadata=ObjectMeta(name="qdrant", labels=dict(QDRANT_LABELS)),
        spec=PodSpec(
            containers=(qdrant_container(),),
            volumes=(Volume(name="storage", empty_dir=EmptyDirVolumeSource()),),
        ),
    )
    with pytest.raises(ValidationError, match="shadow pod volumes"):
        statefulset(template=template)


def test_statefulset_selector_must_match_template() -> None:
    with pytest.raises(ValidationError, match="selector does not match"):
        statefulset(selector=LabelSelector(match_labels=APP_LABELS))


@pytest.mark.parametrize(
    "overrides",
    [
        {"size": "20GB"},
        {"size": "0Gi"},
        {"storage_class": "Fast_SSD"},
    ],
)
def test_invalid_pvc_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        claim("storage", **overrides)


def test_standalone_pvc_manifest() -> None:
    pvc = PersistentVolumeClaim(
        metadata=ObjectMeta(name="redis-data", namespace=NS), spec=claim("data", "8Gi").spec
    )
    assert pvc.to_k8s() == {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {"name": "redis-data", "namespace": NS},
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "storageClassName": "gp3",
            "resources": {"requests": {"storage": "8Gi"}},
        },
    }


def test_pvc_access_modes_validated() -> None:
    with pytest.raises(ValidationError):
        PersistentVolumeClaimSpec.from_wire(
            {"accessModes": [], "resources": {"requests": {"storage": "1Gi"}}}
        )
    with pytest.raises(ValidationError):
        PersistentVolumeClaimSpec.from_wire(
            {"accessModes": ["ReadWriteSometimes"], "resources": {"requests": {"storage": "1Gi"}}}
        )


def test_qdrant_defaults() -> None:
    qdrant = QdrantSpec(image=QDRANT_IMAGE, resources=resources())
    assert (qdrant.rest_port, qdrant.grpc_port) == (6333, 6334)
    assert qdrant.storage.mount_path == "/qdrant/storage"
    assert qdrant.snapshots.mount_path == "/qdrant/snapshots"
    assert memory_bytes(qdrant.storage.size) == 20 * 2**30


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"rest_port": 6334}, "ports must differ"),
        (
            {"snapshots": QdrantVolume(size="1Gi", mount_path="/qdrant/storage/snapshots")},
            "overlaps",
        ),
        ({"snapshots": QdrantVolume(size="1Gi", mount_path="/qdrant/storage/")}, "overlaps"),
        ({"image": "qdrant/qdrant:latest"}, "latest"),
    ],
)
def test_qdrant_invariants(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        QdrantSpec(**{"image": QDRANT_IMAGE, "resources": resources(), **overrides})


def test_qdrant_sibling_paths_with_common_prefix_allowed() -> None:
    qdrant = QdrantSpec(
        image=QDRANT_IMAGE,
        resources=resources(),
        storage=QdrantVolume(size="1Gi", mount_path="/data"),
        snapshots=QdrantVolume(size="1Gi", mount_path="/data-snapshots"),
    )
    assert qdrant.snapshots.mount_path == "/data-snapshots"


def redis(**overrides: Any) -> RedisSpec:
    fields: dict[str, Any] = {"image": REDIS_IMAGE, "resources": resources(), "maxmemory": "768Mi"}
    fields.update(overrides)
    return RedisSpec(**fields)


@pytest.mark.parametrize(
    ("persistence", "expected"),
    [
        (
            RedisPersistence(),
            ["--appendonly", "yes", "--appendfsync", "everysec", "--save", ""],
        ),
        (
            RedisPersistence(mode="rdb"),
            ["--appendonly", "no", "--save", "3600 1 300 100"],
        ),
        (
            RedisPersistence(mode="rdb+aof", appendfsync="always"),
            ["--appendonly", "yes", "--appendfsync", "always", "--save", "3600 1 300 100"],
        ),
        (
            RedisPersistence(mode="none", volume_size=None),
            ["--appendonly", "no", "--save", ""],
        ),
    ],
)
def test_redis_server_args(persistence: RedisPersistence, expected: list[str]) -> None:
    args = redis(persistence=persistence).server_args()
    assert args[:6] == (
        "--port",
        "6379",
        "--maxmemory",
        str(768 * 2**20),
        "--maxmemory-policy",
        "noeviction",
    )
    assert list(args[6:8]) == expected[:2]
    assert list(args[10:]) == expected[2:]
    assert args[8:10] == ("--dir", "/data")


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"maxmemory": "1Gi"}, "must stay below the memory limit"),
        ({"maxmemory": "2Gi"}, "must stay below the memory limit"),
        ({"maxmemory": "512m"}, "invalid byte quantity"),
        ({"maxmemory_policy": "lru"}, "maxmemory_policy"),
    ],
)
def test_redis_memory_contract(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        redis(**overrides)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"mode": "none"}, "must not request a volume"),
        ({"mode": "aof", "volume_size": None}, "requires volumeSize"),
        ({"mode": "rdb", "save_points": ()}, "at least one save point"),
        ({"mode": "snapshot"}, "mode"),
    ],
)
def test_redis_persistence_contract(kwargs: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        RedisPersistence(**kwargs)


def test_rdb_save_point_bounds() -> None:
    with pytest.raises(ValidationError):
        RdbSavePoint(seconds=0, changes=1)
    with pytest.raises(ValidationError):
        RdbSavePoint(seconds=60, changes=0)


# ---------------------------------------------------------------------------
# KEDA
# ---------------------------------------------------------------------------
def test_scaled_object_manifest() -> None:
    manifest = scaled_object(
        min_replica_count=1, max_replica_count=20, cooldown_period=120
    ).to_k8s()
    assert manifest["apiVersion"] == "keda.sh/v1alpha1"
    assert manifest["kind"] == "ScaledObject"
    assert manifest["spec"] == {
        "scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment", "name": "inference-api"},
        "pollingInterval": 30,
        "cooldownPeriod": 120,
        "minReplicaCount": 1,
        "maxReplicaCount": 20,
        "triggers": [
            {
                "type": "redis",
                "metadata": {
                    "address": "redis.ai-system.svc.cluster.local:6379",
                    "databaseIndex": "0",
                    "enableTLS": "false",
                    "listName": "inference-jobs",
                    "listLength": "5",
                    "activationListLength": "0",
                },
            }
        ],
    }


def test_keda_metadata_values_are_strings_on_the_wire() -> None:
    trigger = scaled_object().to_k8s()["spec"]["triggers"][0]
    assert all(isinstance(v, str) for v in trigger["metadata"].values())


def test_keda_metadata_accepts_string_and_typed_input() -> None:
    from_strings = RedisListTriggerMetadata.from_wire(
        {"address": "redis:6379", "listName": "q", "listLength": "10", "enableTLS": "true"}
    )
    typed = RedisListTriggerMetadata(
        address="redis:6379", list_name="q", list_length=10, enable_tls=True
    )
    assert from_strings == typed
    assert (typed.list_length, typed.enable_tls) == (10, True)


def test_stream_trigger_manifest() -> None:
    trigger = ALL_BUILDERS["stream-trigger"]().to_wire()["spec"]["triggers"][0]
    assert trigger == {
        "type": "redis-streams",
        "name": "jobs",
        "metadata": {
            "address": "redis:6379",
            "databaseIndex": "0",
            "enableTLS": "true",
            "stream": "jobs",
            "consumerGroup": "workers",
            "pendingEntriesCount": "5",
            "activationLagCount": "0",
        },
    }


@pytest.mark.parametrize(
    "metadata",
    [
        {"list_length": 0},
        {"list_length": "0"},
        {"list_length": "five"},
        {"list_length": "5.0"},
        {"list_length": True},
        {"list_length": -5},
        {"activation_list_length": -1},
        {"database_index": 16},
        {"enable_tls": "yes"},
        {"address": "redis"},
        {"address": "redis:0"},
        {"address": "redis:70000"},
        {"address": "Redis_Host:6379"},
        {"list_name": ""},
        {"list_name": "has space"},
    ],
)
def test_invalid_redis_trigger_metadata_rejected(metadata: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        redis_trigger(**metadata)


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ({"min_replica_count": 5, "max_replica_count": 2}, "exceeds maxReplicaCount"),
        ({"idle_replica_count": 1, "min_replica_count": 1}, "idleReplicaCount"),
        ({"cooldown_period": -1}, "cooldown_period"),
        ({"polling_interval": 0}, "polling_interval"),
        ({"max_replica_count": 0}, "max_replica_count"),
        ({"triggers": ()}, "triggers"),
        (
            {
                "triggers": (
                    RedisListTrigger(name="q", metadata=redis_trigger().metadata),
                    RedisListTrigger(name="q", metadata=redis_trigger().metadata),
                )
            },
            "unique",
        ),
    ],
)
def test_scaled_object_invariants(spec: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        scaled_object(**spec)


def test_scale_to_zero_with_idle_replicas() -> None:
    spec = scaled_object(idle_replica_count=0, min_replica_count=1).spec
    assert (spec.idle_replica_count, spec.min_replica_count) == (0, 1)


def test_unknown_trigger_type_rejected() -> None:
    wire = scaled_object().to_k8s()
    wire["spec"]["triggers"][0]["type"] = "kafka"
    with pytest.raises(ValidationError, match=r"discriminator|tag"):
        ScaledObject.from_wire(wire)


def test_scale_target_kind_restricted() -> None:
    with pytest.raises(ValidationError):
        ScaleTargetRef.from_wire({"kind": "DaemonSet", "name": "x"})


# ---------------------------------------------------------------------------
# NetworkPolicies
# ---------------------------------------------------------------------------
def test_default_deny_policy() -> None:
    policy = default_deny_policy(NS)
    assert policy.spec.denies_all
    assert policy.to_k8s() == {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "default-deny-all", "namespace": NS},
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [],
            "egress": [],
        },
    }


def test_dns_egress_policy() -> None:
    policy = dns_egress_policy(NS)
    assert not policy.spec.denies_all
    assert policy.to_k8s()["spec"]["egress"] == [
        {
            "to": [
                {
                    "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                    "namespaceSelector": {
                        "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
                    },
                }
            ],
            "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}],
        }
    ]


def test_qdrant_isolated_to_app_pods() -> None:
    policy = qdrant_ingress_policy(NS, qdrant_labels=QDRANT_LABELS, app_labels=APP_LABELS)
    spec = policy.spec
    assert spec.policy_types == ("Ingress",)
    assert spec.pod_selector.matches(QDRANT_LABELS)
    assert not spec.pod_selector.matches(APP_LABELS)
    (rule,) = spec.ingress
    (peer,) = rule.from_
    assert peer.namespace_selector is None, "must stay namespace-local"
    assert peer.ip_block is None
    assert peer.pod_selector is not None
    assert peer.pod_selector.matches(APP_LABELS)
    assert not peer.pod_selector.matches({"app.kubernetes.io/name": "redis"})
    assert not peer.pod_selector.matches({})
    assert [(p.protocol, p.port) for p in rule.ports] == [("TCP", 6333), ("TCP", 6334)]
    assert policy.to_k8s()["spec"]["ingress"][0]["from"] == [
        {"podSelector": {"matchLabels": APP_LABELS}}
    ]


@pytest.mark.parametrize(("qdrant_labels", "app_labels"), [({}, APP_LABELS), (QDRANT_LABELS, {})])
def test_qdrant_policy_refuses_empty_selectors(
    qdrant_labels: dict[str, str], app_labels: dict[str, str]
) -> None:
    with pytest.raises(ValueError, match="non-empty"):
        qdrant_ingress_policy(NS, qdrant_labels=qdrant_labels, app_labels=app_labels)


def test_rules_must_name_peers() -> None:
    with pytest.raises(ValidationError, match="from"):
        NetworkPolicyIngressRule.from_wire({"from": [], "ports": [{"port": 6333}]})
    with pytest.raises(ValidationError, match="to"):
        NetworkPolicyEgressRule.from_wire({"ports": [{"port": 443}]})


@pytest.mark.parametrize(
    "peer",
    [
        {},
        {"podSelector": {}, "ipBlock": {"cidr": "10.0.0.0/8"}},
        {"namespaceSelector": {}, "ipBlock": {"cidr": "10.0.0.0/8"}},
    ],
)
def test_peer_kind_exclusive(peer: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="exclusive"):
        NetworkPolicyPeer.from_wire(peer)


@pytest.mark.parametrize(
    ("block", "ok"),
    [
        ({"cidr": "10.0.0.0/8", "except": ["10.1.0.0/16"]}, True),
        ({"cidr": "2001:db8::/32", "except": ["2001:db8:1::/48"]}, True),
        ({"cidr": "10.0.0.0/8", "except": ["192.168.0.0/16"]}, False),
        ({"cidr": "10.0.0.0/8", "except": ["10.0.0.0/8"]}, False),
        ({"cidr": "10.0.0.0/8", "except": ["2001:db8::/32"]}, False),
        ({"cidr": "10.0.0.1/8"}, False),
        ({"cidr": "10.0.0.0/33"}, False),
        ({"cidr": "300.0.0.0/8"}, False),
        ({"cidr": "not-a-cidr"}, False),
    ],
)
def test_ip_block_validation(block: dict[str, Any], ok: bool) -> None:
    if ok:
        parsed = IPBlock.from_wire(block)
        assert parsed.to_k8s() == block
    else:
        with pytest.raises(ValidationError):
            IPBlock.from_wire(block)


def test_policy_types_must_cover_rules() -> None:
    rule = NetworkPolicyIngressRule(from_=(NetworkPolicyPeer(pod_selector=LabelSelector()),))
    with pytest.raises(ValidationError, match="require policyType Ingress"):
        NetworkPolicySpec(pod_selector=LabelSelector(), policy_types=("Egress",), ingress=(rule,))
    egress = NetworkPolicyEgressRule(to=(NetworkPolicyPeer(pod_selector=LabelSelector()),))
    with pytest.raises(ValidationError, match="require policyType Egress"):
        NetworkPolicySpec(pod_selector=LabelSelector(), policy_types=("Ingress",), egress=(egress,))
    with pytest.raises(ValidationError, match="duplicate policyTypes"):
        NetworkPolicySpec(pod_selector=LabelSelector(), policy_types=("Ingress", "Ingress"))
    with pytest.raises(ValidationError):
        NetworkPolicySpec(pod_selector=LabelSelector(), policy_types=())
    with pytest.raises(ValidationError):
        NetworkPolicySpec.from_wire({"podSelector": {}, "policyTypes": ["Both"]})


@pytest.mark.parametrize(
    ("port", "ok"),
    [
        ({"port": 6333, "endPort": 6334}, True),
        ({"port": "rest"}, True),
        ({"port": 6334, "endPort": 6333}, False),
        ({"port": "rest", "endPort": 6334}, False),
        ({"endPort": 6334}, False),
        ({"port": 0}, False),
        ({"port": 65536}, False),
        ({"protocol": "ICMP", "port": 1}, False),
    ],
)
def test_network_policy_port_validation(port: dict[str, Any], ok: bool) -> None:
    if ok:
        assert NetworkPolicyPort.from_wire(port).to_k8s() == {"protocol": "TCP", **port}
    else:
        with pytest.raises(ValidationError):
            NetworkPolicyPort.from_wire(port)


def test_network_policy_from_wire_roundtrip_with_alias() -> None:
    policy = NetworkPolicy.from_wire(
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "api-from-ingress", "namespace": NS},
            "spec": {
                "podSelector": {"matchLabels": APP_LABELS},
                "policyTypes": ["Ingress"],
                "ingress": [
                    {
                        "from": [
                            {
                                "namespaceSelector": {
                                    "matchLabels": {"kubernetes.io/metadata.name": "ingress-nginx"}
                                }
                            }
                        ],
                        "ports": [{"protocol": "TCP", "port": 8000}],
                    }
                ],
            },
        }
    )
    assert policy.spec.ingress[0].from_[0].namespace_selector is not None
    assert NetworkPolicy.from_wire(policy.to_k8s()) == policy


# ---------------------------------------------------------------------------
# Terraform bootstrap variables
# ---------------------------------------------------------------------------
def test_eks_tfvars_are_snake_case() -> None:
    tfvars = eks_vars().to_tfvars()
    assert tfvars["provider"] == "eks"
    assert tfvars["kubernetes_version"] == "1.33"
    assert tfvars["vpc"] == {
        "cidr": "10.0.0.0/16",
        "private_subnets": ["10.0.0.0/19", "10.0.32.0/19"],
        "public_subnets": ["10.0.128.0/24", "10.0.129.0/24"],
    }
    gpu = tfvars["node_pools"][1]  # type: ignore[index]
    assert gpu["accelerator_count"] == 1
    assert gpu["taints"] == [{"key": "nvidia.com/gpu", "value": "true", "effect": "NoSchedule"}]
    for path, key, _ in walk(tfvars):
        if not path.endswith(("labels", "tags")):
            assert not any(c.isupper() for c in key), f"camelCase key {path}.{key}"


def test_gke_vars_valid() -> None:
    gke = gke_vars()
    assert gke.vpc.pods_cidr == "10.64.0.0/14"
    assert gke.endpoint_public_access


@pytest.mark.parametrize(
    ("version", "message"),
    [
        ("1.29", "older than 1.31"),
        ("1.30", "older than 1.31"),
        ("v1.31", "invalid Kubernetes version"),
        ("1.31.2", "invalid Kubernetes version"),
        ("2.0", "invalid Kubernetes version"),
        ("1.3x", "invalid Kubernetes version"),
    ],
)
def test_kubernetes_version_constraints(version: str, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        eks_vars(kubernetes_version=version)


@pytest.mark.parametrize(
    ("build", "message"),
    [
        (lambda: eks_vars(region="europe-west4"), "not a valid eks region"),
        (lambda: gke_vars(region="eu-central-1"), "not a valid gke region"),
        (
            lambda: eks_vars(node_pools=(node_pool(machine_type="e2-standard-4"),)),
            "not a eks machine type",
        ),
        (
            lambda: gke_vars(node_pools=(node_pool(machine_type="m6i.xlarge"),)),
            "not a gke machine type",
        ),
        (lambda: eks_vars(node_pools=(node_pool(), node_pool())), "unique"),
        (lambda: eks_vars(max_total_nodes=8), "scale to 9 nodes"),
        (lambda: eks_vars(node_pools=()), "node_pools"),
        (
            lambda: eks_vars(vpc=VpcConfig(cidr="10.0.0.0/16", private_subnets=("10.0.0.0/19",))),
            "two availability zones",
        ),
        (
            lambda: gke_vars(vpc=VpcConfig(cidr="10.10.0.0/20", private_subnets=("10.10.0.0/22",))),
            "requires vpc.pods_cidr",
        ),
        (lambda: eks_vars(endpoint_public_access=True), "requires authorized_cidrs"),
        (lambda: gke_vars(authorized_cidrs=("0.0.0.0/0",)), "must not include 0.0.0.0/0"),
        (lambda: eks_vars(cluster_name="a" * 41), "cluster_name"),
        (lambda: eks_vars(provider="aks"), "provider"),
        (lambda: eks_vars(tags={"Project": "x"}), "tags"),
    ],
)
def test_bootstrap_invariants(build: Callable[[], object], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        build()


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"min_size": 3, "desired_size": 2}, "min_size <= desired_size <= max_size"),
        ({"desired_size": 6}, "min_size <= desired_size <= max_size"),
        ({"max_size": 0}, "max_size"),
        ({"min_size": -1}, "min_size"),
        ({"disk_size_gb": 10}, "disk_size_gb"),
        ({"accelerator_type": "nvidia-l4"}, "go together"),
        ({"accelerator_count": 1}, "go together"),
        ({"capacity_type": "preemptible"}, "capacity_type"),
        ({"taints": ({"key": "gpu", "effect": "Sometimes"},)}, "effect"),
    ],
)
def test_node_pool_autoscaling_bounds(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        node_pool(**overrides)


@pytest.mark.parametrize(
    ("vpc", "message"),
    [
        ({"cidr": "10.0.0.0/8", "private_subnets": ["10.0.0.0/19"]}, "between /16 and /24"),
        ({"cidr": "10.0.0.0/26", "private_subnets": ["10.0.0.0/27"]}, "between /16 and /24"),
        ({"cidr": "10.0.0.0/16", "private_subnets": ["10.1.0.0/19"]}, "outside VPC"),
        (
            {"cidr": "10.0.0.0/16", "private_subnets": ["10.0.0.0/19", "10.0.16.0/20"]},
            "overlap",
        ),
        (
            {
                "cidr": "10.0.0.0/16",
                "private_subnets": ["10.0.0.0/19"],
                "public_subnets": ["10.0.0.0/24"],
            },
            "overlap",
        ),
        (
            {
                "cidr": "10.0.0.0/16",
                "private_subnets": ["10.0.0.0/19"],
                "pods_cidr": "10.0.64.0/18",
            },
            "overlaps VPC",
        ),
        (
            {
                "cidr": "10.0.0.0/16",
                "private_subnets": ["10.0.0.0/19"],
                "pods_cidr": "10.64.0.0/14",
                "services_cidr": "10.64.0.0/20",
            },
            "overlap",
        ),
        ({"cidr": "10.0.0.1/16", "private_subnets": ["10.0.0.0/19"]}, "host bits"),
        ({"cidr": "10.0.0.0/16", "private_subnets": ["10.0.0/19"]}, "invalid CIDR"),
        ({"cidr": "2001:db8::/48", "private_subnets": ["2001:db8::/64"]}, "not an IPv4 CIDR"),
        ({"cidr": "10.0.0.0/16", "private_subnets": []}, "private_subnets"),
    ],
)
def test_vpc_cidr_layout(vpc: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        VpcConfig.from_wire(vpc)


def test_cidrs_are_normalized() -> None:
    assert IPBlock(cidr="2001:DB8:0::/32").cidr == "2001:db8::/32"


def test_cidr_leading_zero_octets_rejected() -> None:
    # Ambiguous (octal in some parsers): never let "010" silently mean 8 or 10.
    with pytest.raises(ValidationError, match="invalid CIDR"):
        VpcConfig(cidr="10.0.0.0/16", private_subnets=("10.0.000.0/19",))


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("K8SAI_"):
            monkeypatch.delenv(key)


def test_settings_defaults() -> None:
    settings = InfraSettings()
    assert settings.namespace == "ai-system"
    assert settings.environment == "dev"
    assert settings.image("inference-api") == "ghcr.io/mikez98/inference-api:0.1.0"
    meta = ObjectMeta(name="x", labels=settings.common_labels)
    assert meta.labels == {
        "app.kubernetes.io/part-of": "cloud-native-k8s-ai",
        "app.kubernetes.io/managed-by": "cloud-native-k8s-ai",
        "environment": "dev",
    }
    assert app_container(image=settings.image("inference-api")).image.endswith(":0.1.0")


def test_settings_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("K8SAI_ENVIRONMENT", "prod")
    monkeypatch.setenv("K8SAI_NAMESPACE", "ai-prod")
    monkeypatch.setenv("K8SAI_CLUSTER_NAME", "ai-eu-1")
    monkeypatch.setenv("K8SAI_IMAGE_REGISTRY", "registry.local:5000/ai")
    monkeypatch.setenv("K8SAI_IMAGE_TAG", "1.4.0")
    settings = InfraSettings()
    assert (settings.environment, settings.namespace, settings.cluster_name) == (
        "prod",
        "ai-prod",
        "ai-eu-1",
    )
    assert settings.image("qdrant") == "registry.local:5000/ai/qdrant:1.4.0"


@pytest.mark.parametrize(
    ("var", "value"),
    [
        ("K8SAI_ENVIRONMENT", "production"),
        ("K8SAI_NAMESPACE", "AI_System"),
        ("K8SAI_CLUSTER_NAME", "-bad"),
        ("K8SAI_IMAGE_TAG", "latest"),
        ("K8SAI_IMAGE_TAG", "has space"),
        ("K8SAI_IMAGE_REGISTRY", "https://ghcr.io"),
    ],
)
def test_invalid_settings_rejected(monkeypatch: pytest.MonkeyPatch, var: str, value: str) -> None:
    monkeypatch.setenv(var, value)
    with pytest.raises(ValidationError):
        InfraSettings()


def test_settings_forbid_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        InfraSettings(namspace="typo")  # type: ignore[call-arg]
