"""Stateful backing services: PVC templates, StatefulSets, Qdrant and Redis contracts."""

from __future__ import annotations

from itertools import combinations
from typing import Any, Literal, Self

from pydantic import (
    Field,
    SerializationInfo,
    SerializerFunctionWrapHandler,
    model_serializer,
    model_validator,
)

from cloud_native_k8s_ai.schemas._base import (
    AbsolutePath,
    DNS1123Label,
    DNS1123Subdomain,
    ImageRef,
    K8sModel,
    Labels,
    LabelSelector,
    MemoryQuantity,
    ObjectMeta,
    Port,
    StorageQuantity,
    memory_bytes,
)
from cloud_native_k8s_ai.schemas.cluster import (
    PodTemplateSpec,
    ResourceRequirements,
    check_selector_matches_template,
)

QDRANT_REST_PORT = 6333
QDRANT_GRPC_PORT = 6334
REDIS_PORT = 6379

AccessMode = Literal["ReadWriteOnce", "ReadOnlyMany", "ReadWriteMany", "ReadWriteOncePod"]


def _check_disjoint_paths(paths: dict[str, str]) -> None:
    """Reject identical or nested mount paths (``/data`` vs ``/data/snapshots``)."""
    for (a_name, a_path), (b_name, b_path) in combinations(paths.items(), 2):
        a, b = a_path.rstrip("/") + "/", b_path.rstrip("/") + "/"
        if a.startswith(b) or b.startswith(a):
            raise ValueError(f"{b_name} path {b_path} overlaps {a_name} path {a_path}")


# ---------------------------------------------------------------------------
# Persistent volume claims & StatefulSet
# ---------------------------------------------------------------------------
class StorageRequest(K8sModel):
    storage: StorageQuantity


class VolumeResourceRequirements(K8sModel):
    requests: StorageRequest


class PersistentVolumeClaimSpec(K8sModel):
    access_modes: tuple[AccessMode, ...] = Field(default=("ReadWriteOnce",), min_length=1)
    storage_class_name: DNS1123Subdomain | None = None
    """``None`` uses the cluster default storage class."""
    resources: VolumeResourceRequirements


class PersistentVolumeClaimTemplate(K8sModel):
    metadata: ObjectMeta
    spec: PersistentVolumeClaimSpec


class PersistentVolumeClaim(K8sModel):
    """Standalone claim, e.g. for a single-replica Deployment such as Redis."""

    api_version: Literal["v1"] = "v1"
    kind: Literal["PersistentVolumeClaim"] = "PersistentVolumeClaim"
    metadata: ObjectMeta
    spec: PersistentVolumeClaimSpec


class StatefulSetUpdateStrategy(K8sModel):
    type: Literal["RollingUpdate", "OnDelete"] = "RollingUpdate"


class PersistentVolumeClaimRetentionPolicy(K8sModel):
    when_deleted: Literal["Retain", "Delete"] = "Retain"
    when_scaled: Literal["Retain", "Delete"] = "Retain"


class StatefulSetSpec(K8sModel):
    service_name: DNS1123Label
    """Headless Service that gives each replica a stable DNS identity."""
    replicas: int = Field(default=1, ge=0, le=100)
    selector: LabelSelector
    template: PodTemplateSpec
    volume_claim_templates: tuple[PersistentVolumeClaimTemplate, ...] = ()
    pod_management_policy: Literal["OrderedReady", "Parallel"] = "OrderedReady"
    update_strategy: StatefulSetUpdateStrategy = Field(default_factory=StatefulSetUpdateStrategy)
    persistent_volume_claim_retention_policy: PersistentVolumeClaimRetentionPolicy = Field(
        default_factory=PersistentVolumeClaimRetentionPolicy
    )

    @model_validator(mode="after")
    def _well_formed(self) -> Self:
        check_selector_matches_template(self.selector, self.template)
        claims = [t.metadata.name for t in self.volume_claim_templates]
        if len(set(claims)) != len(claims):
            raise ValueError("duplicate volumeClaimTemplate names")
        volumes = {v.name for v in self.template.spec.volumes}
        if clash := volumes & set(claims):
            raise ValueError(f"claim templates shadow pod volumes: {sorted(clash)}")
        if missing := self.template.spec.mounted_volume_names() - volumes - set(claims):
            raise ValueError(f"volume mounts reference undeclared volumes: {sorted(missing)}")
        return self


class StatefulSet(K8sModel):
    api_version: Literal["apps/v1"] = "apps/v1"
    kind: Literal["StatefulSet"] = "StatefulSet"
    metadata: ObjectMeta
    spec: StatefulSetSpec


# ---------------------------------------------------------------------------
# Qdrant vector store (domain input for manifest generation)
# ---------------------------------------------------------------------------
class QdrantVolume(K8sModel):
    size: StorageQuantity
    mount_path: AbsolutePath
    storage_class_name: DNS1123Subdomain | None = None


class QdrantSpec(K8sModel):
    """Qdrant StatefulSet contract: REST/gRPC ports and separate storage/snapshot PVCs."""

    name: DNS1123Label = "qdrant"
    image: ImageRef
    replicas: int = Field(default=1, ge=1, le=100)
    rest_port: Port = QDRANT_REST_PORT
    grpc_port: Port = QDRANT_GRPC_PORT
    resources: ResourceRequirements
    storage: QdrantVolume = Field(
        default_factory=lambda: QdrantVolume(size="20Gi", mount_path="/qdrant/storage")
    )
    snapshots: QdrantVolume = Field(
        default_factory=lambda: QdrantVolume(size="10Gi", mount_path="/qdrant/snapshots")
    )
    labels: Labels = Field(default_factory=dict)

    @model_validator(mode="after")
    def _distinct_ports_and_paths(self) -> Self:
        if self.rest_port == self.grpc_port:
            raise ValueError("Qdrant REST and gRPC ports must differ")
        _check_disjoint_paths(
            {"storage": self.storage.mount_path, "snapshots": self.snapshots.mount_path}
        )
        return self


# ---------------------------------------------------------------------------
# Redis broker / cache (domain input for manifest generation)
# ---------------------------------------------------------------------------
class RdbSavePoint(K8sModel):
    """``save <seconds> <changes>``: snapshot after ``seconds`` if ``changes`` keys changed."""

    seconds: int = Field(ge=1, le=86_400)
    changes: int = Field(ge=1)


class RedisPersistence(K8sModel):
    mode: Literal["none", "rdb", "aof", "rdb+aof"] = "aof"
    appendfsync: Literal["always", "everysec", "no"] = "everysec"
    save_points: tuple[RdbSavePoint, ...] = (
        RdbSavePoint(seconds=3600, changes=1),
        RdbSavePoint(seconds=300, changes=100),
    )
    volume_size: StorageQuantity | None = "8Gi"
    storage_class_name: DNS1123Subdomain | None = None

    @model_serializer(mode="wrap")
    def _explicit_no_volume(
        self, handler: SerializerFunctionWrapHandler, info: SerializationInfo
    ) -> Any:
        """Keep ``volumeSize: null`` on the wire: dropping it (``exclude_none``) would let
        the ``8Gi`` default reappear on parsing and fail ``mode: none``."""
        data = handler(self)
        if self.volume_size is None and not {"volumeSize", "volume_size"} & set(data):
            data["volume_size" if info.by_alias is False else "volumeSize"] = None
        return data

    @property
    def rdb(self) -> bool:
        return self.mode in {"rdb", "rdb+aof"}

    @property
    def aof(self) -> bool:
        return self.mode in {"aof", "rdb+aof"}

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.mode == "none" and self.volume_size is not None:
            raise ValueError("persistence mode 'none' must not request a volume")
        if self.mode != "none" and self.volume_size is None:
            raise ValueError(f"persistence mode {self.mode!r} requires volumeSize")
        if self.rdb and not self.save_points:
            raise ValueError("RDB persistence requires at least one save point")
        return self


MaxMemoryPolicy = Literal[
    "noeviction",
    "allkeys-lru",
    "allkeys-lfu",
    "allkeys-random",
    "volatile-lru",
    "volatile-lfu",
    "volatile-random",
    "volatile-ttl",
]


class RedisSpec(K8sModel):
    """Redis contract: in-memory ceiling below the container limit, explicit persistence."""

    name: DNS1123Label = "redis"
    image: ImageRef
    port: Port = REDIS_PORT
    resources: ResourceRequirements
    maxmemory: MemoryQuantity
    maxmemory_policy: MaxMemoryPolicy = "noeviction"
    """``noeviction`` by default: queues must never silently drop jobs."""
    persistence: RedisPersistence = Field(default_factory=RedisPersistence)
    data_mount_path: AbsolutePath = "/data"
    labels: Labels = Field(default_factory=dict)

    @model_validator(mode="after")
    def _maxmemory_has_headroom(self) -> Self:
        if memory_bytes(self.maxmemory) >= memory_bytes(self.resources.limits.memory):
            raise ValueError(
                f"maxmemory {self.maxmemory} must stay below the memory limit "
                f"{self.resources.limits.memory} (fork/AOF rewrite headroom)"
            )
        return self

    def server_args(self) -> tuple[str, ...]:
        """``redis-server`` arguments implementing this contract."""
        p = self.persistence
        args = [
            "--port",
            str(self.port),
            "--maxmemory",
            str(memory_bytes(self.maxmemory)),
            "--maxmemory-policy",
            self.maxmemory_policy,
            "--appendonly",
            "yes" if p.aof else "no",
            "--dir",
            self.data_mount_path,
        ]
        if p.aof:
            args += ["--appendfsync", p.appendfsync]
        save = " ".join(f"{s.seconds} {s.changes}" for s in p.save_points) if p.rdb else ""
        args += ["--save", save]
        return tuple(args)
