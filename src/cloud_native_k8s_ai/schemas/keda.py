"""KEDA event-driven autoscaling: ScaledObject with Redis list / stream triggers.

KEDA trigger metadata is a ``map[string]string``, so numeric and boolean fields are
typed in Python and serialized as strings; both spellings are accepted on input.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal, Self

from pydantic import (
    AfterValidator,
    BeforeValidator,
    Field,
    PlainSerializer,
    StringConstraints,
    model_validator,
)

from cloud_native_k8s_ai.schemas._base import MAX_PORT, DNS1123Label, K8sModel, ObjectMeta

_DIGITS_RE = re.compile(r"^[0-9]+$")
_ADDRESS_RE = re.compile(r"^(?P<host>[a-z0-9]([-a-z0-9.]*[a-z0-9])?):(?P<port>[0-9]{1,5})$")


def _int_from_metadata(value: Any) -> Any:
    if isinstance(value, str) and _DIGITS_RE.match(value):
        return int(value)
    return value


def _bool_from_metadata(value: Any) -> Any:
    return {"true": True, "false": False}.get(value, value) if isinstance(value, str) else value


def _redis_address(value: str) -> str:
    match = _ADDRESS_RE.match(value)
    if match is None or not 1 <= int(match["port"]) <= MAX_PORT:
        raise ValueError(f"invalid Redis address {value!r}: expected '<host>:<port 1-65535>'")
    return value


MetadataInt = Annotated[int, BeforeValidator(_int_from_metadata), PlainSerializer(str)]
MetadataBool = Annotated[
    bool,
    BeforeValidator(_bool_from_metadata),
    PlainSerializer(lambda v: "true" if v else "false"),
]
RedisAddress = Annotated[str, StringConstraints(max_length=261), AfterValidator(_redis_address)]
"""``<host>:<port>`` of the Redis endpoint, e.g. ``redis.ai-system.svc.cluster.local:6379``."""
RedisKey = Annotated[str, StringConstraints(min_length=1, max_length=512, pattern=r"^\S+$")]


class _RedisConnection(K8sModel):
    address: RedisAddress
    database_index: Annotated[MetadataInt, Field(ge=0, le=15)] = 0
    enable_tls: MetadataBool = Field(default=False, alias="enableTLS")


class RedisListTriggerMetadata(_RedisConnection):
    """Scale on ``LLEN listName``: one replica per ``listLength`` pending jobs."""

    list_name: RedisKey
    list_length: Annotated[MetadataInt, Field(ge=1)] = 5
    activation_list_length: Annotated[MetadataInt, Field(ge=0)] = 0


class RedisStreamTriggerMetadata(_RedisConnection):
    """Scale on consumer-group pending entries of a Redis stream (queue depth)."""

    stream: RedisKey
    consumer_group: RedisKey
    pending_entries_count: Annotated[MetadataInt, Field(ge=1)] = 5
    activation_lag_count: Annotated[MetadataInt, Field(ge=0)] = 0


class AuthenticationRef(K8sModel):
    name: DNS1123Label
    kind: Literal["TriggerAuthentication", "ClusterTriggerAuthentication"] = "TriggerAuthentication"


class RedisListTrigger(K8sModel):
    type: Literal["redis"] = "redis"
    name: DNS1123Label | None = None
    metadata: RedisListTriggerMetadata
    authentication_ref: AuthenticationRef | None = None


class RedisStreamTrigger(K8sModel):
    type: Literal["redis-streams"] = "redis-streams"
    name: DNS1123Label | None = None
    metadata: RedisStreamTriggerMetadata
    authentication_ref: AuthenticationRef | None = None


Trigger = Annotated[RedisListTrigger | RedisStreamTrigger, Field(discriminator="type")]


class ScaleTargetRef(K8sModel):
    api_version: Literal["apps/v1"] = "apps/v1"
    kind: Literal["Deployment", "StatefulSet"] = "Deployment"
    name: DNS1123Label


class ScaledObjectSpec(K8sModel):
    scale_target_ref: ScaleTargetRef
    polling_interval: int = Field(default=30, ge=1, le=3600)
    cooldown_period: int = Field(default=300, ge=0, le=86_400)
    idle_replica_count: int | None = Field(default=None, ge=0)
    min_replica_count: int = Field(default=1, ge=0, le=1000)
    max_replica_count: int = Field(default=10, ge=1, le=1000)
    triggers: tuple[Trigger, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _replica_bounds(self) -> Self:
        if self.min_replica_count > self.max_replica_count:
            raise ValueError(
                f"minReplicaCount {self.min_replica_count} exceeds "
                f"maxReplicaCount {self.max_replica_count}"
            )
        if self.idle_replica_count is not None and (
            self.idle_replica_count >= self.min_replica_count
        ):
            raise ValueError("idleReplicaCount must be lower than minReplicaCount")
        names = [t.name for t in self.triggers if t.name is not None]
        if len(set(names)) != len(names):
            raise ValueError("trigger names must be unique")
        return self


class ScaledObject(K8sModel):
    api_version: Literal["keda.sh/v1alpha1"] = "keda.sh/v1alpha1"
    kind: Literal["ScaledObject"] = "ScaledObject"
    metadata: ObjectMeta
    spec: ScaledObjectSpec
