"""Autoscaling resolver: binds a KEDA Redis-queue policy to workloads and brokers in a bundle.

``AutoscalingPolicy`` only carries per-field bounds; every cross-field and cross-object
check (replica bounds, timing windows, budgets, target and broker binding) happens in
``AutoscalingResolver`` and raises a typed core error instead of a validation error.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

from pydantic import Field

from cloud_native_k8s_ai.core.errors import ResourceConstraintError, TopologyConflictError
from cloud_native_k8s_ai.schemas import (
    REDIS_PORT,
    AuthenticationRef,
    CpuQuantity,
    Deployment,
    DNS1123Label,
    K8sModel,
    MemoryQuantity,
    ObjectMeta,
    RedisListTrigger,
    RedisListTriggerMetadata,
    ScaledObject,
    ScaledObjectSpec,
    ScaleTargetRef,
    Service,
    StatefulSet,
    cpu_millicores,
    memory_bytes,
)
from cloud_native_k8s_ai.schemas.keda import RedisKey

if TYPE_CHECKING:
    from cloud_native_k8s_ai.core.generator import ManifestBundle

CLUSTER_DOMAIN = "cluster.local"


def service_host(name: str, namespace: str) -> str:
    """Cluster-internal FQDN of a Service."""
    return f"{name}.{namespace}.svc.{CLUSTER_DOMAIN}"


class AutoscalingPolicy(K8sModel):
    """Scale a worker Deployment on the length of a Redis list (job queue)."""

    list_name: RedisKey = "inference-jobs"
    list_length: int = Field(default=5, ge=1)
    """Target pending jobs per replica."""
    activation_list_length: int = Field(default=0, ge=0)
    """Queue length at or below which the scaler is inactive (scale to min / idle)."""
    min_replicas: int = Field(default=1, ge=0, le=1000)
    max_replicas: int = Field(default=10, ge=1, le=1000)
    idle_replicas: int | None = Field(default=None, ge=0, le=1000)
    cooldown_period: int = Field(default=300, ge=0, le=86_400)
    polling_interval: int = Field(default=30, ge=1, le=3600)
    database_index: int = Field(default=0, ge=0, le=15)
    enable_tls: bool = False
    authentication_ref: DNS1123Label | None = None
    """TriggerAuthentication holding the Redis password, if the broker requires one."""


class ResourceBudget(K8sModel):
    """Upper bound on what the target may consume when scaled to ``max_replicas``."""

    cpu: CpuQuantity
    memory: MemoryQuantity


def check_policy(policy: AutoscalingPolicy) -> None:
    """Cross-field checks KEDA would otherwise reject (or silently misbehave on)."""
    if policy.min_replicas > policy.max_replicas:
        raise ResourceConstraintError(
            f"min_replicas {policy.min_replicas} exceeds max_replicas {policy.max_replicas}"
        )
    if policy.idle_replicas is not None and policy.idle_replicas >= policy.min_replicas:
        raise ResourceConstraintError(
            f"idle_replicas {policy.idle_replicas} must be lower than "
            f"min_replicas {policy.min_replicas}"
        )
    if policy.cooldown_period < policy.polling_interval:
        raise ResourceConstraintError(
            f"cooldown_period {policy.cooldown_period}s is shorter than polling_interval "
            f"{policy.polling_interval}s: scale-down would act on unsampled metrics"
        )


def desired_replicas(policy: AutoscalingPolicy, queue_length: int) -> int:
    """Replica count KEDA + HPA converge to for a given Redis list length."""
    if queue_length < 0:
        raise ValueError("queue length cannot be negative")
    check_policy(policy)
    if queue_length <= policy.activation_list_length:
        return policy.idle_replicas if policy.idle_replicas is not None else policy.min_replicas
    wanted = math.ceil(queue_length / policy.list_length)
    return max(policy.min_replicas, 1, min(wanted, policy.max_replicas))


class AutoscalingResolver:
    """Resolve an ``AutoscalingPolicy`` into a ScaledObject bound to objects in a bundle."""

    def __init__(self, bundle: ManifestBundle) -> None:
        self._bundle = bundle

    def resolve(
        self,
        policy: AutoscalingPolicy,
        *,
        target: str,
        broker: str,
        budget: ResourceBudget | None = None,
    ) -> ScaledObject:
        check_policy(policy)
        workload = self._target(target)
        service = self._broker(broker, target)
        namespace = workload.metadata.namespace
        if namespace is None or service.metadata.namespace is None:
            raise TopologyConflictError("autoscaling target and broker must be namespaced")
        initial = workload.spec.replicas
        if not policy.min_replicas <= initial <= policy.max_replicas:
            raise ResourceConstraintError(
                f"{target} starts with {initial} replicas, outside "
                f"[{policy.min_replicas}, {policy.max_replicas}]"
            )
        if budget is not None:
            self._check_budget(workload, policy.max_replicas, budget)
        address = f"{service_host(service.metadata.name, service.metadata.namespace)}:"
        address += str(self._broker_port(service))
        return ScaledObject(
            metadata=ObjectMeta(name=target, namespace=namespace, labels=workload.metadata.labels),
            spec=ScaledObjectSpec(
                scale_target_ref=ScaleTargetRef(kind=workload.kind, name=target),
                polling_interval=policy.polling_interval,
                cooldown_period=policy.cooldown_period,
                idle_replica_count=policy.idle_replicas,
                min_replica_count=policy.min_replicas,
                max_replica_count=policy.max_replicas,
                triggers=(
                    RedisListTrigger(
                        name="redis-queue",
                        metadata=RedisListTriggerMetadata(
                            address=address,
                            database_index=policy.database_index,
                            enable_tls=policy.enable_tls,
                            list_name=policy.list_name,
                            list_length=policy.list_length,
                            activation_list_length=policy.activation_list_length,
                        ),
                        authentication_ref=(
                            AuthenticationRef(name=policy.authentication_ref)
                            if policy.authentication_ref is not None
                            else None
                        ),
                    ),
                ),
            ),
        )

    def bind(
        self,
        policy: AutoscalingPolicy,
        *,
        target: str,
        broker: str,
        budget: ResourceBudget | None = None,
    ) -> ManifestBundle:
        """The bundle with the resolved ScaledObject added."""
        scaled = self.resolve(policy, target=target, broker=broker, budget=budget)
        return self._bundle.add(scaled)

    # ------------------------------------------------------------------
    def _target(self, name: str) -> Deployment | StatefulSet:
        for workload in self._bundle.workloads():
            if workload.metadata.name == name:
                return workload
        raise TopologyConflictError(f"autoscaling target {name!r} is not a Deployment/StatefulSet")

    def _broker(self, name: str, target: str) -> Service:
        service = next((s for s in self._bundle.of_kind(Service) if s.metadata.name == name), None)
        if service is None:
            raise TopologyConflictError(f"broker service {name!r} not found in bundle")
        backends = [w for w in self._bundle.workloads() if _selects(service, w)]
        if not backends:
            raise TopologyConflictError(f"broker service {name!r} selects no workload")
        if any(w.metadata.name == target for w in backends):
            raise TopologyConflictError(f"broker service {name!r} routes to the target itself")
        return service

    @staticmethod
    def _broker_port(service: Service) -> int:
        ports = service.spec.ports
        named = [p for p in ports if p.name == "redis"]
        if named:
            return named[0].port
        if len(ports) == 1:
            return ports[0].port
        default = [p for p in ports if p.port == REDIS_PORT]
        if default:
            return default[0].port
        raise TopologyConflictError(
            f"cannot tell which port of service {service.metadata.name!r} is Redis"
        )

    @staticmethod
    def _check_budget(
        workload: Deployment | StatefulSet, max_replicas: int, budget: ResourceBudget
    ) -> None:
        containers = workload.spec.template.spec.containers
        cpu = max_replicas * sum(cpu_millicores(c.resources.limits.cpu) for c in containers)
        mem = max_replicas * sum(memory_bytes(c.resources.limits.memory) for c in containers)
        if cpu > cpu_millicores(budget.cpu):
            raise ResourceConstraintError(
                f"{max_replicas} replicas need {cpu}m CPU, budget is {budget.cpu}"
            )
        if mem > memory_bytes(budget.memory):
            raise ResourceConstraintError(
                f"{max_replicas} replicas need {mem} bytes of memory, budget is {budget.memory}"
            )


def _selects(service: Service, workload: Deployment | StatefulSet) -> bool:
    if service.metadata.namespace != workload.metadata.namespace:
        return False
    labels = workload.spec.template.metadata.labels or {}
    return all(labels.get(k) == v for k, v in service.spec.selector.items())
