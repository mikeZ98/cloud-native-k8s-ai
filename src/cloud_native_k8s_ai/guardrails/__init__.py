"""Admission guardrails: workload security, zero-trust network critic, autoscaling safety
and the auto-remediation critic loop, all pure and in-memory."""

from cloud_native_k8s_ai.guardrails.admission import WorkloadGuardrail, image_problem
from cloud_native_k8s_ai.guardrails.engine import (
    DEFAULT_GUARDRAILS,
    AdmissionEngine,
    Manifests,
    evaluate_manifests,
    load_documents,
)
from cloud_native_k8s_ai.guardrails.keda_critic import KedaCritic
from cloud_native_k8s_ai.guardrails.models import (
    AdmissionDeniedError,
    AdmissionReport,
    GuardrailDecision,
    GuardrailError,
    JsonPatchOp,
    ObjectDecision,
    ObjectRef,
    PolicyViolation,
    RemediationAdvice,
    RemediationResult,
    RemediationRound,
)
from cloud_native_k8s_ai.guardrails.network_critic import NetworkCritic
from cloud_native_k8s_ai.guardrails.remediation import (
    Guardrail,
    apply_patch,
    apply_remediations,
    critic_loop,
)

__all__ = [
    "DEFAULT_GUARDRAILS",
    "AdmissionDeniedError",
    "AdmissionEngine",
    "AdmissionReport",
    "Guardrail",
    "GuardrailDecision",
    "GuardrailError",
    "JsonPatchOp",
    "KedaCritic",
    "Manifests",
    "NetworkCritic",
    "ObjectDecision",
    "ObjectRef",
    "PolicyViolation",
    "RemediationAdvice",
    "RemediationResult",
    "RemediationRound",
    "WorkloadGuardrail",
    "apply_patch",
    "apply_remediations",
    "critic_loop",
    "evaluate_manifests",
    "image_problem",
    "load_documents",
]
