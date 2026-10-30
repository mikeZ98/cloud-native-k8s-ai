"""AdmissionEngine: every guardrail over a manifest set, one aggregated report.

Accepts a compiled ``ManifestBundle``, untrusted multi-document YAML (anchors refused)
or raw documents. ``evaluate`` only judges; ``remediate`` runs the critic loop across
all guardrails; ``admit`` raises ``AdmissionDeniedError`` on any blocking violation.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from cloud_native_k8s_ai.core import (
    AIStackGenerator,
    AIStackSpec,
    ManifestBundle,
    parse_untrusted_yaml,
)
from cloud_native_k8s_ai.guardrails.admission import WorkloadGuardrail
from cloud_native_k8s_ai.guardrails.keda_critic import KedaCritic
from cloud_native_k8s_ai.guardrails.models import AdmissionReport, GuardrailError, RemediationResult
from cloud_native_k8s_ai.guardrails.network_critic import KUBE_SYSTEM, NetworkCritic
from cloud_native_k8s_ai.guardrails.remediation import (
    DEFAULT_MAX_ROUNDS,
    Guardrail,
    critic_loop,
    evaluate_all,
)
from cloud_native_k8s_ai.schemas import InfraSettings

type Manifests = ManifestBundle | str | Sequence[Mapping[str, Any]]

DEFAULT_GUARDRAILS: Final[tuple[Guardrail, ...]] = (
    WorkloadGuardrail(),
    NetworkCritic(),
    KedaCritic(),
)


def load_documents(manifests: Manifests) -> list[dict[str, Any]]:
    """Raw documents from any accepted input; inputs are never mutated."""
    if isinstance(manifests, ManifestBundle):
        return manifests.to_documents()
    if isinstance(manifests, str):
        return parse_untrusted_yaml(manifests)
    documents = list(manifests)
    if not all(isinstance(d, Mapping) for d in documents):
        raise GuardrailError("every manifest must be a mapping")
    return [copy.deepcopy(dict(d)) for d in documents]


@dataclass(frozen=True)
class AdmissionEngine:
    guardrails: tuple[Guardrail, ...] = DEFAULT_GUARDRAILS

    @classmethod
    def for_stack(cls, settings: InfraSettings, spec: AIStackSpec) -> AdmissionEngine:
        """Guardrails configured with a stack's own trust instead of generic defaults.

        Trusted namespaces are the stack's ingress-controller and KEDA namespaces (plus
        ``kube-system`` for DNS), and "the API" / "Qdrant" are its exact immutable
        selectors, so a look-alike labelled ``component: api`` is never taken for the API.
        """
        generator = AIStackGenerator(settings, spec)
        network = NetworkCritic(
            trusted_namespaces=frozenset(
                {KUBE_SYSTEM, spec.ingress_namespace, spec.keda_namespace}
            ),
            vector_store_labels=generator.qdrant_selector,
            api_labels=generator.app_selector,
        )
        return cls((WorkloadGuardrail(), network, KedaCritic()))

    def evaluate(self, manifests: Manifests) -> AdmissionReport:
        documents = load_documents(manifests)
        return AdmissionReport.build(documents, evaluate_all(self.guardrails, documents))

    def admit(self, manifests: Manifests) -> AdmissionReport:
        """``evaluate``, raising ``AdmissionDeniedError`` when anything blocks admission."""
        report = self.evaluate(manifests)
        report.raise_for_denial()
        return report

    def remediate(
        self, manifests: Manifests, *, max_rounds: int = DEFAULT_MAX_ROUNDS
    ) -> RemediationResult:
        return critic_loop(self.guardrails, load_documents(manifests), max_rounds=max_rounds)


def evaluate_manifests(manifests: Manifests) -> AdmissionReport:
    """Run the default guardrails (workload security, zero-trust network, autoscaling)."""
    return AdmissionEngine().evaluate(manifests)
