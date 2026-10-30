"""Auto-remediation: RFC 6902 patches and the critic loop that applies them until stable.

Each round applies at most one patch per object, then re-runs every guardrail on the
result. Patches on the same object can invalidate each other's JSON pointers (removing a
rule shifts the indices after it), so one fix per object per round keeps every patch
valid; the loop picks up whatever is left on the next round.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from cloud_native_k8s_ai.guardrails.models import (
    AdmissionReport,
    GuardrailError,
    JsonPatchOp,
    ObjectRef,
    PolicyViolation,
    RemediationResult,
    RemediationRound,
)

DEFAULT_MAX_ROUNDS = 16


class Guardrail(Protocol):
    """A policy over a whole manifest set (some checks need several objects at once)."""

    @property
    def name(self) -> str: ...

    def evaluate(self, documents: Sequence[Mapping[str, Any]]) -> list[PolicyViolation]: ...


def evaluate_all(
    guardrails: Sequence[Guardrail], documents: Sequence[Mapping[str, Any]]
) -> list[PolicyViolation]:
    return [v for guardrail in guardrails for v in guardrail.evaluate(documents)]


# ---------------------------------------------------------------------------
# JSON Patch (add / replace / remove)
# ---------------------------------------------------------------------------
def _tokens(path: str) -> list[str]:
    if path == "":
        return []
    if not path.startswith("/"):
        raise GuardrailError(f"invalid JSON pointer {path!r}")
    return [t.replace("~1", "/").replace("~0", "~") for t in path[1:].split("/")]


def _index(token: str, size: int, path: str) -> int:
    if not token.isdigit() or int(token) >= size:
        raise GuardrailError(f"{path}: index {token!r} out of range")
    return int(token)


def _child(node: Any, token: str, path: str) -> Any:
    if isinstance(node, dict) and token in node:
        return node[token]
    if isinstance(node, list):
        return node[_index(token, len(node), path)]
    raise GuardrailError(f"{path}: {token!r} does not exist")


def _apply(document: Any, op: JsonPatchOp) -> Any:
    tokens = _tokens(op.path)
    if not tokens:
        if op.op == "remove":
            raise GuardrailError("cannot remove the whole document")
        return copy.deepcopy(op.value)
    parent = document
    for token in tokens[:-1]:
        parent = _child(parent, token, op.path)
    last = tokens[-1]
    value = copy.deepcopy(op.value)
    if isinstance(parent, dict):
        if op.op != "add" and last not in parent:
            raise GuardrailError(f"{op.path}: {last!r} does not exist")
        if op.op == "remove":
            del parent[last]
        else:
            parent[last] = value
    elif isinstance(parent, list):
        if op.op == "add":
            position = len(parent) if last == "-" else _index(last, len(parent) + 1, op.path)
            parent.insert(position, value)
        elif op.op == "replace":
            parent[_index(last, len(parent), op.path)] = value
        else:
            del parent[_index(last, len(parent), op.path)]
    else:
        raise GuardrailError(f"{op.path}: parent is not a container")
    return document


def apply_patch(document: Mapping[str, Any], ops: Sequence[JsonPatchOp]) -> dict[str, Any]:
    """A patched copy of ``document``; the original is never modified."""
    patched: Any = copy.deepcopy(dict(document))
    for op in ops:
        patched = _apply(patched, op)
    if not isinstance(patched, dict):
        raise GuardrailError("a patch replaced the document with a non-object")
    return patched


# ---------------------------------------------------------------------------
# Critic loop
# ---------------------------------------------------------------------------
def apply_remediations(
    documents: Sequence[Mapping[str, Any]], violations: Sequence[PolicyViolation]
) -> tuple[list[dict[str, Any]], list[PolicyViolation]]:
    """Apply automatic remediations: one patch per object, every new object once."""
    result = [copy.deepcopy(dict(d)) for d in documents]
    index = {ObjectRef.of(d): i for i, d in enumerate(result)}
    patched: set[ObjectRef] = set()
    applied: list[PolicyViolation] = []
    for violation in violations:
        advice = violation.remediation
        if advice.action == "patch" and violation.target in index:
            if violation.target in patched:
                continue
            position = index[violation.target]
            try:
                result[position] = apply_patch(result[position], advice.patch)
            except GuardrailError:
                continue  # stale pointer: the next evaluation re-derives the fix
            patched.add(violation.target)
            applied.append(violation)
        elif advice.action == "create" and advice.document is not None:
            ref = ObjectRef.of(advice.document)
            if ref not in index:
                index[ref] = len(result)
                result.append(copy.deepcopy(advice.document))
                applied.append(violation)
    return result, applied


def critic_loop(
    guardrails: Sequence[Guardrail],
    documents: Sequence[Mapping[str, Any]],
    *,
    max_rounds: int = DEFAULT_MAX_ROUNDS,
) -> RemediationResult:
    """Evaluate, apply automatic fixes, re-evaluate; stop when nothing more can be fixed."""
    current = [copy.deepcopy(dict(d)) for d in documents]
    violations = evaluate_all(guardrails, current)
    initial = AdmissionReport.build(current, violations)
    rounds: list[RemediationRound] = []
    for number in range(1, max_rounds + 1):
        updated, applied = apply_remediations(current, violations)
        if not applied or updated == current:
            break
        current = updated
        violations = evaluate_all(guardrails, current)
        rounds.append(
            RemediationRound(
                round=number,
                applied=tuple(f"{v.code} {v.target}" for v in applied),
                remaining=len(violations),
            )
        )
    return RemediationResult(
        initial=initial,
        final=AdmissionReport.build(current, violations),
        rounds=tuple(rounds),
        converged=not any(v.remediation.automatic for v in violations),
        documents=tuple(current),
    )
