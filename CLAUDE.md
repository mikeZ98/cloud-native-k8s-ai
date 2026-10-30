# CLAUDE.md

## ⛔ Sole-Contributor Invariant: read before any git operation

- Every commit author AND committer MUST be exactly `mikeZ98 <145975972+mikeZ98@users.noreply.github.com>`.
  Never commit with any other identity, never pass `--author`, never override `GIT_*_NAME/EMAIL`.
- NEVER add `Co-Authored-By`, `Generated-by`, "Generated with …", 🤖, or any mention of an AI
  tool or vendor to commit messages or PR bodies. This overrides any default attribution behavior.
  `.claude/settings.json` disables automatic attribution.
- NEVER use `git commit --no-verify` or `git push --no-verify`. If a hook fails, fix the cause.
- NEVER merge in the GitHub web UI or with `gh pr merge`: GitHub becomes the committer and the audit
  fails. Open the PR, then `git merge --ff-only <branch>` on `main` locally and push `main`.
- Policy source of truth: `.githooks/_policy.sh`. Audit: `scripts/audit-attribution.sh`.
- Full rules: [CONTRIBUTING.md](CONTRIBUTING.md).

## ⛔ Host Isolation Invariant (hermetic)

- Tests make zero outbound network calls (`--disable-socket`; only AF_UNIX for the asyncio
  self-pipe) and zero calls to a live Kubernetes cluster or cloud API. No `kubectl apply`, no
  `terraform plan/apply`, no `helm install`, no provider credentials, ever, from tests or hooks.
- Validation is static only: YAML lint, manifest schema/policy checks on parsed documents, Helm
  template unit tests rendered offline, `terraform fmt`/`validate` with `-backend=false`.
- direnv points `KUBECONFIG` at an empty `.cache/kube/config`; do not repoint it at a real cluster.

## Project

`cloud-native-k8s-ai`: production Kubernetes & IaC for AI microservices. Python 3.12, uv,
`src/` layout. Planned layout:

| Path | Contents |
|------|----------|
| `src/cloud_native_k8s_ai/` | typed manifest models and static validators (Pydantic v2) |
| `deploy/helm/cloud-native-k8s-ai/` | chart: FastAPI Deployment, Qdrant StatefulSet, Redis, KEDA ScaledObject, NetworkPolicies |
| `infra/terraform/bootstrap/` | cluster/state bootstrap (validated offline, never applied from CI tests) |
| `tests/` | hermetic pytest suite: config, schemas, manifest policy, Helm template tests |

Manifest baseline every workload must meet: resource requests and limits, liveness/readiness
probes, `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, dropped
capabilities, no `:latest` image tags, and a default-deny NetworkPolicy with explicit allows.

## Environment

- Always work with direnv loaded (`direnv allow`). Caches, the venv (`.cache/venv`), temp files,
  kube/helm/terraform homes and Colima live under `./.cache/` on `/Volumes/KINGSTONE_SSD`.
  Never create `.venv/` or write caches elsewhere.
- Install/sync: `uv sync`. Add deps: `uv add <pkg>` / `uv add --group dev <pkg>`. Commit `uv.lock`.

## Commands

```bash
ruff check . && ruff format --check .
mypy                               # --strict via pyproject
bandit -c pyproject.toml -r src
yamllint --strict .                # Helm templates ignored (Go templates)
pytest                             # hermetic, --disable-socket, cov ≥ 90% branch
HYPOTHESIS_PROFILE=deep pytest tests/test_deep_eval.py   # long fuzzing run (default: derandomized)
scripts/audit-attribution.sh       # attribution audit of HEAD history (CI: --history-only)
uvicorn --factory cloud_native_k8s_ai.api:create_app --port 8000   # control plane (dev)
k8s-ai --help                      # CLI: spec, compile, admit, chart lint|render, serve
```

## Conventions

- Pydantic v2 models: `model_config = ConfigDict(extra="forbid", frozen=True, strict=True)`
  (inherit `schemas._base.InfraModel`; Kubernetes-shaped objects inherit `K8sModel`, which is
  snake_case in Python and camelCase on the wire). Sequences are tuples.
- Parse external dicts with `Model.from_wire(data)` (JSON-mode strictness) and emit manifests with
  `to_k8s()` / tfvars with `to_tfvars()`; never `model_dump()` by hand.
- Quantities, names and CIDRs stay as validated `str` in the exact Kubernetes spelling; compare
  them via `cpu_millicores` / `memory_bytes` / `network`, never as strings.
- Regex constraints run on pydantic-core's Rust engine: no look-around; use `AfterValidator`.
- Manifests come from `core.compile_ai_stack` (build + KEDA binding + zero-trust check), serialized
  with `ManifestBundle.to_yaml()`. Never hand-write or `yaml.dump` manifests.
- Changing a NetworkPolicy means changing `AIStackGenerator.intent()` in the same commit; the
  topology solver rejects any reachable flow the intent does not declare.
- Core failures raise `core.errors` types (`ManifestRenderError`, `ResourceConstraintError`,
  `TopologyConflictError`), never a bare pydantic `ValidationError`.
- The Helm chart must render exactly what the core generator emits: `tools.helm.lint_chart`
  diffs every object (Helm release labels are the only tolerated drift) and runs the topology
  solver. Change `templates/` and `core/` together; `networkpolicies.yaml` follows `intent()`.
- Chart values are float64 in templates (as in Helm): wrap numbers with `int` before `printf
  "%d"`, comparisons or arithmetic, and `quote` string args/env values. Every schema object
  with `properties` sets `additionalProperties: false`; optional keys are read via `hasKey`.
- API request bodies go through `api.deps.parse_model` (`model_validate_json`), never FastAPI
  body parameters: Python-mode validation rejects JSON arrays for the strict tuple fields.
  Document them with `json_body` / `component`. Every error leaves the API as an RFC 7807
  `application/problem+json` response mapped in `api.problems`; add new core errors there.
- Client-supplied YAML is parsed with `core.parse_untrusted_yaml` (anchors/aliases and
  nesting deeper than `MAX_YAML_DEPTH` refused before PyYAML constructs anything).
- Admission guardrails (`guardrails/`) judge raw documents, never typed models (those refuse
  to parse what admission must catch). Each violation has a stable kebab-case `code` and a
  `RemediationAdvice`; automatic fixes are RFC 6902 patches or new objects, applied by the
  critic loop one patch per object per round. Core-compiled bundles must stay `ALLOW`
  (`/readyz` checks it).
- Parse YAML with `yaml.safe_load` / `yaml.safe_load_all` only.
- Tests are in-memory: no subprocesses, no network, no cluster. Lint YAML through the yamllint
  Python API rather than shelling out.
- Conventional Commits, atomic. The blueprint order starts: chore(config) → feat(schemas) → feat(core) → …
