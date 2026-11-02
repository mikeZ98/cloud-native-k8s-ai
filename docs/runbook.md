# Operational runbook

On-call guide for the cloud-native-k8s-ai stack (inference API, Qdrant, Redis, KEDA,
zero-trust NetworkPolicies) and its control plane. Alert rules ship in
[`deploy/monitoring/alerts.yaml`](../deploy/monitoring/alerts.yaml); each links to a
section below. Architecture: [architecture.md](architecture.md); threat model and code
catalog: [security_model.md](security_model.md); API and CLI: [api_reference.md](api_reference.md).

- [1. Quick reference](#1-quick-reference)
- [2. Signals and alert thresholds](#2-signals-and-alert-thresholds)
- [3. Incident playbooks](#3-incident-playbooks)
- [4. Recovery, break-glass and manual overrides](#4-recovery-break-glass-and-manual-overrides)
- [5. Offline drift analysis](#5-offline-drift-analysis)
- [6. After every incident](#6-after-every-incident)

## 1. Quick reference

| Symptom | Go to | First command |
|---|---|---|
| CI or the control plane rejects most manifests | [3.1](#31-admission-denial-storm-and-rogue-manifest-flooding) | `k8s-ai admit manifests.yaml --spec stack.yaml` |
| Jobs pile up in Redis, replicas do not move | [3.2](#32-keda-scaler-decoupling-queue-starvation-and-saturation) | `kubectl -n ai-system describe scaledobject inference-api` |
| API times out talking to Qdrant or Redis | [3.3](#33-networkpolicy-cni-desynchronization-and-dropped-zero-trust-flows) | `kubectl -n ai-system get networkpolicy` |
| Control plane 5xx, `/readyz` 503, slow responses | [3.4](#34-control-plane-errors-readiness-and-saturation) | `curl -s localhost:8000/readyz` |
| Suspected drift between chart, cluster and code | [5](#5-offline-drift-analysis) | `k8s-ai chart lint --values prod-values.yaml` |

Conventions: the namespace is `ai-system`, the API Deployment `inference-api`, the
KEDA HPA `keda-hpa-inference-api`, the Redis list `inference-jobs` (chart defaults;
substitute yours). Every control-plane response and log line carries a request ID
(`X-Request-ID`, `request_id`): quote it in every ticket.

## 2. Signals and alert thresholds

Control-plane metrics (from `GET /metrics`):

| Metric | Labels | Meaning |
|---|---|---|
| `http_requests_total` | `method`, `route`, `status` | requests by route template |
| `http_request_duration_seconds` | `method`, `route` | latency histogram; streams measure until the last byte |
| `http_requests_in_flight` | | requests being served |
| `validations_total` | `target` (`chart`, `topology`, `admission`), `outcome` | `pass`/`fail` for chart and topology; `allow`/`warn`/`deny`/`error` for admission |
| `manifest_compilations_total` | `outcome` (`success`, `failure`) | compilations; failures are usually invalid client specs |
| `manifest_compile_duration_seconds` | | compile + zero-trust proof latency (6 ms reference baseline) |
| `manifest_documents_total` | `kind` | documents emitted |
| `manifest_streams_total` | `outcome` (`completed`, `aborted`) | SSE streams |
| `control_plane_build_info` | `version` | build information; its absence means no scrape |

| Alert | Fires when | Severity | Why this threshold |
|---|---|---|---|
| `K8sAiAdmissionDenialStorm` | deny rate > 0.2/s **and** > 50% of admissions, for 10 min | warning | normal CI traffic denies occasionally; a majority of denials means a broken pipeline or an attack |
| `K8sAiAdmissionFlood` | > 5 admission requests/s for 10 min | warning | far above human or CI cadence: scripted submission |
| `K8sAiControlPlane5xx` | > 1% of responses are 5xx for 5 min | critical | every 5xx is an unexpected exception (validation failures are 4xx) |
| `K8sAiControlPlaneAbsent` | no `control_plane_build_info` for 5 min | critical | the control plane is down or not scraped |
| `K8sAiWorkerSaturation` | `http_requests_in_flight` > 40 for 5 min | warning | compile, lint and admission run in a 40-thread pool; beyond that, work queues |
| `K8sAiSlowRequests` | p99 > 2.5 s on non-streaming routes for 10 min | warning | `lint_chart` takes about 80 ms; seconds mean contention |
| `K8sAiSlowCompilation` | p99 compile > 250 ms for 10 min | warning | about 40× the 6 ms baseline |
| `K8sAiStreamAborts` | > 20% of streams aborted for 15 min | warning | clients or proxies cutting SSE streams (timeouts, buffering) |
| `K8sAiQueueSaturated` | HPA desired replicas at `maxReplicaCount` for 15 min | critical | demand exceeds the configured ceiling |
| `K8sAiQueueStalled` | queue > 5 jobs while the HPA stays at its minimum for 10 min | critical | the scaler is decoupled from the queue |
| `K8sAiScalerErrors` | KEDA scaler errors in the last 10 min | warning | KEDA cannot read Redis |

The scaling alerts need kube-state-metrics, redis_exporter (`--check-keys=inference-jobs`)
and KEDA's operator metrics; verify their metric names against your installed versions.

## 3. Incident playbooks

### 3.1 Admission denial storm and rogue manifest flooding

**Symptoms.** `K8sAiAdmissionDenialStorm` or `K8sAiAdmissionFlood`; pipelines fail at
`k8s-ai admit`; `validations_total{target="admission",outcome="deny"}` climbs.

**Triage.**

1. Is it one source? The control-plane access log (JSON, logger
   `cloud_native_k8s_ai.api`) records `request_id`, `route`, `status` and
   `duration_ms` but not the client address: join the `request_id` values of
   `/api/v1/validate/admission` requests with your ingress logs and CI job IDs.
2. What is denied? Reproduce offline on the submitted manifests:
   `k8s-ai admit manifests.yaml --spec stack.yaml`. The JSON report lists every code.
3. Classify by code:

| Codes | Likely cause |
|---|---|
| `image-latest-tag`, `missing-resource-limits`, `best-effort-container`, `selector-template-mismatch` | broken template or values change: a regression, not an attack |
| `missing-default-deny-ingress`, `missing-default-deny-egress`, `missing-dns-egress` | a policy was dropped from the bundle (packaging bug, partial apply) |
| `host-namespace`, `privileged-container`, `capabilities-added`, `run-as-root` | an escalation attempt or a debug workaround left in |
| `workload-selector-overlap`, `qdrant-ingress-not-exclusive`, `cross-namespace-ingress`, `external-egress` | identity spoofing or exfiltration path: **treat as a security incident** |

**Contain.**

- Regression: revert the offending commit; the gate keeps blocking until it is fixed.
- Flooding: rate-limit the source at the ingress in front of the control plane, revoke
  the CI token or service account used; the 1 MiB body limit and YAML screening already
  bound the cost of each request.
- Attack codes: freeze deployments to `ai-system`, preserve the rejected manifests and
  request IDs, inspect who could submit them, rotate their credentials.

**Recover.** For regressions, `k8s-ai admit manifests.yaml --remediate -o fixed.yaml`
applies every automatic fix; review the diff, then fix the manual items (see
[the catalog](security_model.md#5-violation-code-catalog)). Re-run the gate until it
exits `0`.

### 3.2 KEDA scaler decoupling, queue starvation and saturation

**Symptoms.** `K8sAiQueueStalled` (jobs waiting, replicas at minimum),
`K8sAiQueueSaturated` (replicas pinned at maximum), `K8sAiScalerErrors`, growing
`inference-jobs` latency.

**Triage.**

1. Scaler state: `kubectl -n ai-system describe scaledobject inference-api` (`Ready`,
   `Active`, last error) and `kubectl -n ai-system get hpa keda-hpa-inference-api`.
2. Queue: `kubectl -n ai-system exec deploy/redis -- redis-cli LLEN inference-jobs`.
3. Can KEDA reach Redis? The zero-trust policy `redis-allow-ingress` admits only the API
   pods and pods labelled `networkPolicy.kedaOperator.podLabels` in namespace
   `networkPolicy.kedaOperator.namespace`. Compare with the real operator:
   `kubectl -n keda get pods --show-labels`. A mismatch silently blocks polling: this is
   the most common cause of a **decoupled** scaler.
4. Timing: `cooldownPeriod` shorter than `pollingInterval` thrashes (the chart and the
   `keda-cooldown-below-polling` guardrail refuse it); a very low `pollingInterval`
   (`keda-polling-too-aggressive`) flaps.

**Act.**

- Decoupled: fix `networkPolicy.kedaOperator` in the values, validate offline with
  `k8s-ai chart lint --values prod-values.yaml`, then upgrade the release.
- Starvation (queue below `activationListLength`, or `idleReplicaCount` too low for the
  arrival rate): lower `activationListLength` or raise `minReplicas`.
- Saturation: raise `maxReplicas` only after checking the quota:
  `k8s-ai admit manifests.yaml --spec stack.yaml` reports `keda-exceeds-quota` with the
  largest `maxReplicaCount` that fits; otherwise raise the ResourceQuota first.
- Bursty traffic: lower `listLength` (more replicas per queued job) or the polling
  interval, never below the `keda-polling-too-aggressive` floor of 5 s.

### 3.3 NetworkPolicy CNI desynchronization and dropped zero-trust flows

**Symptoms.** API errors connecting to Qdrant (6333/6334) or Redis (6379), DNS
failures, or the opposite: flows that should be blocked succeed.

**Triage.**

1. Policies present: `kubectl -n ai-system get networkpolicy` must list
   `default-deny-all`, `allow-dns-egress`, `qdrant-allow-from-app`,
   `inference-api-allow-ingress`, `inference-api-allow-egress`, `redis-allow-ingress`.
2. The CNI enforces NetworkPolicy at all (Calico, Cilium and others do; some
   managed defaults do not). Without enforcement every policy is a no-op.
3. Namespace labels: peers select namespaces by `kubernetes.io/metadata.name`; check
   `kubectl get ns ai-system keda ingress-nginx --show-labels`.
4. Pod label drift: a pod whose labels no longer match its selector silently loses its
   grants (`selector-template-mismatch`); a pod copying another's labels gains them
   (`workload-selector-overlap`). Run the live state through admission (section 5).
5. CNI telemetry: dropped-by-policy counters and flow logs (for example Cilium Hubble or
   Calico flow logs) for the pod pair.

**Act.** Re-apply the compiled bundle rather than hand-editing policies; validate the
intended state first with `POST /api/v1/validate/topology` (or
`k8s-ai admit manifests.yaml --spec stack.yaml`). If the CNI lost state, restart its
agents on the affected nodes per the CNI's documentation, then verify flows from the
API pod.

### 3.4 Control plane errors, readiness and saturation

**`K8sAiControlPlane5xx`.** Every 5xx is an `internal-error` problem whose details are
only in the JSON log: search for `"message": "unhandled error"` with the `request_id`
from the response. 4xx responses are client errors and never page.

**`/readyz` returns 503.** The body names the failed check:

| Check | Meaning | Action |
|---|---|---|
| `chart` | the reference chart is missing or malformed | fix `K8SAI_API_CHART_DIR` or the chart files |
| `schemas` | chart defaults violate the schema or contracts | `k8s-ai chart lint` shows the problems |
| `generator` | the reference stack does not compile zero trust | a code regression: roll back the release |
| `guardrails` | the reference bundle is not admitted | a guardrail regression: roll back |
| `chartLint` | chart and generator disagree | `k8s-ai chart lint`, fix the drift |
| `lifespan` | `not started` or `draining` | transient during rollout; persistent means a crash loop |

**`K8sAiWorkerSaturation`, `K8sAiSlowRequests`, `K8sAiSlowCompilation`.** Look for
expensive callers (`/api/v1/validate/chart` lints cost about 80 ms each), scale the
control plane horizontally (it is stateless), and check CPU throttling.

**`K8sAiStreamAborts`.** Clients or proxies cut Server-Sent Events: confirm the proxy
honours `X-Accel-Buffering: no` and its read timeout exceeds a stream (milliseconds per
document). Aborts are safe: the stream is closed and counted, nothing is left half-done.

## 4. Recovery, break-glass and manual overrides

**There is no waiver mechanism, by design.** The guardrails have no annotation, flag or
allow list that silences a `DENY`; a gate that can be switched off from the manifest it
judges protects nothing. What operators can legitimately change:

| Lever | Effect | Where |
|---|---|---|
| `WARN` codes | never block admission (`missing-dns-egress`, `qdrant-unreachable-from-api`, `keda-polling-too-aggressive`, `keda-no-scaling-range`, `keda-target-missing`) | none needed |
| Stack trust | `--spec stack.yaml` (or the control plane's reference stack) trusts exactly the stack's ingress and KEDA namespaces and its selectors | `k8s-ai admit … --spec` |
| Network allow lists | `NetworkCritic(allowed_egress_cidrs=…, trusted_namespaces=…)` for sanctioned external endpoints | Python API, reviewed code change |
| Automatic remediation | `--remediate` / `?remediate=true` applies safe fixes; it only ever removes access | CLI, API |
| Autoscaling | pause KEDA with the `autoscaling.keda.sh/paused-replicas` annotation, or render the chart with `autoscaling.enabled=false` | cluster, values |

**Break-glass procedure** (production outage, the gate itself blocks the fix):

1. The incident commander approves in writing; record who, why and the expiry (at most
   24 hours).
2. A cluster administrator applies the minimal change out of band (`kubectl apply`),
   never touching `default-deny-all` or `allow-dns-egress`.
3. Immediately run the live state through admission (section 5) and attach the report
   to the incident.
4. Before the expiry, land the change through the normal pipeline (gate green), then
   re-apply the compiled bundle so the cluster matches the code again.

**Rollback** is a Helm rollback (`helm rollback ai <revision> -n ai-system`) or a
re-apply of an earlier compiled bundle. Roll back only to a revision that passed the
release gates of section 5: those are the revisions whose chart was proven equal to the
zero-trust core bundle and whose manifests were admitted.

## 5. Offline drift analysis

Three kinds of drift, three tools, no cluster access needed except to export state:

| Question | Command | A finding means |
|---|---|---|
| Does the chart still render exactly what the generator emits? | `k8s-ai chart lint --values prod-values.yaml` | template or values drift: the chart would deploy something the zero-trust proof never covered |
| Is the live cluster still admissible? | `kubectl -n ai-system get deploy,sts,svc,netpol,pvc,scaledobject -o yaml \| k8s-ai admit - --spec stack.yaml` | someone changed the cluster outside the pipeline (or a controller mutated objects) |
| Do the guardrails still catch what they caught before? | `k8s-ai eval --epsilon 0.5 --min codes.f1=1 --min robustness=1` | a guardrail regression or a new blind spot; the failure list names the perturbation |

`kubectl get -o yaml` prints a `kind: List`; admission expands it into its items.
Live objects carry `status` and `managedFields`; the guardrails ignore them, but the
typed topology solver does not accept them, so use admission (not
`/api/v1/validate/topology`) for live state.

Reading the results together:

- **lint clean, eval clean, live state denied:** out-of-band cluster change. Re-apply
  the compiled bundle, then find who changed it.
- **lint findings:** fix the chart or values before the next release; `chart render`
  shows exactly what would deploy (`k8s-ai chart render --values prod-values.yaml -o rendered.yaml`).
- **eval below threshold:** do not release; the report's failures list the operator,
  the missed and the spurious codes. A missed code is a detection regression, a
  spurious one a false positive, a low `remediation.convergence_rate` a critic-loop bug.
- **all clean:** the chart, the code and the cluster agree, and the guardrails catch
  every modelled perturbation. The modelled set is not exhaustive: see the gaps in the
  [security model](security_model.md#9-residual-risks-and-non-goals).

Gate every release on all three in CI; they are hermetic and finish in seconds.

## 6. After every incident

- Attach request IDs, the admission reports and the alert timeline to the ticket.
- If the incident revealed a manifest pattern the guardrails missed, add a perturbation
  operator to `cloud_native_k8s_ai.evals` (exact ground truth) and, if needed, a new
  catalog code; both are covered by the documentation tests.
- If an alert fired late or not at all, adjust `deploy/monitoring/alerts.yaml` and the
  table in section 2 together.
- Expire every break-glass change: the cluster must match an admitted bundle again.
