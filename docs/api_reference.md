# API and CLI reference

The control plane is a FastAPI application (`k8s-ai serve`, or
`uvicorn --factory cloud_native_k8s_ai.api:create_app`); the CLI is `k8s-ai`. Both expose
the same engine: compile, stream, validate, admit, evaluate.

- [1. Conventions](#1-conventions)
- [2. Endpoints](#2-endpoints)
- [3. Problem details (RFC 7807) catalog](#3-problem-details-rfc-7807-catalog)
- [4. Server-Sent Events protocol](#4-server-sent-events-protocol)
- [5. Schemas](#5-schemas)
- [6. CLI reference](#6-cli-reference)

Sections 2, 5 and 6 are generated from the live OpenAPI document and the CLI parser by
`python -m cloud_native_k8s_ai.tools.reference`, which also writes the complete
[`openapi.json`](openapi.json) snapshot; `tests/test_docs.py` fails if either drifts from
the code. Interactive documentation is served at `/docs`, the document at `/openapi.json`.

## 1. Conventions

| Topic | Rule |
|---|---|
| Versioning | Application endpoints live under `/api/v1`; probes and `/metrics` at the root. |
| Field names | camelCase on the wire (`containerPort`, `maxReplicaCount`), as in Kubernetes. |
| Strict JSON | Bodies are parsed with `model_validate_json`: no type coercion (`"2"` is not an integer), unknown fields are rejected, JSON arrays become tuples. |
| YAML bodies | `/validate/topology` and `/validate/admission` also accept a raw manifest body with `Content-Type: application/yaml`, `application/x-yaml` or `text/yaml`; it is screened for anchors, aliases and nesting deeper than 64 levels before parsing. |
| Body limit | 1 MiB by default (`K8SAI_API_MAX_BODY_BYTES`, 1 KiB to 64 MiB), enforced on `Content-Length` and while streaming: `413`. |
| Compile output | `?format=yaml` or `?format=json` wins; otherwise the first YAML (`application/yaml`, `application/x-yaml`, `text/yaml`) or JSON (`application/json`, `*/*`) entry of `Accept`; default JSON. |
| Correlation | Every response carries `X-Request-ID`: the caller's value when it matches `[A-Za-z0-9._:-]{1,128}`, otherwise a fresh 32-hex ID. Problems and logs repeat it. |
| Errors | Always `application/problem+json` (section 3). |
| Settings | `K8SAI_API_CHART_DIR` (reference chart), `K8SAI_API_LOG_LEVEL` (`DEBUG`, `INFO`, `WARNING`, `ERROR`), `K8SAI_API_MAX_BODY_BYTES`. |

Readiness (`GET /readyz`) reports one entry per self-check: `chart`, `schemas`,
`generator`, `guardrails`, `chartLint`; a failed check holds `ErrorType: message`,
later checks `skipped`. Before startup it reports `lifespan: not started`, during
shutdown `lifespan: draining`; any of these returns `503`.

Examples:

```bash
k8s-ai spec -o stack.yaml
python -c 'import json,sys,yaml; print(json.dumps(yaml.safe_load(sys.stdin)))' < stack.yaml > stack.json
curl -s localhost:8000/api/v1/compile -H 'content-type: application/json' --data-binary @stack.json
curl -s 'localhost:8000/api/v1/compile?format=yaml' -H 'content-type: application/json' --data-binary @stack.json
curl -s localhost:8000/api/v1/validate/chart -H 'content-type: application/json' \
  -d '{"values": {"redis": {"maxmemory": "512Mi"}}, "release": {"name": "ai", "namespace": "ai-system"}}'
curl -s localhost:8000/api/v1/validate/topology -H 'content-type: application/yaml' --data-binary @manifests.yaml
curl -s 'localhost:8000/api/v1/validate/admission?remediate=true' -H 'content-type: application/yaml' \
  --data-binary @manifests.yaml
curl -sN 'localhost:8000/api/v1/stream/compile?namespace=team-a'
```

## 2. Endpoints

<!-- BEGIN GENERATED: endpoints -->
| Method | Path | Summary |
|---|---|---|
| `POST` | `/api/v1/compile` | Compile an AI stack to Kubernetes manifests |
| `GET` | `/api/v1/stream/compile` | Stream the reference stack (chart defaults) document by document |
| `POST` | `/api/v1/stream/compile` | Stream a submitted stack document by document |
| `POST` | `/api/v1/validate/chart` | Lint a values overlay against the chart (schema, contracts, parity, zero trust) |
| `POST` | `/api/v1/validate/topology` | Run the zero-trust topology solver on submitted manifests |
| `POST` | `/api/v1/validate/admission` | Run the admission guardrails (workload security, zero trust, autoscaling) |
| `GET` | `/healthz` | Liveness: the process serves requests |
| `GET` | `/readyz` | Readiness: chart, schemas and generator passed their self-checks |
| `GET` | `/metrics` | Prometheus metrics (text exposition format) |

### `POST /api/v1/compile`

Compile an AI stack to Kubernetes manifests

| Parameter | In | Type | Required | Default | Constraints |
|---|---|---|---|---|---|
| `format` | query | `"json"` \| `"yaml"` or null |  |  |  |

Request body:
- `application/json`: [InfraSpec](#infraspec)

| Status | Description | Content |
|---|---|---|
| 200 | The bundle as JSON, or multi-document YAML (?format=yaml / Accept) | `application/json` [CompileResponse](#compileresponse); `application/yaml` string |
| 400 | Manifests cannot be rendered | `application/problem+json` |
| 413 | Request body too large | `application/problem+json` |
| 422 | Invalid spec, resource constraint or zero-trust violation | `application/problem+json` |
| 503 | Control plane unavailable | `application/problem+json` |

### `GET /api/v1/stream/compile`

Stream the reference stack (chart defaults) document by document

| Parameter | In | Type | Required | Default | Constraints |
|---|---|---|---|---|---|
| `environment` | query | `"dev"` \| `"staging"` \| `"prod"` or null |  |  |  |
| `namespace` | query | string or null |  |  |  |

| Status | Description | Content |
|---|---|---|
| 200 | SSE: one `manifest` event per document, then `complete` | `application/json`; `text/event-stream` string |
| 422 | Invalid spec, resource constraint or zero-trust violation | `application/problem+json` |
| 503 | Control plane unavailable | `application/problem+json` |

### `POST /api/v1/stream/compile`

Stream a submitted stack document by document

Request body:
- `application/json`: [InfraSpec](#infraspec)

| Status | Description | Content |
|---|---|---|
| 200 | SSE: one `manifest` event per document, then `complete` | `application/json`; `text/event-stream` string |
| 400 | Manifests cannot be rendered | `application/problem+json` |
| 413 | Request body too large | `application/problem+json` |
| 422 | Invalid spec, resource constraint or zero-trust violation | `application/problem+json` |
| 503 | Control plane unavailable | `application/problem+json` |

### `POST /api/v1/validate/chart`

Lint a values overlay against the chart (schema, contracts, parity, zero trust)

Request body:
- `application/json`: [ChartValidationRequest](#chartvalidationrequest)

| Status | Description | Content |
|---|---|---|
| 200 | All checks passed | `application/json` [ChartValidationResponse](#chartvalidationresponse) |
| 400 | Manifests cannot be parsed | `application/problem+json` |
| 413 | Request body too large | `application/problem+json` |
| 422 | Schema, contract, render, parity or zero-trust findings | `application/problem+json` |
| 503 | Control plane unavailable | `application/problem+json` |

### `POST /api/v1/validate/topology`

Run the zero-trust topology solver on submitted manifests

Request body:
- `application/json`: [TopologyRequest](#topologyrequest)
- `application/yaml`: string

| Status | Description | Content |
|---|---|---|
| 200 | All checks passed | `application/json` [TopologyResponse](#topologyresponse) |
| 400 | Manifests cannot be parsed | `application/problem+json` |
| 413 | Request body too large | `application/problem+json` |
| 422 | Zero-trust violations (default deny, isolation, unauthorized flows) | `application/problem+json` |
| 503 | Control plane unavailable | `application/problem+json` |

### `POST /api/v1/validate/admission`

Run the admission guardrails (workload security, zero trust, autoscaling)

| Parameter | In | Type | Required | Default | Constraints |
|---|---|---|---|---|---|
| `remediate` | query | boolean |  | `false` |  |

Request body:
- `application/json`: [AdmissionRequest](#admissionrequest)
- `application/yaml`: string

| Status | Description | Content |
|---|---|---|
| 200 | All checks passed | `application/json` [AdmissionResponse](#admissionresponse) |
| 400 | Manifests cannot be parsed | `application/problem+json` |
| 413 | Request body too large | `application/problem+json` |
| 422 | Admission denied: violations with remediation advice | `application/problem+json` |
| 503 | Control plane unavailable | `application/problem+json` |

### `GET /healthz`

Liveness: the process serves requests

| Status | Description | Content |
|---|---|---|
| 200 | Successful Response | `application/json` [HealthResponse](#healthresponse) |

### `GET /readyz`

Readiness: chart, schemas and generator passed their self-checks

| Status | Description | Content |
|---|---|---|
| 200 | Successful Response | `application/json` [ReadinessResponse](#readinessresponse) |
| 503 | Not ready (starting, failed self-check or draining) |  |

### `GET /metrics`

Prometheus metrics (text exposition format)

| Status | Description | Content |
|---|---|---|
| 200 | Successful Response | `application/json`; `text/plain; version=1.0.0; charset=utf-8` string |
<!-- END GENERATED: endpoints -->

## 3. Problem details (RFC 7807) catalog

Every error body has `type` (`urn:cloud-native-k8s-ai:problem:<slug>`), `title`,
`status`, `detail`, `instance` (the request path) and `requestId`, plus the extensions
listed here.

| Slug | Status | Raised when | Extensions |
|---|---|---|---|
| `invalid-request` | 422 | the body, a query parameter or JSON itself fails validation | `errors`: `[{loc, msg, type}]` |
| `admission-denied` | 422 | an admission guardrail returned DENY | `decision`, `violations` (full PolicyViolation objects), `remediation` when `?remediate=true` |
| `chart-lint-failed` | 422 | `/validate/chart` found schema, contract, parity or zero-trust problems | `findings`: `[string]` |
| `invalid-chart-values` | 422 | chart values break `values.schema.json` or the typed contracts | `problems`: `[string]` |
| `topology-conflict` | 422 | the zero-trust solver found violations, or autoscaling binding failed | `violations`: `[{code, message}]` |
| `resource-constraint` | 422 | replica bounds, timing windows or budgets are inconsistent | none |
| `manifest-render` | 400 | manifests or YAML cannot be parsed or rendered (including YAML bombs) | none |
| `guardrail-error` | 400 | the guardrails cannot evaluate the input | none |
| `core-error` | 400 | any other engine failure | none |
| `unavailable` | 503 | the control plane is not started, draining, or lacks its reference chart | none |
| `http-{status}` | 400, 404, 405, 413 | routing and transport errors (unknown path, wrong method with `Allow`, oversized body, non-UTF-8 YAML) | none |
| `internal-error` | 500 | an unexpected exception; details only in the log under the same request ID | none |

## 4. Server-Sent Events protocol

`GET /api/v1/stream/compile` streams the reference stack (optional `environment` and
`namespace` overrides); `POST` streams a submitted [InfraSpec](#infraspec).

1. The stack is compiled and proven zero trust **before** the first byte. Every failure is
   an ordinary problem response; a `200` stream never carries errors.
2. Response headers: `Content-Type: text/event-stream; charset=utf-8`,
   `Cache-Control: no-cache`, `X-Accel-Buffering: no` (disables proxy buffering),
   `X-Request-ID`.
3. One `manifest` event per document, in apply order (NetworkPolicies first, the
   ScaledObject last), with ids `0 … total-1`, then one `complete` event with id
   `total`. No `retry:` field, no heartbeats: the stream is finite and short.
4. Each `data:` line is a single-line JSON object:

| Event | Field | Meaning |
|---|---|---|
| `manifest` | `index` | position in apply order, equal to the event `id` |
| `manifest` | `total` | number of documents in the bundle |
| `manifest` | `kind`, `name`, `namespace` | identity of the document |
| `manifest` | `yaml` | the document as standalone YAML (starts with `---`) |
| `complete` | `count` | documents sent |
| `complete` | `kinds` | documents per kind, e.g. `{"NetworkPolicy": 6, "Service": 4, …}` |

```text
id: 0
event: manifest
data: {"index":0,"total":15,"kind":"NetworkPolicy","name":"allow-dns-egress","namespace":"ai-system","yaml":"---\napiVersion: networking.k8s.io/v1\n..."}

id: 15
event: complete
data: {"count":15,"kinds":{"NetworkPolicy":6,"PersistentVolumeClaim":1,"Service":4,"Deployment":2,"StatefulSet":1,"ScaledObject":1}}
```

5. A client that disconnects cancels the stream at the next document; the generator is
   closed at once and counted as `manifest_streams_total{outcome="aborted"}`
   (`completed` otherwise). Reconnecting simply starts a new, identical stream.

## 5. Schemas

Request and response bodies, generated from the Pydantic contracts. Types link to their
schema; `map of X` is a JSON object with string keys. The full JSON Schemas, including
every pattern and nested definition, are in [`openapi.json`](openapi.json).

<!-- BEGIN GENERATED: schemas -->
### AIStackSpec

Everything the generator needs beyond ``InfraSettings``.

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `app` | [FastAPIAppSpec](#fastapiappspec) | yes |  |  |
| `qdrant` | [QdrantSpec](#qdrantspec) | yes |  |  |
| `redis` | [RedisSpec](#redisspec) | yes |  |  |
| `autoscaling` | [AutoscalingPolicy](#autoscalingpolicy) |  |  |  |
| `budget` | [ResourceBudget](#resourcebudget) or null |  | `null` |  |
| `ingressNamespace` | string |  | `"ingress-nginx"` | length ≥ 1, length ≤ 63, pattern `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` |
| `kedaNamespace` | string |  | `"keda"` | length ≥ 1, length ≤ 63, pattern `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` |
| `kedaOperatorLabels` | map of string |  |  |  |

### AdmissionReport

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `decision` | [GuardrailDecision](#guardraildecision) | yes |  |  |
| `objects` | array of [ObjectDecision](#objectdecision) | yes |  |  |
| `violations` | array of [PolicyViolation](#policyviolation) | yes |  |  |

### AdmissionRequest

Multi-document manifest YAML to run through every admission guardrail.

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `manifests` | string | yes |  | length ≥ 1 |

### AdmissionResponse

ALLOW or WARN; a DENY is a 422 ``admission-denied`` problem instead.

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `report` | [AdmissionReport](#admissionreport) | yes |  |  |
| `remediation` | [RemediationSummary](#remediationsummary) or null |  | `null` |  |

### AutoscalingPolicy

Scale a worker Deployment on the length of a Redis list (job queue).

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `listName` | string |  | `"inference-jobs"` | length ≥ 1, length ≤ 512, pattern `^\S+$` |
| `listLength` | integer |  | `5` | ≥ 1 |
| `activationListLength` | integer |  | `0` | ≥ 0 |
| `minReplicas` | integer |  | `1` | ≥ 0, ≤ 1000 |
| `maxReplicas` | integer |  | `10` | ≥ 1, ≤ 1000 |
| `idleReplicas` | integer or null |  | `null` |  |
| `cooldownPeriod` | integer |  | `300` | ≥ 0, ≤ 86400 |
| `pollingInterval` | integer |  | `30` | ≥ 1, ≤ 3600 |
| `databaseIndex` | integer |  | `0` | ≥ 0, ≤ 15 |
| `enableTls` | boolean |  | `false` |  |
| `authenticationRef` | string or null |  | `null` |  |

### ChartValidationRequest

A values overlay, merged over the chart defaults like ``helm install -f``.

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `values` | object |  |  |  |
| `release` | [ReleaseRef](#releaseref) |  |  |  |

### ChartValidationResponse

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `status` | `"pass"` |  | `"pass"` |  |
| `release` | [ReleaseRef](#releaseref) | yes |  |  |
| `findings` | array of string |  | `[]` |  |

### CompileResponse

A compiled bundle in apply order (NetworkPolicies first, ScaledObject last).

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `environment` | `"dev"` \| `"staging"` \| `"prod"` | yes |  |  |
| `namespace` | string | yes |  | length ≥ 1, length ≤ 63, pattern `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` |
| `count` | integer | yes |  |  |
| `kinds` | map of integer | yes |  |  |
| `documents` | array of object | yes |  |  |

### EnvVar

Plain value or secret reference, never both; secrets never appear inline.

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `name` | string | yes |  | length ≤ 253, pattern `^[A-Za-z_][A-Za-z0-9_]*$` |
| `value` | string or null |  | `null` |  |
| `valueFrom` | [EnvVarSource](#envvarsource) or null |  | `null` |  |

### EnvVarSource

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `secretKeyRef` | [SecretKeySelector](#secretkeyselector) | yes |  |  |

### FastAPIAppSpec

High-level contract for the FastAPI inference microservice.

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `name` | string |  | `"inference-api"` | length ≥ 1, length ≤ 63, pattern `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` |
| `image` | string | yes |  |  |
| `replicas` | integer |  | `2` | ≥ 0, ≤ 1000 |
| `containerPort` | integer |  | `8000` | ≥ 1, ≤ 65535 |
| `servicePort` | integer |  | `80` | ≥ 1, ≤ 65535 |
| `resources` | [ResourceRequirements](#resourcerequirements) | yes |  |  |
| `livenessPath` | string |  | `"/healthz"` | length ≥ 1, length ≤ 4096, pattern `^/` |
| `readinessPath` | string |  | `"/readyz"` | length ≥ 1, length ≤ 4096, pattern `^/` |
| `env` | array of [EnvVar](#envvar) |  | `[]` |  |
| `labels` | map of string |  |  |  |

### GuardrailDecision

Type: `"ALLOW"` \| `"WARN"` \| `"DENY"`

### HealthResponse

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `status` | `"ok"` |  | `"ok"` |  |
| `version` | string | yes |  |  |
| `uptimeSeconds` | number | yes |  |  |

### InfraSpec

What to compile: target environment and namespace plus the AI stack.

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `environment` | `"dev"` \| `"staging"` \| `"prod"` |  | `"dev"` |  |
| `namespace` | string |  | `"ai-system"` | length ≥ 1, length ≤ 63, pattern `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` |
| `stack` | [AIStackSpec](#aistackspec) | yes |  |  |

### JsonPatchOp

One RFC 6902 operation (``add``, ``replace`` or ``remove``) on a JSON pointer.

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `op` | `"add"` \| `"replace"` \| `"remove"` | yes |  |  |
| `path` | string | yes |  |  |
| `value` | any |  | `null` |  |

### ObjectDecision

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `target` | [ObjectRef](#objectref) | yes |  |  |
| `decision` | [GuardrailDecision](#guardraildecision) | yes |  |  |

### ObjectRef

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `kind` | string | yes |  |  |
| `namespace` | string or null |  | `null` |  |
| `name` | string | yes |  |  |

### PolicyViolation

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `code` | string | yes |  |  |
| `policy` | string | yes |  |  |
| `decision` | `"WARN"` \| `"DENY"` | yes |  |  |
| `target` | [ObjectRef](#objectref) | yes |  |  |
| `path` | string |  | `""` |  |
| `message` | string | yes |  |  |
| `remediation` | [RemediationAdvice](#remediationadvice) | yes |  |  |

### QdrantSpec

Qdrant StatefulSet contract: REST/gRPC ports and separate storage/snapshot PVCs.

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `name` | string |  | `"qdrant"` | length ≥ 1, length ≤ 63, pattern `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` |
| `image` | string | yes |  |  |
| `replicas` | integer |  | `1` | ≥ 1, ≤ 100 |
| `restPort` | integer |  | `6333` | ≥ 1, ≤ 65535 |
| `grpcPort` | integer |  | `6334` | ≥ 1, ≤ 65535 |
| `resources` | [ResourceRequirements](#resourcerequirements) | yes |  |  |
| `storage` | [QdrantVolume](#qdrantvolume) |  |  |  |
| `snapshots` | [QdrantVolume](#qdrantvolume) |  |  |  |
| `labels` | map of string |  |  |  |

### QdrantVolume

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `size` | string | yes |  |  |
| `mountPath` | string | yes |  | length ≥ 1, length ≤ 4096, pattern `^/` |
| `storageClassName` | string or null |  | `null` |  |

### RdbSavePoint

``save <seconds> <changes>``: snapshot after ``seconds`` if ``changes`` keys changed.

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `seconds` | integer | yes |  | ≥ 1, ≤ 86400 |
| `changes` | integer | yes |  | ≥ 1 |

### ReadinessResponse

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `status` | `"ready"` \| `"unavailable"` | yes |  |  |
| `checks` | map of string | yes |  |  |

### RedisPersistence

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `mode` | `"none"` \| `"rdb"` \| `"aof"` \| `"rdb+aof"` |  | `"aof"` |  |
| `appendfsync` | `"always"` \| `"everysec"` \| `"no"` |  | `"everysec"` |  |
| `savePoints` | array of [RdbSavePoint](#rdbsavepoint) |  | (see `openapi.json`) |  |
| `volumeSize` | string or null |  | `"8Gi"` |  |
| `storageClassName` | string or null |  | `null` |  |

### RedisSpec

Redis contract: in-memory ceiling below the container limit, explicit persistence.

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `name` | string |  | `"redis"` | length ≥ 1, length ≤ 63, pattern `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` |
| `image` | string | yes |  |  |
| `port` | integer |  | `6379` | ≥ 1, ≤ 65535 |
| `resources` | [ResourceRequirements](#resourcerequirements) | yes |  |  |
| `maxmemory` | string | yes |  |  |
| `maxmemoryPolicy` | `"noeviction"` \| `"allkeys-lru"` \| `"allkeys-lfu"` \| `"allkeys-random"` \| `"volatile-lru"` \| `"volatile-lfu"` \| `"volatile-random"` \| `"volatile-ttl"` |  | `"noeviction"` |  |
| `persistence` | [RedisPersistence](#redispersistence) |  |  |  |
| `dataMountPath` | string |  | `"/data"` | length ≥ 1, length ≤ 4096, pattern `^/` |
| `labels` | map of string |  |  |  |

### ReleaseRef

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `name` | string |  | `"ai"` | length ≤ 53, pattern `^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$` |
| `namespace` | string |  | `"ai-system"` | length ≥ 1, length ≤ 63, pattern `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` |

### RemediationAdvice

How to fix a violation: a patch on the object, a new object, or manual steps.

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `summary` | string | yes |  |  |
| `action` | `"patch"` \| `"create"` \| `"manual"` | yes |  |  |
| `patch` | array of [JsonPatchOp](#jsonpatchop) |  | `[]` |  |
| `document` | object or null |  | `null` |  |

### RemediationRound

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `round` | integer | yes |  | ≥ 1 |
| `applied` | array of string | yes |  |  |
| `remaining` | integer | yes |  |  |

### RemediationSummary

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `initialDecision` | [GuardrailDecision](#guardraildecision) | yes |  |  |
| `rounds` | array of [RemediationRound](#remediationround) | yes |  |  |
| `converged` | boolean | yes |  |  |
| `manifests` | string | yes |  |  |

### ResourceBudget

Upper bound on what the target may consume when scaled to ``max_replicas``.

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `cpu` | string | yes |  |  |
| `memory` | string | yes |  |  |

### ResourceList

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `cpu` | string | yes |  |  |
| `memory` | string | yes |  |  |

### ResourceRequirements

Requests and limits; both CPU and memory are mandatory and requests must fit limits.

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `requests` | [ResourceList](#resourcelist) | yes |  |  |
| `limits` | [ResourceList](#resourcelist) | yes |  |  |

### SecretKeySelector

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `name` | string | yes |  | length ≥ 1, length ≤ 253, pattern `^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$` |
| `key` | string | yes |  | length ≤ 253, pattern `^[-._A-Za-z0-9]+$` |

### TopologyRequest

Multi-document manifest YAML, checked against the intent of ``spec`` (the reference stack when omitted).

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `manifests` | string | yes |  | length ≥ 1 |
| `spec` | [InfraSpec](#infraspec) or null |  | `null` |  |

### TopologyResponse

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `status` | `"pass"` |  | `"pass"` |  |
| `namespace` | string | yes |  | length ≥ 1, length ≤ 63, pattern `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` |
| `policies` | integer | yes |  |  |
| `workloads` | integer | yes |  |  |
| `reachable` | array of string | yes |  |  |

<!-- END GENERATED: schemas -->

## 6. CLI reference

`k8s-ai [--version] <command> …`. Every input file may be `-` for stdin; results go to
stdout unless `-o` is given. Untrusted YAML is screened like on the API.

| Exit code | Meaning |
|---|---|
| `0` | success: admitted (ALLOW or WARN), lint clean, eval thresholds met |
| `1` | admission DENY, chart lint findings, or an eval `--min` threshold missed |
| `2` | invalid input: unreadable file, invalid spec or values, malformed YAML, unknown metric, usage error |

```bash
k8s-ai spec -o stack.yaml                                  # reference stack (chart defaults)
k8s-ai compile stack.yaml -o manifests.yaml                # zero-trust bundle
k8s-ai admit manifests.yaml --spec stack.yaml              # gate: exit 1 on DENY
k8s-ai admit manifests.yaml --remediate -o fixed.yaml      # critic loop, report on stdout
k8s-ai chart lint --values prod-values.yaml                # chart vs core, zero trust
k8s-ai chart render --namespace ai-system -o rendered.yaml # helm template, offline
k8s-ai eval --epsilon 0.5 --min codes.f1=1 --min robustness=1
k8s-ai serve --host 0.0.0.0 --port 8000
```

<!-- BEGIN GENERATED: cli -->
### `spec`

print the reference stack spec (chart defaults)

| Argument | Default | Choices | Description |
|---|---|---|---|
| `--chart` | `deploy/helm/cloud-native-k8s-ai` |  | chart directory |
| `--namespace` |  |  | override the target namespace |
| `--environment` |  | `dev` \| `staging` \| `prod` | override the environment label |
| `-o, --output` |  |  | write the spec here instead of stdout |

### `compile`

compile a stack spec into manifests

| Argument | Default | Choices | Description |
|---|---|---|---|
| `spec` |  |  | InfraSpec file (YAML or JSON), or - for stdin |
| `--format` | `yaml` | `yaml` \| `json` | multi-document YAML or JSON bundle |
| `-o, --output` |  |  | write the manifests here instead of stdout |

### `admit`

run the admission guardrails on manifests

| Argument | Default | Choices | Description |
|---|---|---|---|
| `manifests` |  |  | multi-document manifest YAML, or - for stdin |
| `--spec` |  |  | trust this stack's namespaces and selectors |
| `--remediate` |  |  | run the critic loop first |
| `-o, --output` |  |  | write remediated manifests here |

### `chart`

lint or render the Helm chart offline


### `chart lint`

lint the chart (schema, contracts, parity, zero trust)

| Argument | Default | Choices | Description |
|---|---|---|---|
| `--chart` | `deploy/helm/cloud-native-k8s-ai` |  | chart directory |
| `--values` |  |  | values overlay file (repeatable) |
| `--release` | `ai` |  | Helm release name |
| `--namespace` | `ai-system` |  | release namespace |

### `chart render`

render the chart like helm template

| Argument | Default | Choices | Description |
|---|---|---|---|
| `--chart` | `deploy/helm/cloud-native-k8s-ai` |  | chart directory |
| `--values` |  |  | values overlay file (repeatable) |
| `--release` | `ai` |  | Helm release name |
| `--namespace` | `ai-system` |  | release namespace |
| `-o, --output` |  |  | write the manifests here |

### `eval`

benchmark the guardrails against seeded perturbations

| Argument | Default | Choices | Description |
|---|---|---|---|
| `--chart` | `deploy/helm/cloud-native-k8s-ai` |  | chart directory |
| `--spec` |  |  | stack spec to evaluate (default: chart reference) |
| `--seed` | `0` |  | perturbation stream seed |
| `--samples` | `200` |  | manifest samples |
| `--spec-samples` | `50` |  | AIStackSpec samples (0 skips the suite) |
| `--epsilon` | `0.3` |  | perturbation budget 0..1 |
| `--benign-ratio` | `0.25` |  | share of unperturbed-intent samples |
| `--no-remediate` |  |  | skip the critic loop |
| `--format` | `text` | `text` \| `json` | summary or full JSON report |
| `--min` |  |  | quality gate (repeatable) |
| `-o, --output` |  |  | write the report here instead of stdout |

### `serve`

run the control plane (uvicorn)

| Argument | Default | Choices | Description |
|---|---|---|---|
| `--chart` | `deploy/helm/cloud-native-k8s-ai` |  | chart directory |
| `--host` | `127.0.0.1` |  | bind address |
| `--port` | `8000` |  | TCP port |
<!-- END GENERATED: cli -->
