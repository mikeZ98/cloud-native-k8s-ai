{{/*
Shared helpers. Object names come from values rather than the release name, so the chart
renders exactly the objects of the typed core generator (core.compile_ai_stack). Selectors
are the immutable (name, component) pair and never change on upgrade.
*/}}

{{/* helm.sh/chart label value: <name>-<version>, at most 63 characters. */}}
{{- define "ai.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{/*
Labels Helm uses to track the release. Object metadata only: putting the chart version on
pod templates would restart every pod on each chart bump.
*/}}
{{- define "ai.releaseLabels" -}}
helm.sh/chart: {{ include "ai.chart" . }}
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}

{{/* Selector labels. Input: dict "name" "component". */}}
{{- define "ai.selectorLabels" -}}
app.kubernetes.io/component: {{ .component }}
app.kubernetes.io/name: {{ .name }}
{{- end }}

{{/*
Pod labels: part-of, environment and user extras, then the selector (which always wins).
Input: dict "root" "name" "component" "extra".
*/}}
{{- define "ai.podLabels" -}}
{{- $labels := dict "app.kubernetes.io/part-of" "cloud-native-k8s-ai" "environment" .root.Values.environment -}}
{{- range $key, $value := .extra }}{{ $_ := set $labels $key $value }}{{ end -}}
{{- $_ := set $labels "app.kubernetes.io/name" .name -}}
{{- $_ := set $labels "app.kubernetes.io/component" .component -}}
{{- toYaml $labels -}}
{{- end }}

{{/* Object labels: pod labels plus release labels. Input: as ai.podLabels. */}}
{{- define "ai.labels" -}}
{{ include "ai.podLabels" . }}
{{ include "ai.releaseLabels" .root }}
{{- end }}

{{/* Pinned image reference: repository:tag[@digest]. Input: an image value. */}}
{{- define "ai.image" -}}
{{- printf "%s:%s" .repository .tag -}}
{{- if hasKey . "digest" }}@{{ .digest }}{{ end -}}
{{- end }}

{{/* Cluster-internal Service FQDN. Input: dict "name" "namespace". */}}
{{- define "ai.serviceHost" -}}
{{- printf "%s.%s.svc.cluster.local" .name .namespace -}}
{{- end }}

{{/* Bytes of a Ki/Mi/Gi quantity (the values schema admits no other unit). */}}
{{- define "ai.bytes" -}}
{{- if hasSuffix "Gi" . -}}
{{- mul (trimSuffix "Gi" . | int64) 1073741824 -}}
{{- else if hasSuffix "Mi" . -}}
{{- mul (trimSuffix "Mi" . | int64) 1048576 -}}
{{- else -}}
{{- mul (trimSuffix "Ki" . | int64) 1024 -}}
{{- end -}}
{{- end }}

{{/* HTTP probe. Input: dict "path" "port" "period" "failures". */}}
{{- define "ai.httpProbe" -}}
httpGet:
  path: {{ .path }}
  port: {{ .port }}
  scheme: HTTP
initialDelaySeconds: 0
periodSeconds: {{ .period }}
timeoutSeconds: 1
successThreshold: 1
failureThreshold: {{ .failures }}
{{- end }}

{{/* Restricted pod security baseline shared by every workload. */}}
{{- define "ai.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 10001
runAsGroup: 10001
fsGroup: 10001
fsGroupChangePolicy: OnRootMismatch
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{- define "ai.containerSecurityContext" -}}
runAsNonRoot: true
runAsUser: 10001
runAsGroup: 10001
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false
privileged: false
capabilities:
  drop:
    - ALL
  add: []
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/* Writable scratch space (TMPDIR); the root filesystem is read-only. */}}
{{- define "ai.scratchVolume" -}}
name: scratch
emptyDir:
  medium: ""
  sizeLimit: 1Gi
{{- end }}

{{/*
Cross-field rules JSON Schema cannot express. Fails the render (helm install/template) with
the same rules the Pydantic contracts and the autoscaling resolver enforce.
*/}}
{{- define "ai.validate" -}}
{{- $v := .Values -}}
{{- if or (eq $v.api.name $v.qdrant.name) (eq $v.api.name $v.redis.name) (eq $v.qdrant.name $v.redis.name) -}}
{{- fail "api.name, qdrant.name and redis.name must be distinct" -}}
{{- end -}}
{{- if eq (int $v.qdrant.ports.rest) (int $v.qdrant.ports.grpc) -}}
{{- fail "qdrant.ports.rest and qdrant.ports.grpc must differ" -}}
{{- end -}}
{{- with $v.autoscaling -}}
{{- if .enabled -}}
{{- if gt (int .minReplicas) (int .maxReplicas) -}}
{{- fail "autoscaling.minReplicas must not exceed autoscaling.maxReplicas" -}}
{{- end -}}
{{- if and (hasKey . "idleReplicas") (ge (int (get . "idleReplicas")) (int .minReplicas)) -}}
{{- fail "autoscaling.idleReplicas must be lower than autoscaling.minReplicas" -}}
{{- end -}}
{{- if lt (int .cooldownPeriod) (int .pollingInterval) -}}
{{- fail "autoscaling.cooldownPeriod must be at least autoscaling.pollingInterval" -}}
{{- end -}}
{{- if or (lt (int $v.api.replicas) (int .minReplicas)) (gt (int $v.api.replicas) (int .maxReplicas)) -}}
{{- fail "api.replicas must lie within [autoscaling.minReplicas, autoscaling.maxReplicas]" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end }}
