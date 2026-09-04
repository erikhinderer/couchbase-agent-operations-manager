{{/*
Base name of the chart, respecting nameOverride.
*/}}
{{- define "aom.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Full release name, respecting fullnameOverride, avoiding double-printing
the chart name when the release name already contains it.
*/}}
{{- define "aom.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "aom.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aom.labels" -}}
helm.sh/chart: {{ include "aom.chart" . }}
{{ include "aom.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "aom.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aom.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Call with (merge (dict "component" "<name>") .) */}}
{{- define "aom.componentLabels" -}}
{{ include "aom.labels" . }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "aom.componentSelectorLabels" -}}
{{ include "aom.selectorLabels" . }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Call with (dict "root" $ "repository" <repo> "tag" <tag>).
Prefixes global.imageRegistry when set.
*/}}
{{- define "aom.image" -}}
{{- $registry := .root.Values.global.imageRegistry -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry .repository .tag -}}
{{- else -}}
{{- printf "%s:%s" .repository .tag -}}
{{- end -}}
{{- end -}}

{{- define "aom.authSecretName" -}}
{{- printf "%s-app-secrets" (include "aom.fullname" .) -}}
{{- end -}}

{{- define "aom.tlsSecretName" -}}
{{- if eq .Values.tls.mode "existingSecret" -}}
{{- .Values.tls.existingSecret -}}
{{- else -}}
{{- printf "%s-tls" (include "aom.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "aom.couchbaseServiceName" -}}
{{- printf "%s-couchbase" (include "aom.fullname" .) -}}
{{- end -}}

{{- define "aom.sampleMcpServersServiceName" -}}
{{- printf "%s-sample-mcp-servers" (include "aom.fullname" .) -}}
{{- end -}}

{{- define "aom.operationsManagerServiceName" -}}
{{- printf "%s-operations-manager" (include "aom.fullname" .) -}}
{{- end -}}

{{- define "aom.uiServiceName" -}}
{{- printf "%s-ui" (include "aom.fullname" .) -}}
{{- end -}}
