{{- define "supermcp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "supermcp.fullname" -}}
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

{{- define "supermcp.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "supermcp.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "supermcp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "supermcp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "supermcp.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "supermcp.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "supermcp.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{/* Environment shared by the server and the migrate job. */}}
{{- define "supermcp.env" -}}
- name: SUPERMCP_PUBLIC_URL
  value: {{ required "publicUrl is required" .Values.publicUrl | quote }}
- name: SUPERMCP_LOG_LEVEL
  value: {{ .Values.config.logLevel | quote }}
- name: SUPERMCP_LOG_FORMAT
  value: {{ .Values.config.logFormat | quote }}
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ required "database.existingSecret is required" .Values.database.existingSecret }}
      key: {{ .Values.database.urlKey }}
- name: SUPERMCP_MAINT_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.database.existingSecret }}
      key: {{ .Values.database.maintUrlKey }}
      optional: true
{{- if .Values.redis.existingSecret }}
- name: REDIS_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.redis.existingSecret }}
      key: {{ .Values.redis.urlKey }}
{{- end }}
{{- with .Values.tracing.endpoint }}
- name: SUPERMCP_OTLP_ENDPOINT
  value: {{ . | quote }}
- name: SUPERMCP_TRACE_SAMPLE
  value: {{ $.Values.tracing.sample | quote }}
{{- end }}
{{- /*
  The pod name names this replica: its audit spool directory on the shared
  volume, and the gap markers it writes. It is unique among live pods,
  which is what keeps two replicas from writing or replaying one file.
*/}}
- name: SUPERMCP_INSTANCE_ID
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
- name: SUPERMCP_AUDIT_ON_UNAVAILABLE
  value: {{ .Values.audit.onUnavailable | quote }}
{{- if .Values.audit.spool.enabled }}
- name: SUPERMCP_AUDIT_SPOOL_DIR
  value: {{ .Values.audit.spool.path | quote }}
- name: SUPERMCP_AUDIT_SPOOL_MAX_BYTES
  value: {{ .Values.audit.spool.maxBytes | int64 | quote }}
- name: SUPERMCP_AUDIT_SPOOL_ORPHAN_AGE
  value: {{ .Values.audit.spool.orphanAge | quote }}
{{- end }}
- name: SUPERMCP_KEK_PROVIDER
  value: {{ .Values.encryption.provider | quote }}
{{- if eq .Values.encryption.provider "local" }}
- name: ENCRYPTION_KEK
  valueFrom:
    secretKeyRef:
      name: {{ required "encryption.local.existingSecret is required for the local provider" .Values.encryption.local.existingSecret }}
      key: {{ .Values.encryption.local.key }}
{{- else if eq .Values.encryption.provider "awskms" }}
- name: SUPERMCP_KMS_KEY_ID
  value: {{ required "encryption.awskms.keyId is required (a key id, alias or ARN)" .Values.encryption.awskms.keyId | quote }}
{{- if .Values.encryption.awskms.region }}
- name: SUPERMCP_KMS_REGION
  value: {{ .Values.encryption.awskms.region | quote }}
{{- end }}
{{- if .Values.encryption.awskms.timeout }}
- name: SUPERMCP_KMS_TIMEOUT
  value: {{ .Values.encryption.awskms.timeout | quote }}
{{- end }}
{{- else }}
{{- fail (printf "encryption.provider %q is not implemented; use local or awskms" .Values.encryption.provider) }}
{{- end }}
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}
