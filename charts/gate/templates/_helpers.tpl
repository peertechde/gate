{{- define "gate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "gate.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "gate.labels" -}}
app.kubernetes.io/name: {{ include "gate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "gate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "gate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "gate.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "gate.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "gate.userNamespace" -}}
{{- default .Release.Namespace .Values.config.userNamespace -}}
{{- end -}}

{{- define "gate.hostKeyNamespace" -}}
{{- default .Release.Namespace .Values.config.hostKeyNamespace -}}
{{- end -}}
