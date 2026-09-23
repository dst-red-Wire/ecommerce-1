{{- define "product.labels" -}}
app.kubernetes.io/name: product
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: ecommerce
ecommerce.io/service: product
{{- end -}}
