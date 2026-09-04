package ecommerce.kubernetes

import rego.v1

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}

manifests := object.get(input, "manifests", [])

production if {
	object.get(input, "environment", "") == "production"
}

production if {
	some manifest in manifests
	labels := object.get(object.get(manifest, "metadata", {}), "labels", {})
	object.get(labels, "ecommerce.dev/environment", "") == "production"
}

workload(manifest) if {
	manifest.kind in workload_kinds
}

pod_spec(manifest) := manifest.spec.jobTemplate.spec.template.spec if {
	manifest.kind == "CronJob"
}

pod_spec(manifest) := manifest.spec.template.spec if {
	manifest.kind != "CronJob"
}

containers(spec) := array.concat(object.get(spec, "initContainers", []), object.get(spec, "containers", []))

object_name(manifest) := sprintf("%s/%s", [
	object.get(object.get(manifest, "metadata", {}), "namespace", "default"),
	object.get(object.get(manifest, "metadata", {}), "name", "<unnamed>"),
])

has_exception(manifest, control_id) if {
	annotations := object.get(object.get(manifest, "metadata", {}), "annotations", {})
	exception_id := object.get(annotations, "governance.ecommerce-1/exception", "")
	some exception in data.exceptions
	exception.id == exception_id
	exception.control_id == control_id
	exception.scope.kind == manifest.kind
	exception.scope.name == object.get(manifest.metadata, "name", "")
	exception.scope.namespace == object.get(manifest.metadata, "namespace", "default")
	"production" in exception.environments
}

container_non_root(spec, _) if {
	object.get(object.get(spec, "securityContext", {}), "runAsNonRoot", false)
}

container_non_root(_, container) if {
	object.get(object.get(container, "securityContext", {}), "runAsNonRoot", false)
}

runtime_default(spec, _) if {
	object.get(object.get(object.get(spec, "securityContext", {}), "seccompProfile", {}), "type", "") == "RuntimeDefault"
}

runtime_default(_, container) if {
	object.get(object.get(object.get(container, "securityContext", {}), "seccompProfile", {}), "type", "") == "RuntimeDefault"
}

drops_all(container) if {
	"ALL" in object.get(object.get(object.get(container, "securityContext", {}), "capabilities", {}), "drop", [])
}

bounded_resources(container) if {
	resources := object.get(container, "resources", {})
	requests := object.get(resources, "requests", {})
	limits := object.get(resources, "limits", {})
	object.get(requests, "cpu", "") != ""
	object.get(requests, "memory", "") != ""
	object.get(limits, "cpu", "") != ""
	object.get(limits, "memory", "") != ""
}

digest_pinned(container) if {
	contains(object.get(container, "image", ""), "@sha256:")
}

mutable_latest(container) if {
	endswith(object.get(container, "image", ""), ":latest")
}

health_probes_required(manifest) if {
	manifest.kind in {"Deployment", "StatefulSet"}
}

has_health_probes(container) if {
	object.get(container, "livenessProbe", null) != null
	object.get(container, "readinessProbe", null) != null
}

default_deny_for(namespace) if {
	some policy in manifests
	policy.kind == "NetworkPolicy"
	object.get(policy.metadata, "namespace", "default") == namespace
	object.get(policy.spec, "podSelector", {}) == {}
	"Ingress" in object.get(policy.spec, "policyTypes", [])
	"Egress" in object.get(policy.spec, "policyTypes", [])
	count(object.get(policy.spec, "ingress", [])) == 0
	count(object.get(policy.spec, "egress", [])) == 0
}

unencrypted_secret_value(manifest) if {
	some _, value in object.get(manifest, "data", {})
	not startswith(value, "ENC[")
}

unencrypted_secret_value(manifest) if {
	some _, value in object.get(manifest, "stringData", {})
	not startswith(value, "ENC[")
}

deny contains sprintf("SEC-001 privileged container %s/%s", [object_name(manifest), container.name]) if {
	production
	some manifest in manifests
	workload(manifest)
	not has_exception(manifest, "SEC-001")
	spec := pod_spec(manifest)
	some container in containers(spec)
	object.get(object.get(container, "securityContext", {}), "privileged", false)
}

deny contains sprintf("SEC-001 host namespace enabled on %s", [object_name(manifest)]) if {
	production
	some manifest in manifests
	workload(manifest)
	not has_exception(manifest, "SEC-001")
	spec := pod_spec(manifest)
	some field in {"hostPID", "hostIPC", "hostNetwork"}
	object.get(spec, field, false)
}

deny contains sprintf("SEC-001 hostPath volume on %s", [object_name(manifest)]) if {
	production
	some manifest in manifests
	workload(manifest)
	not has_exception(manifest, "SEC-001")
	spec := pod_spec(manifest)
	some volume in object.get(spec, "volumes", [])
	object.get(volume, "hostPath", null) != null
}

deny contains sprintf("SEC-001 runAsNonRoot missing on %s/%s", [object_name(manifest), container.name]) if {
	production
	some manifest in manifests
	workload(manifest)
	not has_exception(manifest, "SEC-001")
	spec := pod_spec(manifest)
	some container in containers(spec)
	not container_non_root(spec, container)
}

deny contains sprintf("SEC-001 RuntimeDefault seccomp missing on %s/%s", [object_name(manifest), container.name]) if {
	production
	some manifest in manifests
	workload(manifest)
	not has_exception(manifest, "SEC-001")
	spec := pod_spec(manifest)
	some container in containers(spec)
	not runtime_default(spec, container)
}

deny contains sprintf("SEC-001 capabilities drop ALL missing on %s/%s", [object_name(manifest), container.name]) if {
	production
	some manifest in manifests
	workload(manifest)
	not has_exception(manifest, "SEC-001")
	spec := pod_spec(manifest)
	some container in containers(spec)
	not drops_all(container)
}

deny contains sprintf("SEC-001 resource requests/limits missing on %s/%s", [object_name(manifest), container.name]) if {
	production
	some manifest in manifests
	workload(manifest)
	not has_exception(manifest, "SEC-001")
	spec := pod_spec(manifest)
	some container in containers(spec)
	not bounded_resources(container)
}

deny contains sprintf("SUPPLY-005 mutable latest image on %s/%s", [object_name(manifest), container.name]) if {
	production
	some manifest in manifests
	workload(manifest)
	spec := pod_spec(manifest)
	some container in containers(spec)
	mutable_latest(container)
}

deny contains sprintf("SUPPLY-005 image is not digest-pinned on %s/%s", [object_name(manifest), container.name]) if {
	production
	some manifest in manifests
	workload(manifest)
	spec := pod_spec(manifest)
	some container in containers(spec)
	not digest_pinned(container)
}

deny contains sprintf("SEC-001 health probes missing on %s/%s", [object_name(manifest), container.name]) if {
	production
	some manifest in manifests
	workload(manifest)
	health_probes_required(manifest)
	not has_exception(manifest, "SEC-001")
	spec := pod_spec(manifest)
	some container in object.get(spec, "containers", [])
	not has_health_probes(container)
}

deny contains sprintf("NET-001 default-deny NetworkPolicy missing for namespace %s", [namespace]) if {
	production
	some manifest in manifests
	workload(manifest)
	not has_exception(manifest, "NET-001")
	namespace := object.get(manifest.metadata, "namespace", "default")
	not default_deny_for(namespace)
}

deny contains sprintf("SEC-003 plaintext Kubernetes Secret %s", [object_name(manifest)]) if {
	production
	some manifest in manifests
	manifest.kind == "Secret"
	unencrypted_secret_value(manifest)
}
