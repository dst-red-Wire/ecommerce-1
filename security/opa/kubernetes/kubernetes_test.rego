package ecommerce.kubernetes

import rego.v1

secure_container := {
	"name": "api",
	"image": "registry.example/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"securityContext": {"allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]}},
	"resources": {
		"requests": {"cpu": "100m", "memory": "128Mi"},
		"limits": {"cpu": "500m", "memory": "512Mi"},
	},
	"livenessProbe": {"httpGet": {"path": "/healthz", "port": 8080}},
	"readinessProbe": {"httpGet": {"path": "/readyz", "port": 8080}},
}

secure_deployment := {
	"apiVersion": "apps/v1",
	"kind": "Deployment",
	"metadata": {"name": "api", "namespace": "shop"},
	"spec": {"template": {"spec": {
		"securityContext": {"runAsNonRoot": true, "seccompProfile": {"type": "RuntimeDefault"}},
		"containers": [secure_container],
	}}},
}

default_deny := {
	"apiVersion": "networking.k8s.io/v1",
	"kind": "NetworkPolicy",
	"metadata": {"name": "default-deny", "namespace": "shop"},
	"spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": []},
}

test_secure_production_bundle_passes if {
	result := deny with input as {"environment": "production", "manifests": [secure_deployment, default_deny]}
	count(result) == 0
}

test_privileged_container_fails if {
	bad := json.patch(secure_deployment, [{"op": "add", "path": "/spec/template/spec/containers/0/securityContext/privileged", "value": true}])
	result := deny with input as {"environment": "production", "manifests": [bad, default_deny]}
	some message in result
	contains(message, "privileged container")
}

test_latest_image_fails if {
	bad := json.patch(secure_deployment, [{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": "registry.example/api:latest"}])
	result := deny with input as {"environment": "production", "manifests": [bad, default_deny]}
	some message in result
	contains(message, "mutable latest image")
}

test_missing_network_policy_fails if {
	result := deny with input as {"environment": "production", "manifests": [secure_deployment]}
	some message in result
	contains(message, "default-deny NetworkPolicy missing")
}
