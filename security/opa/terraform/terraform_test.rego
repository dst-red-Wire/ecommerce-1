package ecommerce.terraform

import rego.v1

test_private_database_plan_passes if {
	result := deny with input as {"resource_changes": [{
		"address": "hcloud_firewall.database",
		"type": "hcloud_firewall",
		"change": {
			"actions": ["create"],
			"after": {"rules": [{"direction": "in", "port": "5432", "source_ips": ["10.0.0.0/24"]}]},
		},
	}]}
	count(result) == 0
}

test_public_database_plan_fails if {
	result := deny with input as {"resource_changes": [{
		"address": "hcloud_firewall.database",
		"type": "hcloud_firewall",
		"change": {
			"actions": ["create"],
			"after": {"rules": [{"direction": "in", "port": "5432", "source_ips": ["0.0.0.0/0"]}]},
		},
	}]}
	some message in result
	contains(message, "public PostgreSQL")
}

test_protected_volume_delete_fails if {
	result := deny with input as {"resource_changes": [{
		"address": "hcloud_volume.postgresql",
		"type": "hcloud_volume",
		"change": {"actions": ["delete", "create"], "before": {}, "after": {}},
	}]}
	some message in result
	contains(message, "protected resource")
}
