package ecommerce.terraform

import rego.v1

public_cidrs := {"0.0.0.0/0", "::/0"}
critical_resource_types := {
	"hcloud_volume",
	"postgresql_database",
	"postgresql_schema",
	"mongodbatlas_cluster",
}

firewall_resource(change) if {
	contains(lower(change.type), "firewall")
}

rule_sources(rule) := object.get(rule, "source_ips", object.get(rule, "cidr_blocks", []))

public_rule(rule) if {
	some cidr in rule_sources(rule)
	cidr in public_cidrs
}

port_matches(rule, expected) if {
	object.get(rule, "port", "") == sprintf("%d", [expected])
}

port_matches(rule, expected) if {
	from_port := object.get(rule, "from_port", -1)
	to_port := object.get(rule, "to_port", from_port)
	from_port <= expected
	expected <= to_port
}

port_matches(rule, _) if {
	object.get(rule, "port", "") in {"any", "1-65535"}
}

protected_resource(change) if {
	change.type in critical_resource_types
}

protected_resource(change) if {
	before := object.get(change.change, "before", {})
	labels := object.get(before, "labels", {})
	object.get(labels, "ecommerce.dev/protected", "false") == "true"
}

delete_or_replace(change) if {
	"delete" in object.get(change.change, "actions", [])
}

deny contains sprintf("NET-002 public PostgreSQL 5432 exposure at %s", [change.address]) if {
	some change in object.get(input, "resource_changes", [])
	firewall_resource(change)
	after := object.get(change.change, "after", {})
	some rule in object.get(after, "rules", [])
	object.get(rule, "direction", "in") == "in"
	public_rule(rule)
	port_matches(rule, 5432)
}

deny contains sprintf("NET-002 public SSH exposure at %s", [change.address]) if {
	some change in object.get(input, "resource_changes", [])
	firewall_resource(change)
	after := object.get(change.change, "after", {})
	some rule in object.get(after, "rules", [])
	object.get(rule, "direction", "in") == "in"
	public_rule(rule)
	port_matches(rule, 22)
}

deny contains sprintf("NET-002 unexpected public ingress at %s", [change.address]) if {
	some change in object.get(input, "resource_changes", [])
	firewall_resource(change)
	after := object.get(change.change, "after", {})
	some rule in object.get(after, "rules", [])
	object.get(rule, "direction", "in") == "in"
	public_rule(rule)
	not port_matches(rule, 80)
	not port_matches(rule, 443)
}

deny contains sprintf("IMM-001 delete or replace of protected resource %s", [change.address]) if {
	some change in object.get(input, "resource_changes", [])
	protected_resource(change)
	delete_or_replace(change)
}
