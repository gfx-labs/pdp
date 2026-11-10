# Base authorization policy. Every allow and deny decision is made here.
#
# data.pdp.config is the administrator's YAML/JSON policy: grants, denies,
# mandatory rules, reviewed operations and the optional relationship snapshot.
# input is the trusted normalized request. input._pdp holds request facts the
# gateway extracted: one unit per REST operation or GraphQL field occurrence,
# with its resources and the values each configured selector picked.
package pdp.base

import rego.v1

config := data.pdp.config

units := input._pdp.units

now := input._pdp.now_ns

custom_denials := data.pdp.custom.deny

default allow := false

allow if {
	count(denied_by) == 0
	count(units) > 0
	every index, _ in units {
		count(matched[index]) > 0
	}
}

decision := {
	"allow": allow,
	"denied_by": denied_by,
	"reasons": reasons,
	"units": [{"grants": matched[index]} | some index, _ in units],
	"custom_denials": custom_denials,
}

# Grants are independent alternatives. Each unit needs one complete grant.
matched[index] := ids if {
	some index, unit in units
	ids := {grant.id | some grant in config.grants; grant_matches(grant, unit)}
}

default grant_matches(_, _) := false

grant_matches(grant, unit) if {
	scope_matches(grant.scope, unit)
	mode_matches(grant, unit)
	operation_allows(grant, unit)
	satisfied(grant.constraints, unit)
}

# Explicit denies and mandatory rules override every grant, including full.
denied_by contains "invalid_facts" if not facts_valid

denied_by contains "resource_normalization" if {
	some unit in units
	unit.resource_error != ""
}

denied_by contains rule.id if {
	some rule in config.denies
	some unit in units
	rule_denies(rule, unit)
}

denied_by contains rule.id if {
	some rule in config.mandatory
	some unit in units
	scope_matches(rule.scope, unit)
	not satisfied(rule.constraints, unit)
}

denied_by contains "custom" if count(custom_denials) > 0

default rule_denies(_, _) := false

rule_denies(rule, unit) if {
	scope_matches(rule.scope, unit)
	deny_matches(rule.constraints, unit)
}

# Scope: an empty list matches everything. Grants must name identities,
# providers and bindings, which configuration loading enforces.
default scope_matches(_, _) := false

scope_matches(scope, unit) if {
	listed(scope.identities, input.identity.id)
	listed(scope.providers, input.provider)
	listed(scope.bindings, input.binding)
	listed(scope.operations, unit.id)
}

default listed(_, _) := false

listed(values, _) if count(values) == 0

listed(values, value) if value in values

# Modes: full needs no classification. Every other mode needs a reviewed
# operation whose pinned schema digest, when set, matches the request.
operation(unit) := config.operations[input.provider][unit.id]

default reviewed(_) := false

reviewed(unit) if {
	op := operation(unit)
	op.reviewed == true
	op.schema_digest in {"", input.schema_digest}
}

default mode_matches(_, _) := false

mode_matches(grant, _) if grant.mode == "full"

mode_matches(grant, unit) if {
	grant.mode == ""
	count(grant.scope.operations) > 0
	reviewed(unit)
}

mode_matches(grant, unit) if {
	grant.mode == "read"
	reviewed(unit)
	operation(unit).classification == "read"
}

mode_matches(grant, unit) if {
	grant.mode == "read_write"
	reviewed(unit)
	operation(unit).classification in {"read", "write"}
}

# Reviewed operation constraints bind every grant except full.
default operation_allows(_, _) := false

operation_allows(grant, _) if grant.mode == "full"

operation_allows(grant, unit) if {
	grant.mode != "full"
	satisfied(operation(unit).constraints, unit)
}

# Constraints for grants and mandatory rules: every part must hold.
default satisfied(_, _) := false

satisfied(constraints, unit) if count(failures(constraints, unit)) == 0

failures(constraints, unit) := {reason |
	some reason, passed in {
		"schema digest not allowed": schema_ok(constraints),
		"repository missing or outside allowed list": kind_ok(constraints.repositories, "repository", unit),
		"issue missing or outside allowed list": kind_ok(constraints.issues, "issue", unit),
		"resource missing or outside allowed list": resources_ok(constraints, unit),
		"request value missing or outside allowed list": values_ok(constraints, unit),
		"request object missing or has a forbidden shape": objects_ok(constraints, unit),
		"relationship requirement not satisfied": relationship_ok(constraints, unit),
	}
	not passed
}

default schema_ok(_) := false

schema_ok(constraints) if count(constraints.schema_digests) == 0

schema_ok(constraints) if input.schema_digest in constraints.schema_digests

# The resource type must be present and every resource of it must be listed.
default kind_ok(_, _, _) := false

kind_ok(ids, _, _) if count(ids) == 0

kind_ok(ids, kind, unit) if {
	present := [resource | some resource in unit.resources; resource.type == kind]
	count(present) > 0
	every resource in present {
		resource.id in ids
	}
}

default resources_ok(_, _) := false

resources_ok(constraints, _) if count(constraints.resources) == 0

resources_ok(constraints, unit) if {
	count(unit.resources) > 0
	every resource in unit.resources {
		resource in constraints.resources
	}
}

# A constraint naming a GraphQL field applies only to that field's units.
default applies(_, _) := false

applies(constraint, _) if constraint.field == ""

applies(constraint, unit) if constraint.field == unit.coordinate

# Selected values are canonical JSON keys, so numbers compare by exact value.
# "null" is a missing or null value and never satisfies a constraint.
default values_ok(_, _) := false

values_ok(constraints, unit) if {
	every constraint in constraints.values {
		value_ok(constraint, unit)
	}
}

default value_ok(_, _) := false

value_ok(constraint, unit) if not applies(constraint, unit)

value_ok(constraint, unit) if {
	applies(constraint, unit)
	selected := unit.values[constraint.selector]
	count(selected) > 0
	every key in selected {
		key != "null"
		key in constraint.allowed
	}
}

default objects_ok(_, _) := false

objects_ok(constraints, unit) if {
	every constraint in constraints.objects {
		object_ok(constraint, unit)
	}
}

default object_ok(_, _) := false

object_ok(constraint, unit) if not applies(constraint, unit)

object_ok(constraint, unit) if {
	applies(constraint, unit)
	selected := unit.objects[constraint.selector]
	count(selected) > 0
	every value in selected {
		shape_ok(constraint, value)
	}
}

default shape_ok(_, _) := false

shape_ok(constraint, value) if {
	is_object(value)
	every key, _ in value {
		key in constraint.allowed_keys
	}
	every key in constraint.required_string_keys {
		is_string(value[key])
		trim_space(value[key]) != ""
	}
}

# Relationship: a fresh snapshot, an unexpired identity-to-task membership and
# an unexpired task permission on every selected resource. No traversal.
default relationship_ok(_, _) := false

relationship_ok(constraints, _) if constraints.relationship == null

relationship_ok(constraints, unit) if {
	requirement := constraints.relationship
	requirement != null
	snapshot := config.relationships
	snapshot != null
	snapshot.issued_at_ns <= now
	snapshot.expires_at_ns > now
	now - snapshot.issued_at_ns <= snapshot.max_age_ns
	task := object.get(input.identity, "task_id", "")
	task != ""
	some membership in snapshot.identity_tasks
	membership.identity == input.identity.id
	membership.task == task
	membership.expires_at_ns > now
	required := [resource |
		some resource in unit.resources
		listed(requirement.resource_types, resource.type)
	]
	count(required) > 0
	every resource in required {
		task_permits(snapshot, task, requirement.permission, resource)
	}
}

default task_permits(_, _, _, _) := false

task_permits(snapshot, task, permission, resource) if {
	some edge in snapshot.task_resources
	edge.task == task
	edge.resource == resource
	edge.permission == permission
	edge.expires_at_ns > now
}

# Constraints for explicit denies: one forbidden resource or value is enough,
# and a missing sibling never hides it. Separate constraints stay conjunctive.
default deny_matches(_, _) := false

deny_matches(constraints, unit) if {
	schema_ok(constraints)
	kind_hit(constraints.repositories, "repository", unit)
	kind_hit(constraints.issues, "issue", unit)
	resources_hit(constraints, unit)
	every constraint in constraints.values {
		value_hit(constraint, unit)
	}
	every constraint in constraints.objects {
		object_hit(constraint, unit)
	}
}

default kind_hit(_, _, _) := false

kind_hit(ids, _, _) if count(ids) == 0

kind_hit(ids, kind, unit) if {
	some resource in unit.resources
	resource.type == kind
	resource.id in ids
}

default resources_hit(_, _) := false

resources_hit(constraints, _) if count(constraints.resources) == 0

resources_hit(constraints, unit) if {
	some resource in unit.resources
	resource in constraints.resources
}

default value_hit(_, _) := false

value_hit(constraint, unit) if {
	applies(constraint, unit)
	some key in unit.values[constraint.selector]
	key != "null"
	key in constraint.allowed
}

default object_hit(_, _) := false

object_hit(constraint, unit) if {
	applies(constraint, unit)
	some value in unit.objects[constraint.selector]
	shape_ok(constraint, value)
}

# Malformed facts must deny. Without this guard an undefined reference inside
# a deny rule would silently skip that deny.
default facts_valid := false

facts_valid if {
	is_number(now)
	is_string(input.identity.id)
	is_string(input.provider)
	is_string(input.binding)
	is_string(input.schema_digest)
	is_array(units)
	every unit in units {
		is_string(unit.id)
		is_string(unit.coordinate)
		is_string(unit.resource_error)
		is_array(unit.resources)
		every resource in unit.resources {
			is_string(resource.type)
			is_string(resource.id)
		}
		every key in config.value_selectors {
			is_array(unit.values[key])
		}
		every key in config.object_selectors {
			is_array(unit.objects[key])
		}
	}
}

# Explanations for administrators. They never influence the decision.
reasons contains "invalid normalized request facts" if not facts_valid

reasons contains unit.resource_error if {
	some unit in units
	unit.resource_error != ""
}

reasons contains sprintf("explicit deny: %s", [rule.id]) if {
	some rule in config.denies
	some unit in units
	rule_denies(rule, unit)
}

reasons contains sprintf("mandatory restriction %s: %s", [rule.id, reason]) if {
	some rule in config.mandatory
	some unit in units
	scope_matches(rule.scope, unit)
	some reason in failures(rule.constraints, unit)
}

reasons contains sprintf("no grant for operation: %s", [unit.id]) if {
	some index, unit in units
	count(matched[index]) == 0
}

reasons contains sprintf("reviewed operation restriction for %s: %s", [unit.id, reason]) if {
	some grant in config.grants
	some unit in units
	scope_matches(grant.scope, unit)
	mode_matches(grant, unit)
	grant.mode != "full"
	some reason in failures(operation(unit).constraints, unit)
}

reasons contains sprintf("grant %s rejected for %s: %s", [grant.id, unit.id, reason]) if {
	some grant in config.grants
	some unit in units
	scope_matches(grant.scope, unit)
	mode_matches(grant, unit)
	operation_allows(grant, unit)
	some reason in failures(grant.constraints, unit)
}
