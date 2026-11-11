# Read named Linear issues, for named Unix UIDs.
#
# input.graphql has one entry per selected field, including aliases, fragments
# and fields behind @skip or @include. Every entry must be allowed.
package pdp.authz

import rego.v1

# Edit these for your deployment.
allowed_uids := {1000}

allowed_issues := {"APPROVED_ISSUE_UUID"}

# Digest of linear.graphql. A changed schema denies until this is reviewed.
reviewed_schema_digest := "sha256:45be35e9a86ff65c6558a58ea67eebd69d2ee75166b0f4da1385aa5b856aec68"

issue_fields := {"Issue.id", "Issue.identifier", "Issue.title", "Issue.description"}

default allow := false

allow if {
	caller_allowed
	route_expected
	schema_reviewed
	count(input.graphql) > 0
	every field in input.graphql {
		field_allowed(field)
	}
}

default caller_allowed := false

caller_allowed if {
	input.identity.auth_method == "unix"
	input.identity.uid in allowed_uids
}

default route_expected := false

route_expected if {
	input.destination.host == "api.linear.app"
	input.destination.port == 443
	input.plugin == "linear"
	input.binding == "linear-app"
}

default schema_reviewed := false

schema_reviewed if input.schema_digest == reviewed_schema_digest

default field_allowed(_) := false

field_allowed(field) if issue_lookup(field)

# A reviewed field directly under an allowed issue lookup. The parent is found
# by path, so one alias cannot borrow another alias's approved issue.
field_allowed(field) if {
	field.coordinate in issue_fields
	count(field.path) == 2
	count(field.arguments) == 0
	parents := [parent | some parent in input.graphql; parent.path == array.slice(field.path, 0, 1)]
	count(parents) > 0
	every parent in parents {
		issue_lookup(parent)
	}
}

default issue_lookup(_) := false

issue_lookup(field) if {
	field.coordinate == "Query.issue"
	count(field.path) == 1
	object.keys(field.arguments) == {"id"}
	field.arguments.id in allowed_issues
}

matched_rules contains "issue-read" if allow

reasons contains "caller UID is not allowed" if not caller_allowed

reasons contains "unexpected destination or binding" if not route_expected

reasons contains "schema digest is not the reviewed one" if not schema_reviewed

reasons contains sprintf("field not allowed: %s at %s", [field.coordinate, concat(".", field.path)]) if {
	some field in input.graphql
	not field_allowed(field)
}
