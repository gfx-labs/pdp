# Read named Linear issues and comment on them, for named Unix UIDs.
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

# Reviewed fields that may be selected directly under each root field.
root_children := {
	"Query.issue": {"Issue.id", "Issue.identifier", "Issue.title", "Issue.description"},
	"Mutation.commentCreate": {"CommentPayload.success", "CommentPayload.comment"},
}

# Reviewed fields of the comment returned by commentCreate.
comment_fields := {"Comment.id", "Comment.body"}

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
	input.provider == "linear"
	input.binding == "linear-installation"
}

default schema_reviewed := false

schema_reviewed if input.schema_digest == reviewed_schema_digest

default field_allowed(_) := false

field_allowed(field) if root_allowed(field)

field_allowed(field) if child_allowed(field)

# A field of the created comment, under an allowed CommentPayload.comment.
field_allowed(field) if {
	field.coordinate in comment_fields
	count(field.path) == 3
	count(field.arguments) == 0
	parents := parents_of(field)
	count(parents) > 0
	every parent in parents {
		parent.coordinate == "CommentPayload.comment"
		child_allowed(parent)
	}
}

# Parents are found by path, so one alias cannot borrow another alias's issue.
parents_of(field) := [parent |
	some parent in input.graphql
	parent.path == array.slice(field.path, 0, count(field.path) - 1)
]

default child_allowed(_) := false

# A reviewed field directly under an allowed root field.
child_allowed(field) if {
	count(field.path) == 2
	count(field.arguments) == 0
	parents := parents_of(field)
	count(parents) > 0
	every parent in parents {
		field.coordinate in root_children[parent.coordinate]
		root_allowed(parent)
	}
}

default root_allowed(_) := false

root_allowed(field) if {
	field.coordinate == "Query.issue"
	count(field.path) == 1
	object.keys(field.arguments) == {"id"}
	field.arguments.id in allowed_issues
}

# A comment names an allowed issue and a nonempty body, and nothing else. Keys
# such as projectId, parentId or createAsUser would change the target or actor.
root_allowed(field) if {
	field.coordinate == "Mutation.commentCreate"
	count(field.path) == 1
	object.keys(field.arguments) == {"input"}
	comment := field.arguments.input
	object.keys(comment) == {"issueId", "body"}
	comment.issueId in allowed_issues
	is_string(comment.body)
	trim_space(comment.body) != ""
}

matched_rules contains "issue-read-comment" if allow

reasons contains "caller UID is not allowed" if not caller_allowed

reasons contains "unexpected provider or binding" if not route_expected

reasons contains "schema digest is not the reviewed one" if not schema_reviewed

reasons contains sprintf("field not allowed: %s at %s", [field.coordinate, concat(".", field.path)]) if {
	some field in input.graphql
	not field_allowed(field)
}
