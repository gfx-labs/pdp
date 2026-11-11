package pdp.authz

import rego.v1

default allow := false

allow if {
	input.identity.auth_method == "unix"
	input.identity.uid == data.peer_uid
	input.provider == "linear"
	input.binding == "installation"
	input.schema_digest == "sha256:45be35e9a86ff65c6558a58ea67eebd69d2ee75166b0f4da1385aa5b856aec68"
	input.http.method == "POST"
	count(input.graphql) > 0
	every field in input.graphql {
		approved_field(field)
	}
}

# Match each descendant to its own aliased root, not any permitted issue.
default approved_field(_) := false

approved_field(field) if {
	field.coordinate == "Query.issue"
	count(field.path) == 1
	object.keys(field.arguments) == {"id"}
	field.arguments.id in object.keys(data.issue_fields)
}

approved_field(field) if {
	field.coordinate == "Mutation.commentCreate"
	count(field.path) == 1
	object.keys(field.arguments) == {"input"}
	value := field.arguments.input
	object.keys(value) == {"issueId", "body"}
	value.issueId in object.keys(data.issue_fields)
	is_string(value.body)
	count(value.body) > 0
}

approved_field(field) if {
	some root in input.graphql
	root.coordinate == "Query.issue"
	count(root.path) == 1
	count(field.path) == 2
	array.slice(field.path, 0, 1) == root.path
	field.coordinate in data.issue_fields[root.arguments.id]
	object.keys(field.arguments) == set()
}

approved_field(field) if {
	some root in input.graphql
	root.coordinate == "Mutation.commentCreate"
	count(root.path) == 1
	count(field.path) == 2
	array.slice(field.path, 0, 1) == root.path
	field.coordinate in {"CommentPayload.success", "CommentPayload.comment"}
	object.keys(field.arguments) == set()
}

approved_field(field) if {
	some parent in input.graphql
	parent.coordinate == "CommentPayload.comment"
	count(parent.path) == 2
	count(field.path) == 3
	array.slice(field.path, 0, 2) == parent.path
	field.coordinate in {"Comment.id", "Comment.body"}
	object.keys(field.arguments) == set()
}

matched_rules contains "issue-comments" if allow
