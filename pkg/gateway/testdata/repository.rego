package pdp.authz

import rego.v1

default allow := false

allow if {
	input.identity.auth_method == "unix"
	input.identity.uid == data.peer_uid
	input.destination.host == "example.com"
	input.plugin == "github"
	input.binding == "installation"
	input.schema_digest == "sha256:e5144f87c069a92de5d96588a6b4b4c8614f1f88c9f52b012a7dd63704a0ca89"
	input.http.method == "GET"
	count(input.operations) == 1
	approved_operation
	task := data.identity_tasks[input.identity.id]
	repository := concat("/", [input.http.path_params.owner, input.http.path_params.repo])
	repository in data.task_repositories[task]
}

approved_operation if input.operations[0].id == "repos/get"

approved_operation if {
	input.operations[0].id == "issues/list-comments"
	input.http.normalized_query.per_page == 10
}

matched_rules contains "repository-read" if allow
