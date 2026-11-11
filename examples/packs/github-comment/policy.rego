# Read one GitHub repository and comment on its issues, for named Unix UIDs.
#
# This allows comments on every issue in the repository. To limit it to named
# issues, add a check on input.http.path_params.issue_number.
package pdp.authz

import rego.v1

# Edit these for your deployment.
allowed_uids := {1000}

allowed_repositories := {"APPROVED_OWNER/APPROVED_REPOSITORY"}

# Digest of github-rest.json. A changed schema denies until this is reviewed.
reviewed_schema_digest := "sha256:e5144f87c069a92de5d96588a6b4b4c8614f1f88c9f52b012a7dd63704a0ca89"

read_operations := {"repos/get", "issues/get", "issues/list-comments"}

default allow := false

allow if {
	caller_allowed
	route_expected
	schema_reviewed
	repository_allowed
	count(input.operations) == 1
	operation_allowed(input.operations[0].id)
}

default caller_allowed := false

caller_allowed if {
	input.identity.auth_method == "unix"
	input.identity.uid in allowed_uids
}

default route_expected := false

route_expected if {
	input.destination.host == "api.github.com"
	input.destination.port == 443
	input.plugin == "github"
	input.binding == "github-app-repo"
}

default schema_reviewed := false

schema_reviewed if input.schema_digest == reviewed_schema_digest

# The repository is the exact owner/repo pair from the validated path.
repository := sprintf("%s/%s", [input.http.path_params.owner, input.http.path_params.repo])

default repository_allowed := false

repository_allowed if repository in allowed_repositories

default operation_allowed(_) := false

operation_allowed(id) if id in read_operations

# A comment carries a nonempty body and nothing else.
operation_allowed("issues/create-comment") if {
	object.keys(input.http.body) == {"body"}
	is_string(input.http.body.body)
	trim_space(input.http.body.body) != ""
}

matched_rules contains "repository-read-comment" if allow

reasons contains "caller UID is not allowed" if not caller_allowed

reasons contains "unexpected destination or binding" if not route_expected

reasons contains "schema digest is not the reviewed one" if not schema_reviewed

reasons contains "repository is not allowed" if not repository_allowed

reasons contains sprintf("operation or request body is not allowed: %s", [operation.id]) if {
	some operation in input.operations
	not operation_allowed(operation.id)
}
