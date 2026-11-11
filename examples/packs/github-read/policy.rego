# Read-only access to one GitHub repository for named Unix UIDs.
#
# Go authenticates the caller and validates the request against the pinned
# schema. Everything about who may do what is decided here.
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
	operations_readable
	repository_allowed
}

default caller_allowed := false

caller_allowed if {
	input.identity.auth_method == "unix"
	input.identity.uid in allowed_uids
}

default route_expected := false

route_expected if {
	input.provider == "github"
	input.binding == "github-repo"
}

default schema_reviewed := false

schema_reviewed if input.schema_digest == reviewed_schema_digest

default operations_readable := false

operations_readable if {
	count(input.operations) > 0
	every operation in input.operations {
		operation.id in read_operations
	}
}

# The repository is the exact owner/repo pair from the validated path.
repository := sprintf("%s/%s", [input.http.path_params.owner, input.http.path_params.repo])

default repository_allowed := false

repository_allowed if repository in allowed_repositories

matched_rules contains "repository-read" if allow

reasons contains "caller UID is not allowed" if not caller_allowed

reasons contains "unexpected provider or binding" if not route_expected

reasons contains "schema digest is not the reviewed one" if not schema_reviewed

reasons contains "operation is not a reviewed read" if not operations_readable

reasons contains "repository is not allowed" if not repository_allowed
