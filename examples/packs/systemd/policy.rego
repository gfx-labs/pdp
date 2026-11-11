# Full access to one GitHub credential binding for named Unix UIDs.
#
# No schema is pinned, so requests are not classified. Anything the provider
# credential can do, these callers can do. Use github-read or github-comment
# when the gateway must restrict operations or repositories.
package pdp.authz

import rego.v1

# Edit this for your deployment.
allowed_uids := {1000}

default allow := false

allow if {
	input.identity.auth_method == "unix"
	input.identity.uid in allowed_uids
	input.provider == "github"
	input.binding == "github-local"
}

matched_rules contains "github-full" if allow

reasons contains "caller is not an allowed UID on the github-local binding" if not allow
