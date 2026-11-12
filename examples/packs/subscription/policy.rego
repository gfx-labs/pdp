# Subscription accounts on one provider host, selected by placeholder.
#
# The workload holds a placeholder, never a real token. The gateway reads the
# placeholder only to pick a candidate binding and reports it as input.binding.
# This policy decides whether the verified caller may use that binding. Knowing
# another account's placeholder grants nothing.
package pdp.authz

import rego.v1

# grants.yaml maps a verified identity to the bindings it may use.
granted_bindings := object.get(data.run_grants, input.identity.id, [])

default allow := false

allow if {
	caller_verified
	destination_expected
	binding_granted
}

default caller_verified := false

caller_verified if input.identity.auth_method == "unix"

default destination_expected := false

destination_expected if {
	input.protocol == "http"
	input.destination.scheme == "https"
	input.destination.host == "api.provider.example"
	input.destination.port == 443
}

default binding_granted := false

# input.binding is absent when the request named no known placeholder.
binding_granted if input.binding in granted_bindings

matched_rules contains sprintf("granted:%s", [input.binding]) if allow

reasons contains "caller is not a Unix peer" if not caller_verified

reasons contains "unexpected destination" if not destination_expected

reasons contains "binding is not granted to this caller" if not binding_granted
