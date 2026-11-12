# Default-deny egress for named Unix UIDs, with no credentials.
#
# Nothing here needs a schema or a plugin. Each rule is a plain yes or no on
# the destination, method and path. Every destination the gateway is asked for
# reaches this policy, including ones that are not in pdp.yaml.
package pdp.authz

import rego.v1

# Edit these for your deployment.
allowed_uids := {1000}

# Hosts that may be read. A leading "*." matches every name below the suffix.
readable_hosts := {"pypi.org", "files.pythonhosted.org", "*.githubusercontent.com"}

# Hosts that may be called with any method.
open_hosts := {"api.example.com"}

# Opaque tunnels, as "host:port". The gateway cannot read these.
tunnels := {"db.internal.example.com:5432"}

default allow := false

allow if {
	caller_allowed
	not private_address
	destination_allowed
}

default caller_allowed := false

caller_allowed if {
	input.identity.auth_method == "unix"
	input.identity.uid in allowed_uids
}

default destination_allowed := false

destination_allowed if {
	input.protocol == "http"
	input.destination.scheme == "https"
	input.destination.port == 443
	input.http.method in {"GET", "HEAD"}
	some pattern in readable_hosts
	glob.match(pattern, ["."], input.destination.host)
}

destination_allowed if {
	input.protocol in {"http", "websocket"}
	input.destination.scheme == "https"
	input.destination.port == 443
	input.destination.host in open_hosts
}

destination_allowed if {
	input.protocol == "tunnel"
	sprintf("%s:%d", [input.destination.host, input.destination.port]) in tunnels
}

# The policy runs once before the name is resolved and once after, with the
# addresses the gateway will dial. This refuses a public name that resolves to
# loopback, link-local (cloud metadata) or private space.
private_ranges := {"127.0.0.0/8", "169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10"}

default private_address := false

private_address if {
	input.protocol != "tunnel"
	some address in input.destination.addresses
	some range in private_ranges
	net.cidr_contains(range, address)
}

matched_rules contains "egress" if allow

reasons contains "caller UID is not allowed" if not caller_allowed

reasons contains "destination resolves to a private address" if private_address

reasons contains "destination, method or protocol is not allowed" if not destination_allowed
