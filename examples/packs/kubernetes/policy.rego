# Two kinds of caller in one cluster.
#
# A workload that presents its SVID to the proxy listener is known by SPIFFE
# ID and may use the credentialed upstream. A workload that was only steered
# here by DNS is known by pod IP alone, so it gets credential-free reads of the
# steered hosts and nothing else.
package pdp.authz

import rego.v1

# Edit these for your deployment.
allowed_workloads := {"spiffe://example.org/ns/agents/sa/worker"}

# Pod CIDR of the namespaces whose DNS points at PDP.
steered_pods := "10.244.0.0/16"

steered_hosts := {"pypi.org", "files.pythonhosted.org"}

default allow := false

allow if credentialed_call

allow if steered_read

default credentialed_call := false

credentialed_call if {
	input.identity.auth_method == "spiffe"
	input.identity.spiffe_id in allowed_workloads
	input.protocol == "http"
	input.destination.scheme == "https"
	input.destination.host == "api.example.com"
	input.destination.port == 443
	input.binding == "example-api"
}

default steered_read := false

# A source IP is weaker than an SVID. Never pair it with a binding.
steered_read if {
	input.identity.auth_method == "transparent"
	net.cidr_contains(steered_pods, input.identity.ip)
	input.protocol == "http"
	input.destination.scheme == "https"
	input.destination.port == 443
	input.destination.host in steered_hosts
	input.http.method in {"GET", "HEAD"}
	not input.binding
}

matched_rules contains "credentialed-call" if credentialed_call

matched_rules contains "steered-read" if steered_read

reasons contains "no rule allows this caller, destination and method" if not allow
