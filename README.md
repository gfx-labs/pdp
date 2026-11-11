# PDP

PDP is an identity-aware HTTP forward proxy written in Go. A workload sends its HTTP requests through PDP. PDP identifies the caller, asks your Rego policy whether this caller may send this request to this destination, and when the destination has a credential binding, injects the provider credential. The workload never holds the real credential.

Any HTTP destination can be reached. Rego is the only allowlist. A destination that is not in the configuration still goes to policy, is denied unless policy allows it, and never receives a credential.

## The parts

| Part | Written in | Does |
| --- | --- | --- |
| Policy | Rego, package `pdp.authz` | Decides who may send what to which destination. This is the only place permissions are defined. |
| Runtime configuration | JSON, `pdp.config/v3` | Wiring: listeners, interception CA, DNS steering, upstream entries, schema files, credential bindings, secret paths, policy files. No permissions. |
| Upstream entry | Part of the configuration | Attaches a credential binding, a schema, a TLS mode or token paths to one host and port. It does not allow anything. |
| Schema | OpenAPI JSON or GraphQL SDL | Optional. Makes Go validate a request strictly and turn it into operations and fields for the policy. |
| Credential adapter | Starlark | Obtains the provider credential after the policy allows. |

Go authenticates the caller, reads the destination and normalizes the request. It does not map identities to names or decide anything about permissions.

## How callers reach PDP

| Listener | Identity in `input.identity` | Request forms |
| --- | --- | --- |
| Unix socket | Kernel peer UID: `auth_method` `unix`, `uid` | absolute-form, `CONNECT` |
| SPIFFE mTLS (optional) | Verified SPIFFE ID: `auth_method` `spiffe`, `spiffe_id` | absolute-form, `CONNECT` |
| Transparent HTTP and HTTPS (optional) | Source IP only: `auth_method` `transparent`, `ip` | plain requests steered by PDP's DNS server |

- **Absolute-form.** The request line carries the full URL, for example `GET https://api.github.com/repos/o/r HTTP/1.1`. PDP makes the TLS connection to the destination. No interception CA is needed. `pdp request` uses this form.
- **`CONNECT host:port`.** This is what a client with `HTTPS_PROXY` sends. PDP terminates the inner TLS with a leaf certificate signed by the `interception` CA and authorizes each request inside. An upstream with `"tls": "tunnel"` is relayed unread instead. Without an interception CA, `CONNECT` works only for tunnel upstreams.
- **Transparent.** PDP's DNS server answers configured names with PDP's address. The client connects to PDP believing it reached the destination. The destination comes from `Host` and, on TLS, from SNI, which must agree. Source IP is the only identity.

## Start with a pack

A pack is a directory holding the configuration, policy, adapter, any schema and example inputs. Copy one, edit the marked values, and serve it. See [examples](examples/README.md) for the list.

```sh
make build
bin/pdp validate --config examples/packs/minimal/pdp.json
bin/pdp explain --config examples/packs/minimal/pdp.json \
  --input examples/packs/minimal/explain/get-repository.json
```

Validation compiles the policy, schemas and adapters. It does not open secrets, read the interception CA key or contact a provider. To serve, copy the pack to an administrator-owned directory, set the caller UID in `policy.rego` and the secret path in `pdp.json`, then:

```sh
bin/pdp serve --config /etc/pdp/pdp.json
bin/pdp request --socket /run/pdp/pdp.sock \
  --url https://api.github.com/repos/OWNER/REPOSITORY
```

Linux Unix-domain HTTP is the minimum deployment. SPIFFE mTLS, interception, DNS steering and schemas are optional. **Credential isolation requires the daemon and the workload to run under different UIDs.** A workload sharing the daemon UID can read its mounted secrets and the interception CA key directly. The [systemd pack](examples/packs/systemd/README.md) shows a separated setup.

## Writing policy

```rego
package pdp.authz

import rego.v1

default allow := false

allow if {
	input.identity.auth_method == "unix"
	input.identity.uid == 1000
	input.destination.host == "api.github.com"
	input.destination.port == 443
	input.binding == "github-local"
}
```

- Every module uses `package pdp.authz`. Only a boolean `allow` authorizes. An undefined, malformed or failing evaluation denies.
- Optional `reasons` and `matched_rules` are sets of strings shown by `pdp explain`. `matched_rules` also appears in audit events.
- `input.identity` carries verified facts: `id` (`uid:<n>`, the SPIFFE ID, or `ip:<address>`), `auth_method` (`unix`, `spiffe` or `transparent`), and `uid`, `spiffe_id` or `ip`. The policy must name the callers it allows. Any UID that can open the socket, any workload in a trusted SPIFFE domain and any address that reaches a transparent listener reaches the policy and is refused only by default deny.
- `input.protocol` is `http`, `websocket` or `tunnel`. `input.destination` has `scheme`, `host` (lower case, no trailing dot), `port` and `addresses`.
- Policy runs before DNS resolution without `addresses`, then again with the exact addresses PDP will dial. A name the first evaluation denies is never resolved. Compare addresses with `net.cidr_contains` to refuse loopback, link-local or private ranges.
- `input.binding` is the credential that will be injected, absent when none will be. Allow a binding only for the callers that may use it.
- On an upstream with a schema, `input.plugin` is the schema name and `input.schema_digest` its digest. Compare the digest to a reviewed value so a changed schema denies until you review it. REST requests add `input.operations` and `input.http.path_params`, `normalized_query` and `body`. GraphQL requests add `input.graphql`, one entry per selected field.
- Without a schema the policy sees `input.http` with `method`, `path` and `query`, and nothing about the body.
- `http.send`, `net.lookup_ip_addr` and `opa.runtime` are unavailable. Optional static data goes in one JSON file named by `policy.data` and is read as `data.<key>`.

## CLI

```sh
bin/pdp validate --config pdp.json
bin/pdp explain --config pdp.json --input input.json
bin/pdp catalog --protocol rest --schema examples/packs/github-read/github-rest.json
bin/pdp catalog --protocol graphql --schema examples/packs/linear-read/linear.graphql
bin/pdp schema diff --protocol rest before.json after.json
bin/pdp request --socket /run/pdp/pdp.sock --method POST \
  --url https://api.linear.app/graphql --body query.json
```

`catalog` prints the schema digest and each operation's request contract. `schema diff` reports added, removed and changed operations. `explain` takes a trusted `pdp.authz/v2` input for administrator debugging. It is not a caller endpoint and contacts nothing. A denied explanation is normal output. `request` sends one absolute-form request over the Unix socket and exits nonzero on a non-2xx response.

`SIGHUP` validates and atomically publishes a new snapshot: policy, upstreams, schemas, credential bindings and adapters together. Use a new revision for each update. A failed reload keeps the previous snapshot. Removing a caller from the policy and reloading revokes it for every request that starts afterward, including requests inside an open `CONNECT`. An open tunnel, WebSocket or streamed response keeps the old snapshot until it ends or `limits.stream_timeout` passes. Listeners, interception, DNS, `ca_file` and limits need a restart.

## Limits of this version

- HTTP/1.1 only. HTTP/2 is not offered to callers or used upstream.
- DNS steering answers over UDP only. There is no DNS over TCP.
- WebSocket frames are relayed without inspection or credential scanning.
- Streamed responses are scanned for the raw credential bytes only. JSON-escaped forms are not caught on streams. A compressed response is refused when a credential was injected.

## More

- [Forward proxy behavior](docs/forward-proxy.md)
- [Packs](examples/README.md)
- [Configuration and limits](docs/configuration.md)
- [systemd, Kubernetes and Workload API setup](docs/deployment.md)
- [Acceptance commands and gaps](docs/acceptance.md)
- [Design](docs/design.md)
- [Security review record](docs/security-review.md)

```sh
go vet ./...
go test -race ./...
```

The tests run against local TLS servers and a local DNS server only. They are not evidence that any real provider accepts a request, that SPIRE, a Kubernetes cluster, cert-manager or trust-manager work with PDP, or that DNS steering and TLS interception cover every connection a real client makes. None of those has been run.
