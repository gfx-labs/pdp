# Forward proxy

Status: implemented on the `forward-proxy` branch. This document started as the approved proposal. It now describes what the code does. Where the code differs from the proposal, the differences are listed in [Changes from the proposal](#changes-from-the-proposal). Tests run against local TLS servers and a local DNS server only. See [What has not been established](#what-has-not-been-established).

PDP used to serve two fixed routes, `/upstreams/github/...` and `/upstreams/linear/graphql`. It is now a forward proxy for any HTTP destination. Every request is authorized by Rego with the verified caller identity. A destination with no schema is still usable through rules on host, port, method and path. A schema adds operations, fields and resources to the same policy input when finer rules are needed.

Not in scope: TPROXY steering, protocols other than HTTP/1.1 and opaque tunnels, HTTP/2, and response filtering beyond the credential scan.

## Caller transports

| Transport | Identity | Request forms |
| --- | --- | --- |
| Unix socket | Kernel peer UID | absolute-form and `CONNECT` |
| SPIFFE mTLS listener | SPIFFE ID verified against the Workload API bundle | absolute-form and `CONNECT` |
| Transparent HTTP and HTTPS listeners | Source IP only | origin-form, destination from `Host` and SNI |

Identity facts reach Rego as `input.identity`: `id`, `auth_method` (`unix`, `spiffe` or `transparent`), and `uid`, `spiffe_id` or `ip`. There is no identity map in Go. A connection on a transparent listener is never promoted to a Unix or SPIFFE identity.

- **Absolute-form** (`GET https://api.example.com/v1/x HTTP/1.1`). The caller's connection to PDP is already authenticated and, on the SPIFFE listener, encrypted. PDP opens the upstream TLS connection itself. No interception CA is involved. `pdp request --url` sends this form.
- **`CONNECT host:port`**. This is what an unmodified client with `HTTPS_PROXY` sends. PDP intercepts the inner TLS, or relays it unread for an upstream with `"tls": "tunnel"`.
- **Transparent.** A DNS-steered client connects to PDP as if it were the destination. On TLS, `Host` must name the same host as SNI, or the request is refused with `400`. The destination never comes from the address the client connected to.

## TLS handling for `CONNECT`

| Mode | What PDP sees | Credential injection | Workload must trust PDP's CA |
| --- | --- | --- | --- |
| `intercept` (default) | every request inside | yes | yes |
| `tunnel` | host and port only | no | no |

In `intercept` mode PDP answers `200`, then reads the first byte. `0x16` starts a TLS handshake with a leaf for the `CONNECT` host, signed by the `interception` CA. Anything else is read as plain HTTP. Requests inside are served as HTTP/1.1. Each is authenticated again (a SPIFFE certificate is rechecked against the current bundle), authorized on its own and gets the credential like any other request. A request inside that names a different host or port in `Host` or in an absolute URL is refused with `400`. Inner requests use the snapshot current when each starts, so a reload applies inside an open `CONNECT`.

Leaves are ECDSA P-256, valid for at most 24 hours, cached in an LRU of 1024 and replaced one hour before expiry. Without an `interception` section, `CONNECT` to anything but a tunnel upstream gets `403 interception_unavailable`.

In `tunnel` mode Rego is asked with `protocol: "tunnel"`, scheme `tcp` and no `http`. After allow, PDP dials a pinned address and relays bytes both ways until either side closes or `stream_timeout` passes. An absolute-form or transparent request to a tunnel upstream is refused with `400`, because it would need the interception that entry turned off.

## Policy input

The generic part is present on every request:

```json
{
  "version": "pdp.authz/v2",
  "identity": {"id": "spiffe://example.org/ns/agents/sa/worker", "auth_method": "spiffe", "spiffe_id": "spiffe://example.org/ns/agents/sa/worker"},
  "protocol": "http",
  "destination": {"scheme": "https", "host": "api.stripe.com", "port": 443, "addresses": ["198.51.100.7"]},
  "http": {"method": "POST", "path": "/v1/charges"}
}
```

`protocol` is `http`, `websocket` or `tunnel`. `http` is absent for `tunnel`. `binding` is present only when a credential will be injected. `plugin`, `schema_digest`, `operations`, `graphql`, `http.path_params`, `http.normalized_query` and `http.body` are present only on an upstream with a schema.

Policy is evaluated twice for a destination given by name:

1. Before DNS resolution, with no `addresses`. A denied name is never looked up.
2. After resolution, with `destination.addresses` set to the addresses PDP will dial, at most 16.

A new connection is dialed only to those addresses, so a second DNS answer cannot move it. A request that reuses an open upstream connection goes to the address that connection was dialed to, unless `limits.disable_upstream_reuse` is set. A rule can refuse loopback, link-local and cluster ranges. An IP literal skips the first evaluation. A token path request dials nothing and is evaluated once without addresses.

A boolean rule for a destination nobody has modelled:

```rego
package pdp.authz

import rego.v1

default allow := false

agents := {"spiffe://example.org/ns/agents/sa/worker"}

allow if {
	input.identity.spiffe_id in agents
	input.destination.host == "api.stripe.com"
	input.destination.port == 443
	input.protocol in {"http", "websocket"}
}
```

When an upstream names a schema, the request is validated against it and the policy gets the fields the earlier packs used: `plugin` (the schema name), `schema_digest`, `operations`, `graphql`, `http.path_params`, `http.normalized_query` and `http.body`. A request the schema rejects as malformed is refused with `400` before Rego runs. The GitHub REST and Linear GraphQL normalizers are the schemas the packs ship.

## Runtime configuration

`pdp.config/v3` replaces `routes` with `upstreams`, matched by exact host and port. A `pdp.config/v2` file is rejected. An upstream entry attaches one or more bindings, a schema, a TLS mode or token paths. It is not an allowlist. A destination with no entry is still evaluated by Rego with the generic input, intercepted when it arrives by `CONNECT`, and gets no credential. The policy is the only place that accepts or refuses a host. A policy can match by suffix or pattern:

```rego
allow if {
	input.identity.spiffe_id in agents
	glob.match("*.githubusercontent.com", ["."], input.destination.host)
	input.http.method in {"GET", "HEAD"}
}
```

`input.destination.host` is lower-cased with any trailing dot removed, so a pattern cannot be bypassed by spelling.

```json
{
  "version": "pdp.config/v3",
  "revision": "proxy-v1",
  "transport": {
    "unix_socket": "/run/pdp/pdp.sock",
    "socket_mode": "0660",
    "spiffe": {"address": ":8443", "workload_api": "unix:///run/spire/sockets/agent.sock"}
  },
  "interception": {
    "certificate_file": "/run/pdp/ca/tls.crt",
    "key_file": "/run/pdp/ca/tls.key"
  },
  "schemas": {
    "github": {"protocol": "rest", "file": "github-rest.json"}
  },
  "upstreams": [
    {"host": "api.github.com", "binding": "github-repo", "schema": "github"},
    {"host": "api.stripe.com", "binding": "stripe"},
    {"host": "db.internal.example.com", "port": 5432, "tls": "tunnel"}
  ],
  "credentials": {"providers": {}, "bindings": {}},
  "policy": {"modules": ["policy.rego"]}
}
```

This shape needs the `github-repo` and `stripe` bindings defined under `credentials` before it validates. See [configuration.md](configuration.md) for a complete file that passes `pdp validate`.

`certificate_file` holds the interception CA certificate followed by any intermediates up to, but not including, the root the workloads trust. A binding, schema or token path on a `tunnel` upstream is a configuration error. A binding or schema is never used over plain `http`.

## Request handling

**Schema-backed upstreams** keep the strict handling of the route-based gateway: bounded JSON request bodies, no compression, no upgrades, a fresh header set with no caller headers, and a buffered JSON-only response within `max_response_bytes` that is scanned whole for the credential, including JSON-escaped forms. A redirect from such an upstream is refused.

**Every other destination** is relayed as a stream. Any method other than `CONNECT`, any content type and any body are forwarded. Hop-by-hop and proxy headers are removed in both directions. The response streams back with its own status, headers and encoding. A redirect is returned to the caller and never followed. Every upstream request uses a fresh HTTP/1.1 connection.

## DNS steering

For clients that cannot be given a proxy setting, PDP runs a DNS server and transparent listeners.

- **Only configured names are steered.** A name is answered with `dns.address` when it is a host in `upstreams` or matches a pattern in `dns.intercept` (exact name or `*.suffix`). PDP does not claim names nobody configured.
- **Everything else follows one setting.** `dns.unlisted` is `forward` (send the query unchanged to `dns.resolver`, the default) or `refuse` (answer `REFUSED`). `refuse` is the deny-all setting. It is not enforcement on its own, because a client can connect to an IP literal, so blocking direct egress is still required.
- **UDP only.** There is no DNS over TCP. A truncated answer that a client retries over TCP gets no reply from PDP.
- **Steered names are fixed at startup.** A reload that changes the set of steered names is rejected and needs a restart.
- **Identity is weaker.** A steered client believes it is talking to the destination and presents no client certificate. Rego receives `auth_method: "transparent"` and `identity.ip`. The policy has to map source addresses to workloads, and that mapping is only as good as the network's protection against address spoofing.
- **Destination comes from SNI and `Host`**, never from the address the client connected to. The transparent HTTPS listener always intercepts, so it needs the interception CA.

```json
"transport": {
  "transparent": {"http": ":80", "https": ":443"}
},
"dns": {
  "listen": ":53",
  "address": "10.16.0.1",
  "intercept": ["*.githubusercontent.com"],
  "unlisted": "forward",
  "resolver": "10.16.0.10:53"
}
```

## Credentials

The adapter runs only after allow, and the caller never chooses a credential by itself. Before injection PDP removes the caller's `Authorization`, `Cookie`, the header the adapter result sets, and every header whose value carries the binding's placeholder. It then sets the binding's fixed `headers` and the credential. On a destination with no binding, caller headers including `Authorization` are forwarded unchanged.

### Placeholders and several accounts on one host

A client such as Jcode needs something in its credential slot to start, and one provider endpoint can serve several accounts. Both are handled the same way:

- An upstream may list several `bindings`. Each binding may declare a `placeholder`, an opaque non-secret string given to the workload in place of the real token. With several bindings, or with `token_paths`, every binding must have a distinct placeholder.
- PDP finds the placeholder in a header value (whole value, last word as in `Bearer <placeholder>`, or user or password of a `Basic` value), or in the body of a token path request, and uses it only to pick the candidate binding. The candidate reaches Rego as `input.binding`. With one binding and no token paths, that binding is the candidate and no placeholder is needed.
- The placeholder is a routing hint, not authorization. Rego must allow that binding for the verified identity, for example from grants in OPA data. A caller that sends another account's placeholder is denied unless policy grants it that binding.
- No matching placeholder on a multi-binding upstream means no candidate, so nothing is injected and policy sees no `binding`.

```rego
allow if {
	input.destination.host == "api.provider.example"
	input.binding in data.run_grants[input.identity.id]
}
```

### Subscription auth

- **Every auth field is replaced.** A binding's `headers` add fixed values such as an account ID. The caller's values for them, its `Authorization` and `Cookie`, and any header carrying the placeholder are dropped, so a placeholder or a stale account header never reaches the provider.
- **PDP owns the refresh.** Real access and refresh tokens stay in the binding's adapter state. A request to a configured `token_paths` entry is answered locally after policy allows the binding, with `{"access_token": <placeholder>, "refresh_token": <placeholder>, "token_type": "Bearer", "expires_in": 3600}`. It is never forwarded, so no provider response carrying real tokens reaches the workload. Token paths need a binding and no schema.
- **Responses are scanned for the real credential**, including streamed ones (see below).

The `subscription` pack shows two accounts on one host.

## WebSocket and streaming

A WebSocket upgrade request is authorized with `protocol: "websocket"` and gets the credential like any other request. When the upstream answers `101`, PDP relays bytes both ways without inspecting frames. Streamed responses are relayed as they arrive and flushed after each read. Both are bounded by `limits.stream_timeout` (default 10 minutes) and the concurrency limit, and the audit event records `bytes_sent` and `bytes_received`. There is no separate idle timeout for an open stream.

Buffered responses on schema-backed upstreams are scanned whole for the injected credential, including Basic and JSON-escaped forms. Streamed responses on a credentialed destination are scanned for the same raw byte patterns as they pass, holding back only a trailing run that could be the start of a match. On a match the connection is cut before the credential is written, and the audit event records `credential_reflected`. JSON-escaped forms are not caught on streams. PDP sends `Accept-Encoding: identity` and refuses a compressed response when a credential was injected, because a scan of compressed bytes would find nothing. Response headers that carry the credential are also refused. WebSocket frames are not scanned, so an upstream that echoes its credential inside a WebSocket would not be caught.

## Kubernetes and cert-manager

Nothing in this section has been tried. It is the intended setup.

- **Interception CA.** A cert-manager `Certificate` with `isCA: true`, issued by a private root `Issuer`, written to a Secret mounted only into the PDP pod. PDP rechecks the files at most once a minute and reloads them when their modification time changes. A failed reload keeps the loaded CA.
- **Workload trust.** A trust-manager `Bundle` publishes the private root, with the public roots, as a ConfigMap in selected workload namespaces. Workloads mount it and point `SSL_CERT_FILE` or the runtime's equivalent at it. Because workloads trust the root and PDP serves the intermediate in its chain, cert-manager can renew the intermediate without touching workloads.
- **Scope of the CA.** Setting `nameConstraints` on the CA `Certificate` limits the hosts PDP can impersonate. Clients enforce this, so check the constraint support of the workload's TLS library and the cert-manager feature gate for the installed version.
- **Bypass.** A `NetworkPolicy` that allows workload egress only to PDP and DNS is what makes the default deny real. PDP cannot stop a pod that has a direct route out.
- **Caller identity.** SPIRE stays as it is for SVIDs. cert-manager is not used for workload identity.

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: pdp-interception-ca
  namespace: pdp
spec:
  isCA: true
  commonName: pdp-interception-ca
  secretName: pdp-interception-ca
  duration: 720h
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: pdp-private-root
    kind: Issuer
  nameConstraints:
    critical: true
    permitted:
      dnsDomains: ["api.github.com", "api.linear.app", "api.stripe.com"]
```

Outside Kubernetes the same two files come from any CA tooling.

## Security notes

- The interception CA key lets its holder impersonate every permitted host to every workload that trusts the root. It is as sensitive as the provider credentials and gets the same file permissions and separate-UID rule. `pdp validate` does not read it.
- `CONNECT` to a port is not proof of protocol. In `intercept` mode an inner stream that is neither TLS nor HTTP/1.1 fails to parse and is closed.
- Redirects are never followed. HTTP/2 is not offered to callers or used upstream.
- Hop-by-hop and proxy headers are removed in both directions.
- A transparent caller is identified by source address only.

## Changes from the proposal

- The proposal listed a `tls` field in policy input. The code has none. Use `protocol` (`tunnel` for an opaque tunnel).
- The proposal had a separate `plugin` field in each upstream entry. The code uses `schema`, and `input.plugin` is the schema name.
- The proposal had adapter results set several headers. In the code an adapter result still sets one header. Extra fixed headers, such as an account ID, come from the binding's `headers`.
- DNS forwarding needs an explicit `dns.resolver` address. `unlisted: "forward"` without a resolver is rejected.
- The interception CA is reloaded on file change only, at most once a minute. `SIGHUP` does not reread it, and a change to the `interception` paths needs a restart.
- Streams and WebSockets have one maximum duration, `limits.stream_timeout`. There is no separate idle timeout.
- `pdp.authz/v1` input is not accepted. All packs moved to `pdp.authz/v2` in this change, which settles the proposal's second open question.

## What has not been established

- Any real provider. Tests use local TLS servers.
- SPIRE, a real Kubernetes cluster, cert-manager and trust-manager. None has been run with PDP.
- Whether Jcode accepts each provider's placeholder in the format that provider's client code expects.
- Whether DNS steering and TLS interception cover every connection a subscription client makes.
- HTTP/2 and DNS over TCP. Neither is implemented.

## Open questions

1. Whether streams need an idle timeout separate from `stream_timeout`.
2. Whether the streamed credential scan should also cover JSON-escaped forms, at the cost of holding back more bytes.
