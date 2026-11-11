# Forward proxy design

Status: proposal. Nothing here is implemented. The current gateway serves `/upstreams/github/...` and `/upstreams/linear/graphql` only.

## Goal

PDP becomes an explicit forward proxy for any HTTP destination. Every request is authorized by Rego with the verified caller identity. A destination with no protocol plugin is still usable through host, port, method and path rules. A plugin adds operations, fields and resources to the same policy input when finer rules are wanted.

Not in scope: TPROXY steering, non-HTTP protocols other than opaque tunnels, and response filtering beyond the credential scan.

## Caller transports

| Transport | Identity | Request forms |
| --- | --- | --- |
| SPIFFE mTLS listener | SPIFFE ID verified against the Workload API bundle | absolute-form and `CONNECT` |
| Unix socket | kernel peer UID | absolute-form and `CONNECT` |

Identity facts reach Rego as they do today: `input.identity.id`, `auth_method`, `uid`, `spiffe_id`. There is no identity map in Go.

Two request forms are accepted on both listeners:

- **Absolute-form** (`GET https://api.example.com/v1/x`). The caller's connection to PDP is already authenticated and, on the SPIFFE listener, encrypted. PDP opens the upstream TLS connection itself. No interception CA is involved.
- **`CONNECT host:port`**. This is what an unmodified client with `HTTPS_PROXY` sends. PDP either intercepts the inner TLS or relays it opaquely, per destination.

## TLS handling for `CONNECT`

| Mode | What PDP sees | Credential injection | Needs workload to trust PDP's CA |
| --- | --- | --- | --- |
| `intercept` (default) | full request | yes | yes |
| `tunnel` | host and port only | no | no |

In `intercept` mode PDP mints a leaf certificate for the requested host, signed by its interception CA, and serves the inner connection as HTTP/1.1. Leaves are cached in a bounded LRU and are short-lived. In `tunnel` mode Rego is asked once with `protocol: "tunnel"` and bytes are relayed after allow.

## Policy input

The generic tier is present on every request:

```json
{
  "version": "pdp.authz/v2",
  "identity": {"id": "spiffe://example.org/ns/agents/sa/worker", "auth_method": "spiffe", "spiffe_id": "spiffe://example.org/ns/agents/sa/worker"},
  "protocol": "http",
  "destination": {"scheme": "https", "host": "api.stripe.com", "port": 443, "addresses": ["198.51.100.7"]},
  "tls": "intercept",
  "http": {"method": "POST", "path": "/v1/charges", "query": {}},
  "binding": "",
  "plugin": ""
}
```

`protocol` is `http`, `websocket` or `tunnel`. `destination.addresses` are the addresses PDP resolved and will dial, so a rule can refuse loopback, link-local and cluster ranges and a later DNS answer cannot change the target. `http` is absent for `tunnel`.

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

When an upstream names a plugin, the plugin validates the request against its pinned schema and adds the fields policies already use: `schema_digest`, `operations`, `graphql`, `http.path_params`, `http.normalized_query` and `http.body`. A plugin that rejects a request as malformed denies it before Rego runs, as schema validation does today. The existing GitHub REST and Linear GraphQL normalizers become the first two plugins.

## Runtime configuration

`routes` is replaced by `upstreams`, matched by exact host and port. An upstream entry only attaches a binding, plugin or TLS mode. It is not an allowlist. A destination with no entry is still evaluated by Rego with the generic input, in `intercept` mode and with no credential, so the policy is the only place that accepts or refuses a host. A policy can match by suffix or pattern:

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
  "upstreams": [
    {"host": "api.github.com", "binding": "github-repo", "plugin": "github-rest", "schema": "github"},
    {"host": "api.stripe.com", "binding": "stripe"},
    {"host": "db.internal.example.com", "port": 5432, "tls": "tunnel"}
  ],
  "policy": {"modules": ["policy.rego"]}
}
```

`certificate_file` holds the interception CA certificate followed by any intermediates up to, but not including, the root the workloads trust. A binding on a `tunnel` upstream is a configuration error.

## DNS steering

For clients that cannot be given a proxy setting, PDP runs a DNS server and transparent listeners on ports 80 and 443.

- **Only configured names are intercepted.** A name is answered with PDP's address when it is a host in `upstreams` or matches a pattern in `dns.intercept`. PDP does not claim names nobody configured.
- **Everything else follows one setting.** `dns.unlisted` is `forward` (resolve through the real resolver, the default) or `refuse` (answer REFUSED). `refuse` is the deny-all rule. It is not enforcement on its own, because a client can connect to an IP literal, so the egress `NetworkPolicy` is still required.
- **Identity is weaker.** A transparently steered client believes it is talking to the destination and presents no client certificate. Rego receives `auth_method: "transparent"` and `identity.ip`. The policy has to map source addresses to workloads, and that mapping is only as good as the network's protection against address spoofing.
- **Destination comes from SNI or `Host`**, never from the address the client connected to. The transparent TLS listener always intercepts, so it needs the interception CA.

```json
"dns": {
  "listen": ":53",
  "address": "10.16.0.1",
  "intercept": ["*.githubusercontent.com"],
  "unlisted": "forward"
}
```

## Credentials

The adapter runs only after allow, and the caller never chooses a credential by itself. Caller-supplied `Authorization`, `Proxy-Authorization` and every header the binding injects are removed before injection.

### Placeholders and several accounts on one host

A client such as Jcode needs something in its credential slot to start, and one provider endpoint can serve several accounts. Both are handled the same way:

- An upstream may list several bindings. Each binding may declare a `placeholder`, an opaque non-secret string given to the workload in place of the real token.
- PDP reads the placeholder from the request's auth fields and uses it only to pick the candidate binding, which reaches Rego as `input.binding`. With one binding on the upstream, that binding is the candidate and no placeholder is needed.
- The placeholder is a routing hint, not authorization. Rego must explicitly allow that binding for the verified identity, for example from the run's grants in OPA data. A caller that sends another account's placeholder is denied unless policy grants it that binding.
- No matching placeholder on a multi-binding upstream means no candidate, so nothing is injected.

```rego
allow if {
	input.destination.host == "api.anthropic.com"
	input.binding in data.run_grants[input.identity.spiffe_id].bindings
}
```

### Subscription auth

- **Every auth field is replaced.** An adapter result can set several headers, for example a bearer token and an account ID header. The caller's values for all of them are dropped, so a placeholder or a stale account header never reaches the provider.
- **PDP owns the refresh.** Real access and refresh tokens stay in the binding's state file and are refreshed by the adapter. A refresh request from the client to a configured `token_paths` entry is answered locally with the placeholders and an expiry. It is never forwarded, so no provider response carrying real tokens reaches the workload.
- **Responses are scanned for the real credential**, including streamed ones (see below).

Untested assumptions: that Jcode accepts each provider's placeholder in the format that provider's client code expects, and that DNS and TLS interception cover every connection a subscription client makes.

## WebSocket and streaming

The upgrade request is authorized and injected like any other request, then frames are relayed without inspection. Streaming responses are relayed as they arrive. Both are bounded by idle timeout, maximum duration and the concurrency limit, and the audit event records bytes in each direction.

Buffered responses are scanned whole for the injected credential, as today. Streamed responses on an upstream with a binding get a sliding-window scan for the same byte patterns, since subscription model APIs answer with event streams. Upgraded WebSocket frames are not scanned, so an upstream that echoes its credential inside a WebSocket would not be caught.

## Kubernetes and cert-manager

- **Interception CA.** A cert-manager `Certificate` with `isCA: true`, issued by a private root `Issuer`, written to a Secret mounted only into the PDP pod. PDP rereads the files on `SIGHUP` and when they change.
- **Workload trust.** trust-manager `Bundle` publishes the private root, with the public roots, as a ConfigMap in selected workload namespaces. Workloads mount it and point `SSL_CERT_FILE` or the runtime's equivalent at it. Because workloads trust the root and PDP serves the intermediate in its chain, cert-manager can renew the intermediate without touching workloads.
- **Scope of the CA.** Setting `nameConstraints` on the CA `Certificate` limits the hosts PDP can impersonate to the ones it is meant to intercept. Clients enforce this, so check the constraint support of the workload's TLS library and the cert-manager feature gate for the installed version.
- **Bypass.** A `NetworkPolicy` that allows workload egress only to PDP and DNS is what makes the default deny real. PDP cannot stop a pod that has a direct route out.
- **Caller identity.** SPIRE stays as it is for SVIDs. cert-manager is not used for workload identity in this design.

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

Outside Kubernetes the same two files come from any CA tooling. The systemd pack would load the key as a systemd credential.

## Security notes

- The interception CA key lets its holder impersonate every permitted host to every workload that trusts the root. It is as sensitive as the provider credentials and gets the same file permissions and separate-UID rule.
- `CONNECT` to a port is not proof of protocol. In `intercept` mode a non-TLS or non-HTTP inner stream is closed.
- Redirects are still not followed. HTTP/2 to the caller is not offered in the first version, so inner connections negotiate HTTP/1.1.
- Hop-by-hop and proxy headers are removed in both directions.

## Open questions

1. Many HTTP libraries cannot present a client certificate to an HTTPS proxy. Workloads using them need the Unix socket or a small local forwarder that holds the SVID. Whether PDP should ship that forwarder is undecided.
2. Whether `pdp.authz/v1` input stays accepted for one release so existing packs keep working, or packs move to v2 in the same change.

## Order of work

1. Generic input, `upstreams` config and absolute-form requests on both listeners. Existing normalizers move behind the plugin interface. Packs move to the new input.
2. `CONNECT` with `tunnel` mode.
3. `CONNECT` with `intercept` mode, leaf minting and CA reload.
4. WebSocket upgrade and streamed responses.
5. DNS server and transparent listeners.
6. Several bindings per upstream, placeholders, multi-header adapter results, local token-endpoint answers and the streamed credential scan.
7. Kubernetes pack with cert-manager, trust-manager and NetworkPolicy manifests, validated against a real cluster only with explicit authorization.
