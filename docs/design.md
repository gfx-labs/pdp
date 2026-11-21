# PDP design

PDP is a standalone identity-aware HTTP forward proxy that injects provider credentials. It is not a Jobshop integration commitment. This document describes the design the code implements. It is not evidence that acceptance has passed. See [acceptance.md](acceptance.md) for what has and has not been run, and [forward-proxy.md](forward-proxy.md) for request forms, interception, DNS steering and placeholders in detail.

## Purpose and trust split

A workload sends HTTP requests through PDP to any destination. PDP decides with the workload's verified identity whether each request may go, and for destinations with a credential binding, injects the credential so the workload never holds it. Three parts divide the work, and each trusts only what the previous part established:

| Part | Owns | Does not do |
| --- | --- | --- |
| Go | Authenticating the caller, reading the destination, parsing and normalizing the request, building `input`, resolving and pinning addresses, enforcing limits, forwarding or relaying the approved request | Decide who may do what or which hosts are reachable. Map identities to principals. Classify operations as safe or unsafe. |
| Rego | The authorization decision, from `input` and optional OPA data | Obtain credentials, make network calls, or see headers |
| Starlark | Obtaining a credential for the binding, after `allow` | See the request, the identity or the policy |

Administrators control upstream entries, schemas, policy modules and data, adapters, secret references, credential bindings, the interception CA and DNS steering. Caller headers cannot establish identity. A caller's placeholder can only select a candidate binding that policy must then allow.

Upstream entries and schemas confer no permissions. Policy decides.

## Authentication

Go authenticates and reports verified facts. It holds no allowlist and does not map identities to principals.

- **Unix socket.** Linux `SO_PEERCRED` supplies the kernel UID. `input.identity` is `{id: "uid:<n>", auth_method: "unix", uid: <n>}`. No identity daemon or schema is needed for a minimal deployment. A shared UID is a shared identity.
- **SPIFFE mTLS (optional).** The go-spiffe Workload API source supplies the SVID and trust bundle. Go checks the peer certificate against the current bundle on every request, including each request inside an open `CONNECT`. `input.identity` is `{id: <spiffe id>, auth_method: "spiffe", spiffe_id: <spiffe id>}`. SPIFFE is not a replacement for the upstream credential.
- **Transparent listeners (optional).** A DNS-steered client presents no identity. `input.identity` is `{id: "ip:<address>", auth_method: "transparent", ip: <address>}`. The address is only as trustworthy as the network's protection against spoofing. A transparent connection is never treated as a Unix or SPIFFE caller.
- **systemd.** Socket activation hands PDP one Unix socket with administrator-set ownership and mode. PID, unit names and cgroups are not identities.

Every connecting UID, every workload the bundle verifies and every address that reaches a transparent listener reaches policy, so a caller that policy does not name gets `403` from default deny. Socket file permissions, the trust bundle and the network stay the outer boundary. An unauthenticatable connection (unreadable peer UID, unverified certificate) gets `401`.

## Request enforcement

1. Authenticate the connection, again for every request.
2. Read the destination: the absolute URL, the `CONNECT` target, or `Host` and SNI on a transparent listener. Normalize the host to lower case without a trailing dot.
3. Look up the upstream entry for host and port. Without one, the request has no binding and no schema.
4. Bound headers and body. On a schema-backed upstream, validate strictly against the schema and normalize to operation IDs, path parameters, typed query values and GraphQL field occurrences. Otherwise check only framing, path and header shape.
5. Pick the candidate binding: the only binding, or the one whose placeholder the request carries.
6. Build `input` and evaluate `data.pdp.authz`. A denied name is never resolved.
7. Resolve the host, evaluate again with `destination.addresses`, and pin the dial to those addresses.
8. Only after `allow`, acquire the credential for the candidate binding.
9. Build the upstream request. On a schema-backed upstream it is a fresh request with no caller headers. Otherwise caller headers are kept minus hop-by-hop headers, and with a credential minus `Authorization`, `Cookie`, the adapter's header and any header carrying the placeholder. Apply the binding's fixed `headers` and the credential.
10. Send it over HTTP/1.1, on a reused upstream connection when one is idle. Return a buffered JSON response for a schema-backed upstream, or relay the response, WebSocket or tunnel as a stream. Scan for the credential.
11. Emit an audit event with the snapshot, principal, destination, binding, policy revision, schema digest, matched rules, outcome and byte counts.

A `token_paths` request stops after step 6: it is answered locally with the placeholder and never sent upstream. A `CONNECT` to a tunnel upstream is authorized once with `protocol: "tunnel"` and relayed unread. Any other `CONNECT` is intercepted, and each request inside goes through these steps.

Redirects are never followed. A request with a body is never sent twice. A bodiless read may be resent once when a reused connection fails, see [configuration](configuration.md#request-forms-and-handling). Concurrency is bounded. Bodies are bounded on schema-backed upstreams. HTTP streams and opaque tunnels are bounded by `stream_timeout`. A WebSocket handshake is bounded by `request_timeout`, but an upgraded connection lasts until either peer closes.

Out of scope: a credential-return endpoint, response-field filtering, HTTP/2, DNS over TCP, a browser consent UI, a multi-tenant admin platform, request-path schema introspection.

## Policy model

Rego is the only policy path and the only allowlist. Administrators write modules in `package pdp.authz`:

```rego
package pdp.authz

import rego.v1

default allow := false

allow if { ... }

matched_rules contains "name" if allow
reasons contains "text" if not allow
```

`allow` is required and must be boolean. `reasons` and `matched_rules` are optional sets of strings that appear in `pdp explain` output, and `matched_rules` also appears in audit events. A missing, undefined, non-boolean or erroring result denies. The query runs with strict builtin errors. `http.send`, `net.lookup_ip_addr` and `opa.runtime` are removed and no network access is allowed. Optional OPA data comes from at most one JSON file and may not define `data.pdp.authz`.

Go provides no grant, profile, mode, constraint, deny, mandatory restriction, relationship, reviewed-operation registry or destination allowlist. A policy that needs one writes it. Examples in `examples/packs` show a UID allowlist, a host allowlist with address ranges, a repository allowlist, reviewed operation IDs, a GraphQL occurrence walk and per-caller binding grants.

What a policy author owns, because nothing else does:

- **Identity.** Compare `input.identity` with the callers allowed. A policy that does not gets whatever it wrote, which can be every caller who reaches a listener.
- **Destination.** Compare `input.destination.host`, `port` and `scheme`. Any host can be requested.
- **Addresses.** Refuse private, loopback and link-local ranges in `input.destination.addresses` where they are not intended. The first evaluation has no addresses.
- **Binding.** Compare `input.binding`. With several bindings on one host, the caller's placeholder picks the candidate, and only policy decides whether the caller may use it.
- **Schema pinning.** Compare `input.schema_digest` with the reviewed digest. A policy that omits it keeps allowing requests after a schema file changes. `pdp catalog` prints the digest and `pdp schema diff` compares two schemas.
- **Resources.** The GitHub repository is the exact `owner/repo` pair from `input.http.path_params`. A comment mutation's team ID is not proof of issue membership, so allow named issue UUIDs.
- **Every occurrence.** For GraphQL, `input.graphql` has one entry per selected field occurrence with coordinate, path and arguments. Aliases, fragments, variables and fields behind `@skip` or `@include` all appear. Repeated occurrences are separate entries, never merged into a coordinate-keyed map.

Parsed caller data stays untrusted even when structurally valid. Provider-state-dependent permissions need a trusted lookup, which PDP does not provide, so a policy cannot rely on them.

## Schema normalization

A schema is attached to an upstream entry. OpenAPI import supports a documented narrow subset. It produces stable operation IDs, methods, path templates, parameter and body references, and a machine-readable catalog. It matches paths deterministically, normalizes typed query values, validates bodies and fails import for unsupported security-relevant constructs. It does not claim full OpenAPI compatibility.

GraphQL uses a pinned schema and a dedicated Go parser and validator. It selects `operationName`, validates operations, expands fragments, resolves aliases to schema coordinates, coerces variables and defaults, and records all selected fields including conditional ones. It rejects batches, subscriptions and unresolved constructs.

Schema digests appear in `input.schema_digest`, decisions and audit events. `pdp schema diff` reports added, removed and changed operations. A new schema operation grants nothing, because policy must name it. See [pkg/schema/README.md](../pkg/schema/README.md).

## Credential engine

Adapters are trusted administrator code, not policy and not workload-supplied programs. Native helpers give them secret handles, opaque JWT signing, bounded HTTPS to configured endpoint aliases, bounded JSON and token parsing, and typed credential results. Policy never sees any of it.

Go owns mounted and systemd credential loading, TLS validation, fixed endpoints, redirect refusal, deadlines, step budgets, bounded inputs and results, concurrency, cache keys, expiry margins, single-flight refresh, invalidation and redaction. Cache keys include provider, binding and requested scope. A new snapshot gets a new cache. Starlark is not a hard memory sandbox. An untrusted adapter would need a separate resource-limited process.

A binding can declare a non-secret `placeholder` for the workload to hold, and fixed non-secret `headers` such as an account ID. Placeholders route among several bindings on one host and answer `token_paths` requests locally, so a client's own refresh never returns a real token.

Supported flows: a static mounted token, a GitHub App installation token limited to administrator repository IDs and permissions, Linear client credentials (app actor), a pre-authorized Linear refresh-token installation, and generic OAuth client credentials and refresh. Linear actor and flow are explicit. Rotating refresh state is serialized and written atomically and durably before the access token counts as a success. See [pkg/credential/README.md](../pkg/credential/README.md).

Responses are scanned for the injected credential. A buffered schema-backed response is scanned whole, including Basic and JSON-escaped forms. A streamed response is scanned for raw bytes as it passes and the connection is cut on a match. A compressed response is refused when a credential was injected. WebSocket frames are not scanned.

## Interception and DNS steering

The `interception` CA signs a short-lived leaf per host so PDP can read requests inside `CONNECT` and on the transparent HTTPS listener. Workloads that use those paths must trust the CA's root. The key lets its holder impersonate any host the CA permits, so it has the same protection as provider secrets. Absolute-form requests need no CA.

The optional DNS server answers only upstream hosts and `dns.intercept` patterns with the gateway address, and forwards or refuses everything else. It is UDP only. Steering and interception do not stop a workload that has a direct route out. Egress must also be blocked outside PDP.

## Reload and revocation

A reload builds a complete new snapshot (policy, schemas, upstreams, bindings, credential manager) and publishes it atomically. A request uses exactly one snapshot. After `reload_applied` for a revision, every request that begins afterward uses it, including new requests inside an open intercepted `CONNECT`. A request already running keeps its snapshot. For a relayed HTTP stream or tunnel that lasts until it ends or `stream_timeout` passes. An upgraded WebSocket keeps its snapshot until either peer closes. There is no positive authorization cache, so a warm provider token cannot outlive a policy change for new requests.

This is a local snapshot boundary. It does not revoke issued provider tokens or undo in-flight provider actions, and it gives no multi-replica consistency. Revocation across replicas needs an acknowledgement from each, or stale replicas must stop serving. Listener, interception, DNS, limit and CA settings need a restart, and so does a change to the set of steered DNS names.

## Operational delivery

The `pdp` CLI provides `serve`, `validate`, `explain`, `catalog`, `schema diff` and `request --url`. Configuration is JSON (`pdp.config/v3`) referencing `.rego`, schema and adapter files. Packs in `examples/packs` cover Unix and SPIFFE callers, GitHub and Linear with schemas, schema-free egress, placeholder subscription accounts, and read or comment use. The `systemd` pack has service and socket units, and the `github-spiffe` pack has a Kubernetes manifest. Neither has been applied. See [deployment.md](deployment.md) and [configuration.md](configuration.md).

## Acceptance matrix

Focused tests and the real CLI cover the local items, against local TLS servers and a local DNS server. Real providers, SPIRE, Kubernetes, cert-manager and trust-manager are not covered. See [acceptance.md](acceptance.md) for the current mapping.

- Default deny: an undefined, non-boolean or failing policy result denies, and a denied request never acquires a credential or reaches the destination.
- A named UID is allowed and another UID is denied, over a real Unix socket.
- A verified SPIFFE ID the policy does not name is denied. Rotation of the source SVID and bundle is exercised against a local Workload API server.
- Forged identity headers are ignored.
- A destination with no upstream entry is decided by policy, gets no credential, and is never resolved when the name is denied. Policy sees the resolved addresses before the dial.
- `CONNECT` is intercepted and each inner request authorized. A request inside naming another host is refused. `CONNECT` without a CA is refused. A tunnel upstream is relayed unread.
- WebSocket upgrades are authorized and relayed. Streamed responses are relayed as they arrive, and a credential split across writes is caught.
- Placeholders select the binding, policy decides it, and token paths are answered locally without reaching the provider.
- A transparent caller is identified by IP, and `Host` must agree with SNI.
- DNS steers only configured names and forwards or refuses the rest.
- Unknown REST operations and GraphQL fields are denied by the shipped policies.
- Aliases, fragments, operation selection, variables and defaults, and repeated selections are separate occurrences.
- Encoded paths, duplicate parameters and body and content-type ambiguity are rejected before policy on schema-backed upstreams.
- Redirects cannot redirect a credential.
- Concurrent requests share one acquisition. Expiry and failed refresh fail closed.
- Rotated refresh state survives a process restart.
- Reload swaps the whole snapshot. Rewriting the Rego file and sending `SIGHUP` revokes a warm credential cache.
- Logs, errors and responses do not reveal provider credentials.

Real provider reads, SPIRE issuance and rotation, Kubernetes deployment, cert-manager and trust-manager, all-replica revocation, and whether steering and interception cover every connection a real subscription client makes are not established until credentials and infrastructure exist. Real writes need explicit approval for named disposable resources.
