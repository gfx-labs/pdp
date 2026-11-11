# PDP design

PDP is a standalone identity-aware credential gateway, not a Jobshop integration commitment. This document describes the design the code implements. It is not evidence that acceptance has passed. See [acceptance.md](acceptance.md) for what has and has not been run.

## Purpose and trust split

A workload calls GitHub REST or Linear GraphQL through PDP without receiving the provider credential. Three parts divide the work, and each trusts only what the previous part established:

| Part | Owns | Does not do |
| --- | --- | --- |
| Go | Authenticating the caller, parsing and normalizing the request, building `input`, enforcing limits, forwarding the approved request | Decide who may do what. Map identities to principals. Classify operations as safe or unsafe. |
| Rego | The authorization decision, from `input` and optional OPA data | Obtain credentials, make network calls, or see headers |
| Starlark | Obtaining a credential for the binding, after `allow` | See the request, the identity or the policy |

Administrators control routes, upstream origins, schemas, policy modules and data, adapters, secret references and credential bindings. Caller headers cannot establish identity, binding or destination.

Schemas describe operations but confer no permissions. Policy decides.

## Authentication

Go authenticates and reports verified facts. It holds no allowlist and does not map identities to principals.

- **Unix socket.** Linux `SO_PEERCRED` supplies the kernel UID. `input.identity` is `{id: "uid:<n>", auth_method: "unix", uid: <n>}`. No identity daemon or schema is needed for a minimal deployment. A shared UID is a shared identity.
- **SPIFFE mTLS (optional).** The maintained go-spiffe Workload API source supplies the SVID and trust bundle. Go checks the peer certificate against the current bundle on every request. `input.identity` is `{id: <spiffe id>, auth_method: "spiffe", spiffe_id: <spiffe id>}`. SPIFFE is not a replacement for the upstream credential.
- **systemd.** Socket activation hands PDP one Unix socket with administrator-set ownership and mode. PID, unit names and cgroups are not identities.

Every connecting UID and every workload the bundle verifies reaches policy, so a caller that policy does not name gets `403` from default deny. Socket file permissions and the trust bundle stay the outer boundary. An unauthenticatable connection (unreadable peer UID, unverified certificate) gets `401`.

## Request enforcement

1. Authenticate the connection.
2. Select the provider route from the path. Routes are `/upstreams/github/...` and `/upstreams/linear/graphql`.
3. Bound headers and body. Reject unsupported encodings, ambiguous paths, query and body forms, and unsupported protocols.
4. Normalize. With a pinned schema the request is validated against it and mapped to operation IDs, path parameters, typed query values and, for GraphQL, field occurrences. Without a schema Go produces only a coarse operation (`untyped:http:<METHOD>` or `untyped:graphql:<type>`).
5. Build `input` and evaluate `data.pdp.authz` in an immutable policy snapshot. Only a boolean `allow` of `true` authorizes. Anything else denies.
6. Only after `allow`, acquire a scoped credential from the cache or the Starlark adapter.
7. Build a fresh upstream request. Drop the local routing prefix, caller authorization, cookies and hop-by-hop headers. Apply the credential and forward the approved path and payload.
8. Return the bounded response with locally reconstructed headers. Reject responses that reflect the credential.
9. Emit an audit event with the snapshot, policy revision, schema digest, matched rules and outcome.

The default upstreams are `https://api.github.com` and `https://api.linear.app/graphql`. Origins come only from administrator configuration. Redirects are refused. Mutating requests are not retried. Response bytes, concurrency and all deadlines are bounded. Streaming, upgrades, GraphQL subscriptions and batching are rejected, not forwarded.

Out of scope: a credential-return endpoint, arbitrary caller URLs, response-field filtering, support for every GitHub CLI command, a browser consent UI, a multi-tenant admin platform, request-path schema introspection.

## Policy model

Rego is the only policy path. Administrators write modules in `package pdp.authz`:

```rego
package pdp.authz

import rego.v1

default allow := false

allow if { ... }

matched_rules contains "name" if allow
reasons contains "text" if not allow
```

`allow` is required and must be boolean. `reasons` and `matched_rules` are optional sets of strings that appear in `pdp explain` output, and `matched_rules` also appears in audit events. A missing, undefined, non-boolean or erroring result denies. The query runs with strict builtin errors. `http.send`, `net.lookup_ip_addr` and `opa.runtime` are removed and no network access is allowed. Optional OPA data comes from at most one JSON file and may not define `data.pdp.authz`.

Go provides no grant, profile, mode, constraint, deny, mandatory restriction, relationship or reviewed-operation registry. A policy that needs one writes it. Examples in `examples/packs` show a UID allowlist, a repository allowlist, reviewed operation IDs and a GraphQL occurrence walk.

What a policy author owns, because nothing else does:

- **Identity.** Compare `input.identity` with the callers allowed. A policy that does not gets whatever it wrote, which can be every caller who reaches the socket.
- **Schema pinning.** Compare `input.schema_digest` with the reviewed digest. A policy that omits it keeps allowing requests after a schema file changes. `pdp catalog` prints the digest and `pdp schema diff` compares two schemas.
- **Provider and binding.** Compare `input.provider` and `input.binding`.
- **Resources.** The GitHub repository is the exact `owner/repo` pair from `input.http.path_params`. A comment mutation's team ID is not proof of issue membership, so allow named issue UUIDs.
- **Every occurrence.** For GraphQL, `input.graphql` has one entry per selected field occurrence with coordinate, path and arguments. Aliases, fragments, variables and fields behind `@skip` or `@include` all appear. Repeated occurrences are separate entries, never merged into a coordinate-keyed map.

Parsed caller data stays untrusted even when structurally valid. Provider-state-dependent permissions need a trusted lookup, which PDP does not provide, so a policy cannot rely on them.

## Schema normalization

OpenAPI import supports a documented narrow subset. It produces stable operation IDs, methods, path templates, parameter and body references, and a machine-readable catalog. It matches paths deterministically, normalizes typed query values, validates bodies and fails import for unsupported security-relevant constructs. It does not claim full OpenAPI compatibility.

GraphQL uses a pinned schema and a dedicated Go parser and validator. It selects `operationName`, validates operations, expands fragments, resolves aliases to schema coordinates, coerces variables and defaults, and records all selected fields including conditional ones. It rejects batches, subscriptions and unresolved constructs.

Schema digests appear in `input.schema_digest`, decisions and audit events. `pdp schema diff` reports added, removed and changed operations. A new schema operation grants nothing, because policy must name it. See [pkg/schema/README.md](../pkg/schema/README.md).

## Credential engine

Adapters are trusted administrator code, not policy and not workload-supplied programs. Native helpers give them secret handles, opaque JWT signing, bounded HTTPS to configured endpoint aliases, bounded JSON and token parsing, and typed credential results. Policy never sees any of it.

Go owns mounted and systemd credential loading, TLS validation, fixed destinations, redirect refusal, deadlines, step budgets, bounded inputs and results, concurrency, cache keys, expiry margins, single-flight refresh, invalidation and redaction. Cache keys include provider, binding and requested scope. A new snapshot gets a new cache. Starlark is not a hard memory sandbox. An untrusted adapter would need a separate resource-limited process.

Supported flows: a static mounted token, a GitHub App installation token limited to administrator repository IDs and permissions, Linear client credentials (app actor), and a pre-authorized Linear refresh-token installation. Linear actor and flow are explicit. Rotating refresh state is serialized and written atomically and durably before the access token counts as a success. See [pkg/credential/README.md](../pkg/credential/README.md).

## Reload and revocation

A reload builds a complete new snapshot (policy, schemas, routes, bindings, credential manager) and publishes it atomically. A request uses exactly one snapshot. After `reload_applied` for a revision, every authorization that begins afterward uses it. Requests already authorized may finish within their deadlines. There is no positive authorization cache, so a warm provider token cannot outlive a policy change.

This is a local snapshot boundary. It does not revoke issued provider tokens or undo in-flight provider actions, and it gives no multi-replica consistency. Revocation across replicas needs an acknowledgement from each, or stale replicas must stop serving. Listener, limit and CA settings need a restart.

## Operational delivery

The `pdp` CLI provides `serve`, `validate`, `explain`, `catalog`, `schema diff` and `request`. Configuration is JSON (`pdp.config/v2`) referencing `.rego`, schema and adapter files. Ready-to-edit packs in `examples/packs` cover Unix and SPIFFE callers, GitHub and Linear, and read or comment use. The `systemd` pack has service and socket units, and the `github-spiffe` pack has a Kubernetes manifest. Neither has been applied. See [deployment.md](deployment.md) and [configuration.md](configuration.md).

## Acceptance matrix

Focused tests and the real CLI cover the local items. Real provider reads and writes, SPIRE and Kubernetes are not covered. See [acceptance.md](acceptance.md) for the current mapping.

- Default deny: an undefined, non-boolean or failing policy result denies, and a denied request never acquires a credential or reaches the provider.
- A named UID is allowed and another UID is denied, over a real Unix socket.
- A verified SPIFFE ID the policy does not name is denied. Rotation of the source SVID and bundle is exercised against a local Workload API server.
- Forged identity headers are ignored.
- Unknown REST operations and GraphQL fields are denied by the shipped policies.
- Aliases, fragments, operation selection, variables and defaults, and repeated selections are separate occurrences.
- Encoded paths, duplicate parameters and body and content-type ambiguity are rejected before policy.
- Redirects and caller URLs cannot redirect a credential.
- Concurrent requests share one acquisition. Expiry and failed refresh fail closed.
- Rotated refresh state survives a process restart.
- Reload swaps the whole snapshot. Rewriting the Rego file and sending `SIGHUP` revokes a warm credential cache.
- Logs, errors and responses do not reveal provider credentials.

Real provider reads, SPIRE issuance and rotation, Kubernetes deployment and all-replica revocation are externally blocked until credentials and infrastructure exist. Local tests do not establish them. Real writes need explicit approval for named disposable resources.
