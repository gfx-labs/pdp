# PDP design and acceptance contract

PDP is a standalone identity-aware credential gateway, not a Jobshop integration commitment. This document records the implementation requirements, not evidence that acceptance has passed. See the acceptance report for measured results and external gaps.

## Purpose and trust boundaries

A workload calls GitHub REST or Linear GraphQL without receiving upstream credentials. The Go gateway authenticates callers, normalizes operations, evaluates embedded OPA, obtains a credential through a bounded administrator-owned Starlark adapter, and forwards only the approved request. Schemas describe operations but confer no permissions. SPIRE runs separately when selected.

Supported authentication modes feed one policy decision path:

- Unix-domain HTTP with Linux `SO_PEERCRED` verified by the kernel and administrator UID-to-principal mapping. No identity daemon or schema is needed for a minimal full-access deployment. Shared UIDs share identity.
- systemd deployment with explicit socket ownership, permissions and socket activation. Do not infer session isolation from PID, unit names, cgroups or caller labels.
- Optional SPIFFE mTLS using the maintained Go SPIFFE Workload API library. Verify peer identity and handle certificate rotation. SPIFFE is not an upstream credential replacement.

Only administrators control routes, upstream origins, identity maps, credential bindings, schema versions, policies, adapters, secret references and relationship snapshots. Caller headers cannot establish identity, binding, destination or resource grants.

## Request enforcement

1. Authenticate the connection using verified peer credentials.
2. Resolve an explicit provider route and credential binding.
3. Bound headers and body. Reject unsupported encodings, ambiguous paths/query/body forms and unsupported protocols.
4. Normalize and validate against the pinned schema when required by the selected restricted grant.
5. Evaluate the complete normalized request using an immutable versioned authorization snapshot.
6. Only after allow, acquire a scoped credential from its cache or adapter.
7. Remove local routing prefix, caller authorization and hop-by-hop headers. Inject the credential and forward the approved provider path/payload.
8. Return the bounded provider response after removing sensitive headers.
9. Emit a sanitized decision and outcome event with snapshot/schema/grant revision metadata.

Routes are `/upstreams/github/...` and `/upstreams/linear/graphql`. Default origins are `https://api.github.com` and `https://api.linear.app`; the latter route forwards `/graphql`. Origins come exclusively from administrator configuration. Refuse redirects. Do not retry mutating requests. Bound response bytes, concurrency and all connection/request deadlines. Reject streaming, upgrades, GraphQL subscriptions, batching and unsupported features rather than forwarding silently.

No credential-return endpoint, arbitrary caller URL, response-field filtering, transparent support for every GitHub CLI command, browser consent UI, multi-tenant admin platform or request-path schema introspection is in scope.

## Progressive permissions

Three supported deployment levels use the same authorization path:

1. `full`: one identity and one binding, no schemas, custom Rego, relationships or task placeholders required. All supported bounded valid HTTP operations on that binding are allowed, including destructive/admin operations within the provider credential scope. This never grants other bindings, destinations, gateway administration or secret retrieval.
2. `read` and `read_write`: built-in reviewed provider operation mappings and optional direct resource allowlists, without custom Rego or graph configuration. Unknown operations deny. Never classify from HTTP verbs or GraphQL query/mutation syntax alone. `read_write` excludes destructive/admin operations unless separately explicitly granted.
3. Fine-grained restrictions: operation/argument constraints, custom Rego and optional relationship requirements on selected grants.

Each grant's constraints are conjunctive. Direct grants do not require graph data. Explicit denies and mandatory deployment restrictions override every allow, including full grants. Diagnostics must expose overlapping broad grants, so a narrow grant is not mistaken for a restriction on an existing broad allow. An explanation command shows identity, binding, profile, effective direct resources and optional advanced constraints. Moving between levels preserves identity and API routing.

## Schema normalization

OpenAPI import deliberately supports a documented narrow subset. Produce stable operation IDs, methods, path templates, parameter/body references and a machine-readable catalog. Deterministically match paths, normalize typed query values, validate bodies and fail import for unsupported security-relevant constructs. Do not claim complete OpenAPI compatibility.

GraphQL uses a pinned schema and a dedicated Go parser/validator if OPA alone cannot establish the required contract. Select `operationName`, validate operations, expand fragments, resolve aliases to actual schema coordinates, coerce variables and defaults, and conservatively authorize all selected fields including conditional selections. Reject batches, subscriptions and unresolved constructs. Every selected nested field must be considered. Preserve repeated field occurrences as a list containing coordinate, path and normalized arguments, never merge distinct calls into one coordinate-keyed arguments map.

Record schema digests in decisions, generate catalog diffs on schema changes, fail validation on unknown operation references and never automatically grant new schema operations. Ship pinned real provider/schema inputs with provenance, not only toy schemas.

REST or GraphQL validation does not establish resource authorization. Policies constrain repositories, issue IDs, teams and input fields as applicable. Provider-state-dependent permissions need an explicit trusted lookup or must deny. Initial GitHub access is read/comment in one designated repository. Initial Linear access is reads/comments in explicit approved issue scope. A comment mutation's team ID is not proof of issue membership. Use an issue allowlist until a trusted resource lookup exists.

## Versioned authorization input

The trusted envelope includes version, verified identity, provider, credential binding, schema digest, HTTP method/path and normalized operations. GraphQL field occurrences retain distinct paths and argument sets. Parsed caller data remains untrusted even when structurally valid. Evaluation errors, missing required data, unknown restricted operations and expired/unavailable policy deny.

## Optional fixed relationships and revocation

Use a small local relationship model, not a general graph engine or external service initially:

- verified worker identity -> assigned task
- task -> permitted GitHub repository or Linear issue
- each permission is explicit, such as read or comment, with expiry

Only administrator configuration or an authenticated controller supplies records. Caller task selections must be verified against assignment. Caller bodies, labels and schema information cannot establish relationships. Repository membership never implies administration.

Load a versioned relationship snapshot atomically with route/schema/policy/adapter configuration. Include its revision in audit records. Avoid positive authorization caching. Every request checks current grants even when reusing a provider token. Required stale or unavailable relationship state fails closed, without imposing graph requirements on unrelated direct grants.

After a new revision is acknowledged, every authorization beginning afterward uses that revision. Already authorized requests may finish within existing deadlines. This is a local snapshot boundary, not Zanzibar distributed consistency. Multi-replica acknowledgement must cover all serving replicas or stale replicas must stop accepting traffic. Removing grants does not revoke issued provider tokens or undo in-flight provider actions. Consider SpiceDB/OpenFGA behind a narrow interface only if a shared relationship service becomes necessary.

## Credential engine

Adapters are trusted administrator code, not policy or workload-supplied programs. Small host capabilities provide secret-reference access, opaque approved JWT signing, bounded HTTPS to configured destinations, bounded JSON/token parsing and typed credential results. Prefer opaque secret handles. If raw values enter trusted code, document the trust implication. Never include secret values in interpreter errors, debug output or HTTP failures.

Go owns mounted/systemd credential loading, TLS validation, fixed destinations and redirect refusal, deadlines, instruction budgets, bounded inputs/results, concurrency, cache keys, expiry margins, single-flight refresh, invalidation and redaction. Cache keys include provider, binding and requested scope. Snapshot changes must not reuse credentials across changed adapter/secret/scope contexts. Starlark is not a hard memory sandbox. Untrusted adapters would require a separately resource-limited process.

GitHub App support signs an App JWT through opaque key access and exchanges it for an installation token restricted to administrator repository IDs and permissions. A static mounted credential supports the vertical slice.

Shared OAuth primitives handle client credentials and refresh exchanges. Linear actor and flow must be explicit. Client credentials for an app actor are not interchangeable with a user-authorized installation, and must not silently replace an existing installation. Pre-authorized refresh state can seed the prototype without implementing browser consent. Rotating refreshes serialize, and replacement state must be atomically persisted durably before the access token is treated as successful. Restart must not lose a rotated refresh token.

## Operational delivery

Ship a usable CLI for configuration validation, Rego compilation, policy explanation, catalog generation/diff and local request exercise. Include minimal full-access and read-only examples first, plus read/write examples and documented exact profile contents. Configuration reload replaces immutable route/schema/policy/adapter/grant snapshots atomically. An in-flight request retains one consistent snapshot. Provide hardened systemd/socket units and mounted/systemd secret examples.

Provide Kubernetes manifests and a Workload API/service-account attestation guide without applying them. Document trusted selector requirements and Jobshop sandbox mounts/environment without changing Jobshop. Actual UID/unit/cgroup selectors must be established before later per-session integration.

## Acceptance matrix

Keep focused security regressions and real local socket/TLS integration checks. Use recorded real provider/schema inputs where feasible. Real writes require explicit approval for named disposable resources.

- Missing, untrusted and wrong identity deny; forged identity headers are ignored.
- Binding selection cannot escape grants.
- Unknown REST operations and GraphQL fields deny under restricted profiles.
- Aliases, fragments, operation selection, variables/defaults and repeated selections cannot bypass authorization.
- Encoded paths, duplicate parameters and body/content-type ambiguity cannot change the authorized operation.
- Forbidden requests never reach the provider.
- Redirects and caller URLs cannot exfiltrate credentials.
- Concurrent requests do not cause refresh storms.
- Expiry and failed refresh fail closed without cached credential leakage.
- Rotated refresh state survives the required persistence/restart boundary.
- Reload never mixes schema/policy/adapter/identity/grant versions.
- Logs, errors and caller responses do not reveal provider credentials.
- Gateway/caller certificate rotation works without replacing upstream tokens.
- Full mode works without schema/task/graph files, and remains confined to its upstream/binding.
- Read and read/write work without custom Rego or relationships; unknown operations deny.
- Optional relationship requirements are mandatory only for their selected grants.
- Assigned, unassigned, forged-context, expired and cross-task resource cases follow explicit permissions.
- Revocation applies at the acknowledged revision boundary with a warm credential cache.
- Audit identifies the schema and grant revisions used.

Run gofmt, build, vet and race tests. Measure gateway idle/active RSS and CPU, authorized-request latency and credential-refresh latency. Measure SPIRE server and agent separately when running them. Never infer the combined deployment is lightweight from gateway measurements alone. Real provider reads, SPIRE deployment/certificate lifecycle and Kubernetes acceptance must be explicitly identified as externally blocked if the needed credentials or infrastructure are unavailable, not claimed passed by local tests.
