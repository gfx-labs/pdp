# Configuration, policy and limits

## File contract

The runtime configuration is one JSON document with `"version": "pdp.config/v2"` and a nonempty `revision` that contains no CR, LF or NUL. YAML is rejected. The loader also rejects unknown fields, duplicate object keys, trailing data, invalid UTF-8 and a non-object root. `pdp validate`, `pdp explain` and `pdp serve` read `pdp.json` in the working directory unless `--config` names another file.

Paths in the file (`ca_file`, `unix_socket`, schema files, `script_file`, policy modules and data, `state_file`, secret `file` and `credentials_directory`) are relative to the directory of the configuration file, not the working directory. Never put credentials in the file, in an adapter, or in policy data.

Top-level fields:

| Field | Meaning |
| --- | --- |
| `version`, `revision` | Required. Give every deployment a new `revision`. Reload rejects a snapshot whose revision equals the active one. |
| `ca_file` | Optional PEM file added to the system roots for private HTTPS endpoints. Verification is never disabled. |
| `limits` | Gateway limits, see [Limits](#limits). |
| `transport` | `unix_socket`, `socket_mode`, and optional `spiffe` with `address` and `workload_api`. |
| `schemas` | Map of name to `{protocol: "rest" or "graphql", file}`. |
| `routes` | One entry per provider: `provider`, `binding`, optional `schema`, `upstream_url` and `scopes`. |
| `credentials` | Starlark adapters and bindings, see [Credentials](#credentials). |
| `policy` | `modules`: one or more `.rego` files. `data`: at most one JSON file. |

There are no other policy fields. Identity mapping, grants, profiles, constraints and relationships do not exist in the configuration. They are written in Rego.

### Transport

At least one of `unix_socket` and `spiffe` is required. `socket_mode` defaults to `0600` and must be an octal string with no bits outside `0770` and no world bits. The socket path must be absolute after resolution. PDP creates it directly and refuses an existing path, or adopts one inherited systemd socket whose path equals `unix_socket`. The socket's parent directory must be owned by root or the daemon, not be a symlink, and not be group or world writable.

`spiffe.address` is a TCP listen address. `spiffe.workload_api` must start with `unix:///`. The listener requires TLS 1.3 and a client certificate that verifies against the current Workload API bundle. Session tickets are disabled.

### Routes

There is at most one route per provider and at most two routes. The provider names are `github` and `linear`. The gateway serves `/upstreams/github/...` and `/upstreams/linear/graphql`. Default upstreams are `https://api.github.com` and `https://api.linear.app/graphql`. `upstream_url` must be a fixed HTTPS URL without credentials, query or fragment. GitHub requires an origin without a path. Linear requires the path `/graphql`. A GitHub route cannot name a GraphQL schema and a Linear route cannot name a REST schema. `scopes` is the scope set the credential adapter is asked for. Redirects and transport retries are disabled.

### What validation checks

`pdp validate` loads every referenced file, compiles schemas, Rego modules and adapters, checks the transport, routes and credential bindings, and builds a gateway snapshot. It prints `{"valid": true, "revision": ..., "diagnostics": []}`. `diagnostics` is always empty because Go does not analyze policy source.

Validation does not read secret contents, request a token, open the Workload API, bind a listener, or contact a provider. A binding that uses `systemd_credential` fails validation unless `credentials.credentials_directory` is set or `CREDENTIALS_DIRECTORY` is in the environment:

```sh
CREDENTIALS_DIRECTORY=/run/credentials/pdp.service \
  bin/pdp validate --config examples/packs/systemd/pdp.json
```

Missing secret files are therefore a runtime failure. Passing validation says nothing about provider reachability or account permissions.

## Policy

Authorization is Rego. Go does not compute candidate permissions or denials.

### Module contract

Every module must declare `package pdp.authz` and is parsed as Rego v1. Go queries `data.pdp.authz` once per request. The result must be an object with:

| Rule | Type | Meaning |
| --- | --- | --- |
| `allow` | boolean | Required. Only `true` authorizes. |
| `reasons` | set or array of strings | Optional. Returned in `pdp explain` output. |
| `matched_rules` | set or array of strings | Optional. Returned in `pdp explain` output and in audit events. |

Write `default allow := false`. If `allow` is undefined, evaluation reports an error and the request is denied. A non-boolean `allow`, a non-string element in `reasons` or `matched_rules`, an undefined result and a runtime error (builtin errors are strict) also deny. The request then receives `403 forbidden` and no credential is acquired. `pdp explain` prints `authorization evaluation failed` for these cases instead of a decision.

The compiler removes `http.send`, `net.lookup_ip_addr` and `opa.runtime` and allows no network access. Other OPA builtins remain, including `time.now_ns`, so a policy that uses the clock is re-evaluated on every request. There is no positive decision cache.

`policy.data` may name one JSON file whose root is an object. It is loaded as OPA data, so `data.<key>` is readable from the modules. It cannot define `data.pdp.authz`. Go gives the data no meaning. All numbers in input and data keep their exact JSON spelling, so large integer IDs are not rounded.

### Input

Go builds `input` from verified facts and normalized request data:

| Field | Content |
| --- | --- |
| `version` | `pdp.authz/v1` |
| `identity.id` | `uid:<n>` for a Unix peer, or the verified SPIFFE ID |
| `identity.auth_method` | `unix` or `spiffe` |
| `identity.uid` | Kernel peer UID, present for `unix` only |
| `identity.spiffe_id` | Verified SPIFFE ID, present for `spiffe` only |
| `provider`, `binding` | From the selected route |
| `schema_digest` | Digest of the route's schema, the empty string when the route has none |
| `http.method`, `http.path` | The provider-side method and path (`/graphql` for Linear) |
| `http.path_params` | Strings extracted by the REST schema, such as `owner`, `repo`, `issue_number` |
| `http.query`, `http.normalized_query` | Raw query values, and schema-typed values for schema-backed REST routes |
| `http.body` | Decoded JSON body, when there is one |
| `operations` | One `{id}` per normalized operation: a REST `operationId`, or one GraphQL field coordinate per selected field occurrence |
| `graphql` | GraphQL routes with a schema only: one entry per selected field occurrence with `coordinate`, `path` (response aliases), `arguments` |
| `operation_type`, `operation_name`, `variables` | GraphQL requests |

A route without a schema is not classified. A GitHub request gets the single operation `untyped:http:<METHOD>` and no path parameters. A Linear request gets `untyped:graphql:query` or `untyped:graphql:mutation`, must contain one operation with no fragments, directives, introspection or subscription, and is limited to 256 fields and depth 32. No `graphql` entries are produced for it.

Identity is established by Go before policy runs. Everything else about the caller is untrusted data, including headers, which are not passed to policy. `http.body`, `http.query` and `variables` are caller data even when schema-valid.

If `schema_digest` is present and a query key has no normalized value, Go denies before Rego runs.

### What the policy author must do

Go does not know which UIDs, SPIFFE IDs, repositories or operations are acceptable. The policy has to say.

- **Name callers.** Every local UID that can open the socket, and every workload whose certificate verifies against the trust bundle, reaches policy. A policy that does not compare `input.identity` allows all of them. An unnamed caller is refused with `403` by default deny. Socket file permissions and the trust bundle remain the outer boundary, and processes that share a UID share an identity.
- **Pin the schema.** Compare `input.schema_digest` with the digest of the reviewed schema (`bin/pdp catalog` prints it). A policy that omits this check keeps allowing requests after the schema file changes.
- **Check provider and binding.** A policy that omits `input.provider` or `input.binding` applies to every route.
- **Treat operation IDs as strings.** A misspelled ID never matches and nothing reports it. List the IDs with `pdp catalog`.
- **Check every occurrence.** For GraphQL, iterate `input.graphql` and require every entry to be allowed. Fields behind `@skip` or `@include`, aliases and repeated selections are all listed.

Checked-in policies are in [`examples/packs`](../examples/README.md). For example, `examples/packs/github-read/policy.rego` allows one Unix UID to run three reviewed read operations on one `owner/repo` under one schema digest. To see a decision without a server, write the input by hand and run:

```sh
bin/pdp explain --config examples/packs/github-read/pdp.json \
  --input examples/packs/github-read/explain/read-issue.json
bin/pdp explain --config examples/packs/github-read/pdp.json \
  --input examples/packs/github-read/explain/other-uid.json
```

The output has `allow`, `identity`, `provider`, `binding`, `schema_digest`, `revision`, `reasons`, `matched_rules` and `operations`. The explain input is a trusted `pdp.authz/v1` document supplied by the administrator, not a way to authenticate a caller. The first command prints `"allow": true` with `"matched_rules": ["repository-read"]`. The second prints `"allow": false` with the reason `caller UID is not allowed`.

### Request outcomes

Authentication runs first. It fails with `401 unauthenticated` only when the Unix peer UID cannot be read or the SPIFFE certificate does not verify. A verified caller that policy does not name is `403 forbidden`. Other error bodies are `{"error": "<code>"}` with `route_not_found` (404), `invalid_request` (400), `concurrency_limited` (503), `credential_unavailable`, `upstream_unavailable` and `invalid_upstream_response` (502).

`pdp serve` writes one JSON audit event per request to stderr with `time`, `snapshot`, `principal`, `provider`, `operation`, `operations`, `policy_revision`, `schema_digest`, `matched_rules`, `outcome`, `status` and `duration_ms`. The `principal` field holds `identity.id`. Events carry identifiers and rule names, never request values or credentials.

## Supported schema surface

OpenAPI input is JSON, versions 3.0.x and 3.1.x, within an explicitly narrow subset. Supported REST values are scalar string, boolean, integer and number path and query parameters, and typed closed JSON request objects and arrays. Local component schema references are allowed without cycles. Unknown relevant keywords fail import. Unsupported features include polymorphism, defaults, format enforcement, external references, header and cookie parameters, array and object query parameters, callbacks, links, authentication schemes and nonempty security requirements, server variables and server base paths. Descriptions and examples are metadata, not permission evidence. Do not import an arbitrary provider OpenAPI document and assume compatibility.

REST rejects percent-encoded paths, dot segments, doubled slashes, duplicate query or body keys, unknown request fields and unsupported body and content types. A matching operation ID does not authorize its values or provider-state-dependent resources.

GraphQL uses pinned SDL with a dedicated parser and validator. Named operations, aliases, fragments, variables and defaults, built-in input scalars, enums, input objects and list coercion are supported. Every selected field is checked, including conditional selections. Subscriptions, batches, introspection, custom executable directives and custom input scalar coercion are not supported.

The schemas under `examples/packs/*/` are request projections taken from pinned provider sources, with provenance in `pkg/schema/testdata/README.md`. They are not complete provider schemas or response filters. See [pkg/schema/README.md](../pkg/schema/README.md) for the exact subset.

## Limits

| Boundary | Default | Maximum or configuration |
| --- | --- | --- |
| Configuration file, each schema file, policy data file | 4 MiB | Fixed |
| All policy modules together | 4 MiB | Fixed |
| Adapter script file | 1 MiB read, then the adapter source limit below | Fixed |
| `ca_file` | 1 MiB | Fixed |
| JSON and schema nesting | 64 | Fixed |
| GraphQL field occurrences | 4096 | Fixed |
| Request body | 1 MiB | `limits.max_request_bytes`, at most 1 MiB |
| Response body | 4 MiB | `limits.max_response_bytes`, at most 4 MiB |
| Request and response headers | 16 KiB | `limits.max_header_bytes`, 1 to 64 KiB |
| Concurrent gateway requests | 32 | `limits.max_concurrent`, 1 to 1024 |
| Gateway request deadline | 15 s | `limits.request_timeout`, 1 ms to 1 min |
| Header read / idle connection | 5 s / 30 s | Fixed |
| Adapter execution steps | 100,000 | `credentials.limits.max_steps`, at most 10,000,000 |
| Adapter timeout / concurrent acquisitions | 10 s / 8 | `timeout` 1 ms to 1 min, `max_concurrent` 1 to 128 |
| Adapter input / output | 8 KiB / 16 KiB | `max_input_bytes`, `max_output_bytes`, at most 1 MiB each |
| Adapter source / HTTPS response | 64 KiB / 256 KiB | `max_script_bytes`, `max_http_response_bytes`, at most 1 MiB each |
| Credential cache entries | 1024 | `cache_entries`, 1 to 100,000 |
| Credential expiry safety margin | 30 s | `expiry_margin`, at most 24 h |

Duration fields (`limits.request_timeout`, `credentials.limits.timeout`, `credentials.limits.expiry_margin`) accept strings such as `15s` or integer nanoseconds. Streaming, WebSockets and upgrades, compressed requests and responses, and non-JSON provider response bodies are rejected. Responses are buffered within their cap. Gateway limits are process-wide and fixed until restart. Starlark is trusted administrator code with step, time, byte and concurrency limits, not a hard memory sandbox. Run an untrusted adapter in a separately limited process instead.

## Credentials

`credentials.providers.<name>` takes `endpoints` (alias to exact HTTPS URL) and exactly one of `script` (inline Starlark) or `script_file`. `credentials.bindings.<name>` takes `provider`, `secrets` (alias to `{file}` or `{systemd_credential}`), `parameters`, `scopes`, `state_file`, `github` and `linear_actor`. `credentials.credentials_directory` and `credentials.limits` are optional. See [pkg/credential/README.md](../pkg/credential/README.md) for the adapter builtins.

Policy never sees credentials. Native helpers load mounted or systemd credentials only after `allow`. Adapter code cannot choose hosts, follow redirects, print secrets, import modules, or return a raw token string. Cache keys include provider, binding and canonical requested scopes. Each snapshot gets a fresh cache. An upstream `401` or `403` invalidates the lease without retrying the request.

The packs use four adapters: a static mounted token (`minimal`, `github-read`, `github-spiffe`, `systemd`), a GitHub App installation token with fixed repository IDs and permissions (`github-comment`), Linear client credentials (`linear-read`) and a Linear refresh-token installation (`linear-comment`).

Linear behavior checked against its primary OAuth documentation on November 9, 2026:

- Client credentials require the application's explicit client-credentials toggle and `linear_actor: app`. No refresh token is issued. Reacquire after expiry or invalidation.
- Authorization-code installations can be `app` or `user` actors. Both use rotating refresh state. `actor=app` does not remove the refresh requirement. The actor is attested administrator configuration from the original authorization, not something PDP can change during refresh.
- For issue reads and comments request `read` and `comments:create`, not `write` or `admin`. Initial browser consent and code exchange are outside PDP. Seed only an already authorized refresh installation.

For the refresh flow use the `linear_refresh` adapter, an explicit `linear_actor`, and a private writable `state_file`. Its initial JSON contains `refresh_token` and `scopes`. The directory must be `0700` and the file `0600`. Every writer must honor the adjacent lock. Native code serializes refreshes and replaces the complete token pair with an atomic rename, file sync and parent-directory sync before reporting success. A recovery-required marker preserves ambiguous refresh outcomes. Do not delete it or retry blindly. A read-only Secret volume cannot hold rotating token state.

Primary reference: <https://linear.app/developers/oauth-2-0-authentication>.

## Reload and revocation

Write the new schema, adapter and policy files first and atomically replace `pdp.json` last, with a new `revision`. Run `validate`, then send `SIGHUP` to `pdp serve`. PDP loads a complete new snapshot (policy, schemas, routes, bindings and a fresh credential manager) and publishes it atomically. `{"event":"reload_applied","revision":...}` on stderr acknowledges publication. A `reload_rejected` event with a reason leaves the old snapshot active. The reasons are `invalid_configuration`, `invalid_transport_or_revision`, `spiffe_source_unavailable`, `invalid_snapshot` and `publication_failed`.

Changing which UIDs or SPIFFE IDs are allowed is a policy edit and reloads without replacing listeners or open connections. `TestCLISocketReload` revokes a warm credential cache by rewriting the Rego file and sending `SIGHUP` to the real CLI.

Every authorization starting after the acknowledgement uses the new snapshot. Requests already authorized may finish within their deadlines. Removing an allow rule does not revoke an issued provider token or undo a write. A warm provider-token cache cannot bypass the new policy because policy is evaluated on every request.

Reload rejects changes to `unix_socket`, `socket_mode`, `spiffe`, `limits`, the `ca_file` path and the CA certificates it contains. Restart for those. With several replicas, revocation needs an acknowledgement from every serving replica, or the stale ones must stop serving. One pod reloading is not a fleet-wide guarantee.
