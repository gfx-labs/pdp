# Configuration, profiles and supported limits

## File contract

Configuration is administrator-owned YAML or JSON with `version: pdp.config/v1` and a nonempty `revision` without CR, LF or NUL. One document is accepted. Duplicate YAML/JSON keys and unknown fields fail validation. Quote numeric UID keys and octal socket modes. YAML aliases/merges, non-string map keys and non-JSON numeric spellings such as hexadecimal, underscores or nonfinite floats are rejected. Numeric policy literals retain exact integer/decimal/exponent lexemes instead of passing through floating-point conversion. Paths for schemas, mounted secrets, OAuth state and custom CA files are relative to the configuration file, not the process working directory. Adapter `script` and policy `custom_modules` values are inline source. Never put credentials in either source or policy values.

Top-level fields are `version`, `revision`, `transport`, `identities`, `principal_tasks`, `schemas`, `routes`, `credentials`, `policy`, `limits`, and optional `ca_file`. `identities` maps a kernel UID to one principal. `principal_tasks` optionally maps a principal to one administrator-assigned task. It is not populated from headers or a caller-selected task name.

There is at most one route per provider and two routes total. The only provider names are `github` and `linear`. Each route binds one administrator-selected credential binding. Supported paths are `/upstreams/github/...` and `/upstreams/linear/graphql`. Default upstreams are `https://api.github.com` and `https://api.linear.app/graphql`. Optional `upstream_url` is a fixed HTTPS administrator endpoint, never a caller value. GitHub requires an origin without a base path. Linear requires `/graphql`. Redirects and implicit transport retries are disabled. `ca_file` augments system certificate roots for private HTTPS endpoints and never disables verification.

Validation reads and compiles source/schema files but does not fetch a token, open a mounted secret, start a Workload API connection, contact a provider, bind a listener, or make a write. Missing secret material is therefore a runtime failure, not proof that validation is incomplete. Provider reachability and authorization need explicit acceptance checks.

## Exact built-in profiles

The finite reviewed map is `pkg/config/profiles.go`. Built-ins are enabled only for the exact reviewed provider-projection digests pinned there, not merely a matching operation ID. A changed method, path, argument type or schema metadata cannot silently retain approval on reload. Updating those pins requires review. An explicit administrator `policy.operations` entry overrides a built-in entry and must supply its nonempty exact reviewed `schema_digest` and `reviewed: true` for restricted access. New schema operations never become readable or writable automatically. A restricted profile with no reviewed operations rejects loading.

| Provider | Read operations/field coordinates | Additional `read_write` operation |
| --- | --- | --- |
| GitHub | `repos/get`, `issues/get`, `issues/list-comments` | `issues/create-comment` |
| Linear | `Query.issue`, `Issue.id`, `Issue.identifier`, `Issue.title`, `Issue.description`, `CommentPayload.success`, `CommentPayload.comment`, `Comment.id`, `Comment.body` | `Mutation.commentCreate` |

The GitHub resource identity is the exact `owner/repo` pair, not a basename. Each GitHub mapped operation extracts both normalized path components. A repository allowlist is therefore `APPROVED_OWNER/APPROVED_REPOSITORY`. An unknown operation is never classified from its method. `read_write` is not general GitHub write access or Linear issue administration.

Linear `Query.issue(id:)` and `Mutation.commentCreate(input.issueId:)` identify the issue. Descendants inherit only their own ancestor occurrence's issue resource. Sibling aliases do not share resources. Use approved issue UUIDs, not a team ID or an assumed team membership. The shipped SDL retains the provider's complete comment input type and actual nullability. The reviewed `Mutation.commentCreate` operation guard permits only `issueId` and `body`, both nonempty strings, under restricted grants. Alternate targets and actor overrides therefore deny rather than relying on a narrowed schema. An unrestricted `full` grant deliberately bypasses this operation-level profile guard, while explicit mandatory constraints still apply. A different schema or broader surface requires a separate policy review. Repeated field occurrences, aliases and arguments remain separate authorization units.

All restricted profiles and typed operation/resource restrictions require a schema. A schema-free route accepts only unrestricted `full` grants and untyped global restrictions. Removing a schema cannot silently disable a typed deny. Unknown policy operation/GraphQL-field references and mismatched pinned schema digests reject the snapshot. Unknown literal operation comparisons diagnosed in custom Rego reject loading. Arbitrary dynamic Rego expressions cannot be exhaustively statically checked. Custom modules use `package pdp.custom`, with `deny` a set of strings. They can only add denials, not replace the base allow decision. Network/runtime introspection builtins are excluded.

See `examples/github-read.yaml`, `examples/github-read-write.yaml` and `examples/linear-read-write.yaml`. Their IDs and secret paths are templates. The schema files are curated supported request projections from pinned real provider sources with provenance under `pkg/schema/testdata`. They are not complete provider schemas or response filters.

## Supported schema surface

OpenAPI input is JSON, versions 3.0.x and 3.1.x, within an explicitly narrow subset. Supported REST values are scalar string/boolean/integer/number path/query parameters and typed closed JSON request objects/arrays. Local component schema references are allowed without cycles. Unknown relevant keywords fail import. Unsupported features include polymorphism, defaults, format enforcement, external references, header/cookie parameters, array/object query parameters, callbacks, links, authentication schemes/nonempty security requirements, server variables and server base paths. Descriptions/examples are metadata, not permission evidence. Do not import an arbitrary full provider OpenAPI document and assume compatibility.

REST rejects percent-encoded paths, dot segments, doubled slashes, duplicate query/body keys, unknown request fields and unsupported body/content types. A matching operation ID does not authorize its values or provider-state-dependent resources.

GraphQL uses pinned SDL with a dedicated parser and validator. Named operations, aliases, fragments, variables/defaults, built-in input scalars, enums, input objects and list coercion are supported. Every selected field is checked, including conditional selections, whether or not a runtime directive would skip them. Subscriptions, batches, introspection, custom executable directives and custom input scalar coercion are not supported. The shipped SDL is a request projection, not a full introspection service.

## Limits

| Boundary | Default | Maximum/configuration |
| --- | --- | --- |
| Config file / individual schema | 4 MiB | Fixed |
| Config/JSON/schema nesting | 64 | Fixed |
| GraphQL field occurrences | 4096 | Fixed |
| Request body | 1 MiB | `limits.max_request_bytes`, at most 1 MiB |
| Response body | 4 MiB | `limits.max_response_bytes`, at most 32 MiB |
| Request/response headers | 16 KiB | `limits.max_header_bytes`, 1 to 64 KiB |
| Concurrent gateway requests | 32 | `limits.max_concurrent`, 1 to 1024 |
| Gateway request deadline | 15 s | `limits.request_timeout`, 1 ms to 1 min |
| Header read / idle connection | 5 s / 30 s | Fixed |
| Adapter execution steps | 100,000 | `credentials.limits.max_steps`, at most 10,000,000 |
| Adapter timeout / concurrent acquisition | 10 s / 8 | 1 ms to 1 min / 1 to 128 |
| Adapter input / output | 8 KiB / 16 KiB | At most 1 MiB each |
| Adapter source / HTTPS response | 64 KiB / 256 KiB | At most 1 MiB each |
| Credential cache entries | 1024 | 1 to 100,000 |
| Credential expiry safety margin | 30 s | At most 24 h |

Duration fields accept strings such as `15s` or integer nanoseconds. Streaming, WebSockets/upgrades, compressed requests/responses and non-JSON provider response bodies are rejected. Responses are buffered within their cap. Gateway limits are process-wide and fixed until restart. Starlark is trusted administrator code with step/time/byte/concurrency limits, not a hard memory sandbox. Run an untrusted adapter in a separately limited process instead.

## Credential adapters and Linear actor modes

The static adapter uses `static(secret("token"))`. `secret` is an opaque handle. Native helpers load mounted or systemd credentials only after authorization. Adapter code cannot choose arbitrary hosts, follow redirects, print secrets, import modules, or return a raw token string. Cache keys include provider, binding and canonical requested scopes. Each snapshot gets a fresh cache. Upstream authentication failure invalidates its lease without automatically retrying the request.

GitHub App configuration supplies an exact installation-token endpoint, App ID, repository IDs, permissions and a mounted private key. Native code signs the short-lived App JWT and restricts the exchanged token to those repository IDs and permissions. Use installation IDs and repository IDs from the administrator, never caller fields.

Linear behavior checked against its primary OAuth documentation on November 9, 2026:

- Client credentials require the application's explicit client-credentials toggle and `linear_actor: app`. No refresh token is issued. Reacquire after expiry/invalidation.
- Authorization-code installations can be `app` or `user` actors. Both use rotating refresh state. `actor=app` does not remove the refresh requirement. The actor is attested administrator configuration from the original authorization, not something PDP can change during refresh.
- For issue reads/comments request `read` and `comments:create`, not unrestricted `write` or `admin`. Initial browser consent/code exchange is outside PDP. Seed only an already authorized refresh installation, without copying credentials into YAML.

For the refresh flow, use the `linear_refresh` adapter, explicit `linear_actor`, and a private writable `state_file`. Its initial JSON contains `refresh_token` and `scopes`. The directory must be `0700` and the file `0600`. Every writer must honor the adjacent lock. Native code serializes refreshes and writes the complete replacement token pair with atomic rename, file sync and parent-directory sync before reporting success. A recovery-required marker preserves ambiguous refresh outcomes. Do not delete it or retry blindly. A read-only Secret volume cannot serve as rotating token state. The complete replacement token pair, not only the access token, must survive restart.

Primary reference: <https://linear.app/developers/oauth-2-0-authentication>.

## Reload and revocation

Write the new schema/source files first and atomically replace the main configuration last. Give every deployment a new `revision`. Run `validate`, then send `SIGHUP`. A `reload_applied` event with the exact new `revision` acknowledges publication. `reload_rejected` leaves the old snapshot active. The server swaps the principal map, schemas, routes/bindings, policy, relationships and credential manager together. Existing requests retain exactly one snapshot, and old caches retire only after those requests drain.

Every authorization starting after acknowledgement uses the new snapshot. Already-authorized upstream operations may finish within their existing deadlines. Removing a grant does not revoke an issued provider token or undo a write. PDP has no positive authorization cache. A warm provider-token cache cannot bypass the new policy. Relationships are a local fixed identity-to-task-to-resource snapshot with explicit permission/expiry, not a distributed consistency service. Required stale, missing, expired or wrong-task data denies only the grants that require it. Direct grants remain independent.

The CLI rejects live changes to listener endpoints, socket mode, Workload API endpoint, gateway limits or the CA filename. Restart for those settings and for CA-file contents. In multiple replicas, revocation acknowledgement must cover every serving replica or stale replicas must stop serving. A single pod reload is not a fleet-wide guarantee.
