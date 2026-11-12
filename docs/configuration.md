# Configuration, policy and limits

## File contract

The runtime configuration is one YAML or JSON document with `version: pdp.config/v3` and a nonempty `revision` that contains no CR, LF or NUL. Both formats have the same fields and go through one loader, which decodes with `goccy/go-yaml`. The format is taken from the content, not the file extension. A `pdp.config/v2` file is rejected. The loader also rejects unknown fields (including the removed `routes`), duplicate keys, trailing data, an empty file, invalid UTF-8 and a non-object root.

In YAML the loader additionally rejects more than one document, anchors, aliases, merge keys and tags, so each value is written where it applies. Quote strings that YAML would read as another type: `socket_mode: "0660"` is a string, while unquoted `0660` is a number and is rejected. The examples in this document are JSON. The [egress pack](../examples/packs/egress/pdp.yaml) is YAML.

`pdp validate`, `pdp explain` and `pdp serve` take `--config FILE`. Without it they read `pdp.yaml`, `pdp.yml` or `pdp.json` from the working directory. If more than one of those exists the command fails and asks for `--config`. No other directory is searched. `pdp serve` resolves the file once at startup and rereads that same file on `SIGHUP`.

The same decoder and the same YAML restrictions apply to every other document an administrator writes: the `policy.data` file, an OpenAPI schema and a `pdp explain` input. A schema has the same digest in either format. These stay as they are: Rego modules, GraphQL SDL, Starlark adapters, credential `state_file` contents, which PDP writes itself, and request bodies from callers, which are always parsed as strict JSON.

Paths in the file (`ca_file`, `unix_socket`, `interception` files, schema files, `script_file`, policy modules and data, `state_file`, secret `file` and `credentials_directory`) are relative to the directory of the configuration file, not the working directory. Never put credentials in the file, in an adapter, or in policy data.

Top-level fields:

| Field | Meaning |
| --- | --- |
| `version`, `revision` | Required. Give every deployment a new `revision`. Reload rejects a snapshot whose revision equals the active one. |
| `ca_file` | Optional PEM file added to the system roots for private HTTPS destinations and credential endpoints. Verification is never disabled. |
| `limits` | Gateway limits, see [Limits](#limits). |
| `transport` | `unix_socket`, `socket_mode`, optional `spiffe` and optional `transparent`. |
| `interception` | Optional CA that signs leaf certificates for `CONNECT` and transparent TLS. |
| `dns` | Optional DNS server that steers configured names to the transparent listeners. |
| `schemas` | Map of name to `{protocol: "rest" or "graphql", file}`. |
| `upstreams` | Destinations that get a credential binding, a schema, a TLS mode or token paths. |
| `credentials` | Starlark adapters and bindings, see [Credentials](#credentials). |
| `policy` | `modules`: one or more `.rego` files. `data`: at most one YAML or JSON file. |

There are no other policy fields. Identity mapping, grants, profiles, constraints, relationships and destination allowlists do not exist in the configuration. They are written in Rego.

This configuration uses every section. It passes `pdp validate` with a `policy.rego` next to it:

```json
{
  "version": "pdp.config/v3",
  "revision": "proxy-v1",
  "limits": {"request_timeout": "15s", "stream_timeout": "10m"},
  "transport": {
    "unix_socket": "/run/pdp/pdp.sock",
    "socket_mode": "0660",
    "spiffe": {"address": ":8443", "workload_api": "unix:///run/spire/sockets/agent.sock"},
    "transparent": {"http": ":80", "https": ":443"}
  },
  "interception": {
    "certificate_file": "/run/pdp/ca/tls.crt",
    "key_file": "/run/pdp/ca/tls.key"
  },
  "dns": {
    "listen": ":53",
    "address": "10.16.0.1",
    "intercept": ["*.githubusercontent.com"],
    "unlisted": "forward",
    "resolver": "10.16.0.10:53"
  },
  "upstreams": [
    {"host": "api.example.com", "binding": "example-token"},
    {"host": "db.internal.example.com", "port": 5432, "tls": "tunnel"}
  ],
  "credentials": {
    "providers": {"static": {"script": "def acquire(request):\n    return static(secret(\"token\"))\n"}},
    "bindings": {"example-token": {"provider": "static", "secrets": {"token": {"file": "/run/secrets/example-token"}}}}
  },
  "policy": {"modules": ["policy.rego"]}
}
```

### Transport

At least one of `unix_socket`, `spiffe` and `transparent` is required. `socket_mode` defaults to `0600` and must be an octal string with no bits outside `0770` and no world bits. The socket path must be absolute after resolution. PDP creates it directly and refuses an existing path, or adopts one inherited systemd socket whose path equals `unix_socket`. The socket's parent directory must be owned by root or the daemon, not be a symlink, and not be group or world writable. Unix peer authentication needs Linux.

`spiffe.address` is a TCP listen address. `spiffe.workload_api` must start with `unix:///`. The listener requires TLS 1.3 and a client certificate that verifies against the current Workload API bundle. Session tickets are disabled. The certificate is checked again for every request, including each request inside an open `CONNECT`.

`transparent.http` and `transparent.https` are TCP listen addresses for DNS-steered clients. At least one is required when `transparent` is present. `https` requires `interception`, because PDP terminates TLS with a leaf for the SNI name. A caller on these listeners is identified by source address only, and is never treated as a Unix or SPIFFE caller.

### Interception

`interception.certificate_file` holds the PEM CA certificate, followed by any intermediates below the root that workloads trust. `interception.key_file` holds its PEM private key. Both are required when the section is present. The certificate must be a currently valid CA with the certificate-signing key usage.

PDP mints one ECDSA P-256 leaf per host, valid for at most 24 hours and never past the CA's expiry, and caches up to 1024 leaves. A leaf is replaced one hour before it expires. At most once a minute, PDP checks whether either file's modification time changed and reloads both. A failed reload keeps the loaded CA. This lets a renewed CA, such as one written by cert-manager, take effect without a restart. Renewal through cert-manager has not been tested.

Only `pdp serve` reads the files. `pdp validate` checks that both paths are set and does not open them. Anyone who holds the key can impersonate any host the CA permits to every workload that trusts its root. Protect it like a provider secret.

Without `interception`, PDP serves absolute-form requests, `CONNECT` to tunnel upstreams and plain HTTP on a transparent listener. Any other `CONNECT` gets `403 interception_unavailable`.

### DNS

`dns` requires `transparent`.

| Field | Meaning |
| --- | --- |
| `listen` | Required. UDP listen address, for example `:53`. |
| `address` | Required. The gateway IP returned for steered names. An IPv4 address answers `A` queries, an IPv6 address answers `AAAA`. The other record type gets an empty answer. |
| `intercept` | Extra names to steer: exact lower-case hosts, or `*.suffix` for every name below a suffix. Every `upstreams` host is steered without being listed. |
| `unlisted` | `forward` (default) or `refuse`. |
| `resolver` | `ip:port` of the real resolver. Required with `forward`, not allowed with `refuse`. |

`pdp validate` checks only that `listen` is set and that `unlisted` and `resolver` agree. The `address`, `resolver` and `intercept` values are parsed when `pdp serve` starts, and a bad value makes it exit then.

A steered name gets an authoritative answer with a 30-second TTL. Any other name is forwarded unchanged to `resolver` and its answer returned unchanged, or answered `REFUSED` when `unlisted` is `refuse`. DNS is UDP only. There is no TCP listener, so a client that retries a truncated answer over TCP gets nothing from PDP. At most 256 queries are handled at once. Further packets are dropped and the client retries.

`refuse` is not enforcement by itself, since a client can connect to an IP literal. Block direct egress from the workload. The set of steered names is fixed at startup. A reload that changes it is rejected.

### Upstreams

An upstream entry matches one exact host and port. It attaches behavior to that destination. It does not allow it. A destination with no entry still reaches policy, with no binding and no schema.

| Field | Meaning |
| --- | --- |
| `host` | Required. Lower-case host name or IP address, no trailing dot. |
| `port` | Default 443. |
| `tls` | `intercept` (default) or `tunnel`. A tunnel entry is relayed unread after `CONNECT` and cannot have a binding, schema or token path. An absolute-form or transparent request to a tunnel entry is refused with `400`. |
| `binding` or `bindings` | One credential binding, or several. Not both. With several bindings, or with `token_paths`, every binding needs its own `placeholder`. |
| `schema` | Name of an entry in `schemas`. Turns on strict validation, see [Request forms and handling](#request-forms-and-handling). |
| `graphql_path` | The only path a GraphQL schema upstream accepts. Default `/graphql`. Needs a schema. |
| `token_paths` | Paths answered locally with the placeholder, see [Placeholders and token paths](#placeholders-and-token-paths). Needs a binding and no schema. |
| `scopes` | Scope set the credential adapter is asked for. Must be a subset of each binding's `scopes`. |

At most 1024 entries. Two entries with the same host and port are rejected. A binding or a schema is never used over plain `http`. Such a request is refused with `400`.

### What validation checks

`pdp validate` loads every referenced file, compiles schemas, Rego modules and adapters, checks transport, interception, DNS, upstreams and credential bindings, and builds a gateway snapshot. It prints `{"valid": true, "revision": ..., "diagnostics": []}`. `diagnostics` is always empty because Go does not analyze policy source.

Validation does not read secret contents or the interception CA files, request a token, open the Workload API, bind a listener, or contact a provider. A binding that uses `systemd_credential` fails validation unless `credentials.credentials_directory` is set or `CREDENTIALS_DIRECTORY` is in the environment:

```sh
CREDENTIALS_DIRECTORY=/run/credentials/pdp.service \
  bin/pdp validate --config examples/packs/systemd/pdp.json
```

Missing secret files and an unreadable interception CA are therefore startup or runtime failures. Passing validation says nothing about provider reachability or account permissions.

## Request forms and handling

| Form | Listener | Destination taken from |
| --- | --- | --- |
| Absolute-form, `GET https://host/path HTTP/1.1` | Any | The request URL. PDP makes the TLS connection. |
| `CONNECT host:port` | Any | The `CONNECT` target. A request inside that names another host or port in `Host` or its URL is refused with `400`. |
| Origin-form, `GET /path` | Transparent only | `Host`. On TLS, `Host` must equal the SNI name, or the request is refused with `400`. |

The Unix socket and SPIFFE listeners refuse origin-form requests with `400`. Transparent listeners also accept absolute-form and `CONNECT`, with the caller still identified by source address only.

Inside an intercepted `CONNECT`, a first byte of `0x16` starts TLS with a leaf for the `CONNECT` host. Anything else is read as plain HTTP with scheme `http`. Each request inside is authenticated and authorized on its own, against the snapshot that is current when that request starts.

Everything is HTTP/1.1. HTTP/2 is not offered to callers, and upstream connections negotiate `http/1.1` only.

Upstream connections are reused. An idle one is kept for 30 seconds, at most `max_concurrent` per destination host and port, and all are closed on reload. Two consequences follow:

- A request may travel on a connection opened for an earlier request to the same host and port, possibly from another caller. It goes to the address resolved when that connection was opened. Policy still runs on every request with the addresses resolved for it, but an address rule is enforced when a connection is opened, not on each request that reuses it.
- If a reused connection fails before the upstream answers, Go's transport sends the request once more on a new connection. This applies to `GET`, `HEAD`, `OPTIONS` and `TRACE` without a body, and to any bodiless request the caller marked with `Idempotency-Key` or `X-Idempotency-Key`. A request with a body is never sent twice.

Set `limits.disable_upstream_reuse` to `true` to open a new connection for every request. Then neither applies, and every request pays for a TCP and TLS handshake.

**Schema-backed upstreams** keep the strict handling of the earlier route-based gateway. The method must be GET, HEAD, POST, PUT, PATCH or DELETE. The request is validated against the pinned schema and refused with `400` before policy on any ambiguity: encoded or dot paths, doubled slashes, duplicate query keys, unknown body fields, non-JSON bodies, compression, upgrades or trailers. PDP builds a fresh request with only `Accept`, `Accept-Encoding: identity`, `User-Agent`, `Content-Type`, the binding's fixed `headers` and the credential, so no caller header is forwarded. The response must be a 2xx, 4xx or 5xx JSON body within `max_response_bytes`, without compression. A redirect is refused as `invalid_upstream_response`. The body is buffered, scanned for the credential, and returned with locally built headers. A GraphQL upstream accepts only POST to its `graphql_path` and refuses subscriptions and batches.

**Every other destination** is relayed as a stream. Any upper-case method except `CONNECT`, any content type and any body are forwarded. Dot segments in the path, NUL or CR/LF in header values, more than 128 headers, trailers, an `Upgrade` other than `websocket`, and headers over `max_header_bytes` are refused with `400`. Hop-by-hop headers are removed in both directions. Other caller headers are forwarded, including the caller's own `Authorization` when no credential is injected. The response streams back as it arrives, with its status, content type and encoding, bounded by `stream_timeout`. A redirect is returned to the caller and never followed. A WebSocket upgrade is authorized with `protocol` `websocket`, the upstream's `101` is relayed, and bytes then flow both ways without frame inspection.

## Policy

Authorization is Rego. Go does not compute candidate permissions or denials.

### Module contract

Every module must declare `package pdp.authz` and is parsed as Rego v1. Go queries `data.pdp.authz` for each decision. The result must be an object with:

| Rule | Type | Meaning |
| --- | --- | --- |
| `allow` | boolean | Required. Only `true` authorizes. |
| `reasons` | set or array of strings | Optional. Returned in `pdp explain` output. |
| `matched_rules` | set or array of strings | Optional. Returned in `pdp explain` output and in audit events. |

Write `default allow := false`. If `allow` is undefined, evaluation reports an error and the request is denied. A non-boolean `allow`, a non-string element in `reasons` or `matched_rules`, an undefined result and a runtime error (builtin errors are strict) also deny. The request then receives `403 forbidden` and no credential is acquired. `pdp explain` prints `authorization evaluation failed` for these cases instead of a decision.

The compiler removes `http.send`, `net.lookup_ip_addr` and `opa.runtime` and allows no network access. Other OPA builtins remain, including `time.now_ns`, `glob.match` and `net.cidr_contains`. There is no positive decision cache, so a policy that uses the clock is evaluated again on every request.

`policy.data` may name one YAML or JSON file whose root is an object. It is loaded as OPA data, so `data.<key>` is readable from the modules. It cannot define `data.pdp.authz`. Go gives the data no meaning. All numbers in input and data keep their exact spelling, so large integer IDs are not rounded.

### When policy runs

For a destination given by name, policy runs twice:

1. Before DNS resolution, without `destination.addresses`. A deny ends the request. The name is never looked up, so a caller cannot send data out through lookups of refused names.
2. After resolution, with `destination.addresses` set to the addresses PDP will dial (at most 16). A new connection is dialed only to those addresses, so a second DNS answer cannot move it. A request that reuses an open connection goes to the address that connection was dialed to, see [request forms and handling](#request-forms-and-handling).

For an IP literal only the second evaluation runs. A request to a `token_paths` entry dials nothing and is evaluated once, without addresses. A rule that refuses address ranges must therefore allow the first evaluation, where `addresses` is absent. Checking only the addresses that are present does this, as the `egress` pack does.

### Input

Go builds `input` (`pdp.authz/v2`) from verified facts and the request:

| Field | Content |
| --- | --- |
| `version` | `pdp.authz/v2` |
| `identity.id` | `uid:<n>`, the verified SPIFFE ID, or `ip:<address>` |
| `identity.auth_method` | `unix`, `spiffe` or `transparent` |
| `identity.uid` | Kernel peer UID, `unix` only |
| `identity.spiffe_id` | Verified SPIFFE ID, `spiffe` only |
| `identity.ip` | Source address, `transparent` only |
| `protocol` | `http`, `websocket` or `tunnel` |
| `destination.scheme` | `https` or `http`, or `tcp` for a tunnel |
| `destination.host`, `destination.port` | Lower-case host without a trailing dot, and port |
| `destination.addresses` | Addresses that will be dialed. Absent on the first evaluation. |
| `binding` | The credential that will be injected. Absent when none will be. |
| `plugin`, `schema_digest` | Schema name and digest. Schema-backed upstreams only. |
| `http.method`, `http.path`, `http.query` | Method, path and parsed query. Absent for a tunnel. On a stream destination the path is the escaped path. |
| `http.path_params`, `http.normalized_query`, `http.body` | Schema-backed only: REST path parameters, schema-typed query values and the decoded JSON body |
| `operations` | Schema-backed only. One `{id}` per operation: a REST `operationId`, or one GraphQL field coordinate per selected field occurrence. |
| `graphql` | GraphQL schema only. One entry per selected field occurrence with `coordinate`, `path` (response aliases) and `arguments`. |
| `operation_type`, `operation_name`, `variables` | GraphQL schema only |

`input.provider` no longer exists. Use `destination.host` and `binding`.

A destination without a schema is not classified. The policy sees method, path and query, and nothing about the body or headers. A tunnel shows only host and port.

Identity is established by Go before policy runs. Everything else about the caller is untrusted data, including headers, which are not passed to policy. `http.body`, `http.query` and `variables` are caller data even when schema-valid.

If `schema_digest` is present and a query key has no normalized value, Go denies before Rego runs.

### What the policy author must do

Go does not know which callers, destinations, repositories or operations are acceptable. The policy has to say.

- **Name callers.** Every local UID that can open the socket, every workload whose certificate verifies against the trust bundle, and every address that reaches a transparent listener reaches policy. A policy that does not compare `input.identity` allows all of them. Socket file permissions, the trust bundle and the network remain the outer boundary. Processes that share a UID share an identity.
- **Name destinations.** Any host can be requested. A rule that does not check `input.destination` applies to every host.
- **Check the binding.** `input.binding` decides which credential is sent. A rule that allows a host without checking `input.binding` allows every binding that host has. With several bindings, the caller's placeholder picks the candidate, and only policy decides whether that caller may use it.
- **Check addresses.** Refuse loopback, link-local and private ranges in `input.destination.addresses` unless a destination needs them.
- **Pin the schema.** Compare `input.schema_digest` with the digest of the reviewed schema (`bin/pdp catalog` prints it). A policy that omits this check keeps allowing requests after the schema file changes.
- **Treat operation IDs as strings.** A misspelled ID never matches and nothing reports it. List the IDs with `pdp catalog`.
- **Check every occurrence.** For GraphQL, iterate `input.graphql` and require every entry to be allowed. Fields behind `@skip` or `@include`, aliases and repeated selections are all listed.

Checked-in policies are in [`examples/packs`](../examples/README.md). For example, `examples/packs/github-read/policy.rego` allows one Unix UID to run three reviewed read operations on one `owner/repo` at `api.github.com` under one schema digest. To see a decision without a server, write the input by hand and run:

```sh
bin/pdp explain --config examples/packs/github-read/pdp.json \
  --input examples/packs/github-read/explain/read-issue.json
bin/pdp explain --config examples/packs/github-read/pdp.json \
  --input examples/packs/github-read/explain/other-uid.json
```

The output has `allow`, `identity`, `protocol`, `destination`, `binding`, `schema_digest`, `revision`, `reasons`, `matched_rules` and `operations`. The explain input is a trusted `pdp.authz/v2` document, YAML or JSON, supplied by the administrator, not a way to authenticate a caller. The first command prints `"allow": true` with `"matched_rules": ["repository-read"]`. The second prints `"allow": false` with the reason `caller UID is not allowed`.

### Request outcomes

Authentication runs first. It fails with `401 unauthenticated` when the Unix peer UID cannot be read, the SPIFFE certificate does not verify, or a transparent caller has no source address. A verified caller that policy does not allow gets `403 forbidden`. Error bodies are `{"error": "<code>"}`:

| Status | Codes |
| --- | --- |
| 400 | `invalid_request` |
| 401 | `unauthenticated` |
| 403 | `forbidden`, `interception_unavailable` |
| 502 | `destination_unresolved`, `credential_unavailable`, `upstream_unavailable`, `invalid_upstream_response` |
| 503 | `concurrency_limited`, `gateway_closed` |

When a streamed response has started and the credential appears in it, PDP can no longer send a status. It closes the connection, and the audit event records `credential_reflected` with status 502.

`pdp serve` writes one JSON audit event per request to stderr with `time`, `snapshot`, `principal`, `protocol`, `host`, `port`, `binding`, `plugin`, `operation`, `operations`, `policy_revision`, `schema_digest`, `matched_rules`, `outcome`, `status`, `bytes_sent`, `bytes_received` and `duration_ms`. `principal` holds `identity.id`. Served outcomes are `forwarded`, `upgraded`, `tunneled`, `intercepting` (the `CONNECT` itself) and `token_answered`. Events carry identifiers, rule names and byte counts, never request values or credentials.

## Supported schema surface

OpenAPI input is JSON or YAML, versions 3.0.x and 3.1.x, within an explicitly narrow subset. Supported REST values are scalar string, boolean, integer and number path and query parameters, and typed closed JSON request objects and arrays. Local component schema references are allowed without cycles. Unknown relevant keywords fail import. Unsupported features include polymorphism, defaults, format enforcement, external references, header and cookie parameters, array and object query parameters, callbacks, links, authentication schemes and nonempty security requirements, server variables and server base paths. Descriptions and examples are metadata, not permission evidence. Do not import an arbitrary provider OpenAPI document and assume compatibility.

REST rejects percent-encoded paths, dot segments, doubled slashes, duplicate query or body keys, unknown request fields and unsupported body and content types. A matching operation ID does not authorize its values or provider-state-dependent resources.

GraphQL uses pinned SDL with a dedicated parser and validator. Named operations, aliases, fragments, variables and defaults, built-in input scalars, enums, input objects and list coercion are supported. Every selected field is checked, including conditional selections. Subscriptions, batches, introspection, custom executable directives and custom input scalar coercion are not supported.

The schemas under `examples/packs/*/` are request projections taken from pinned provider sources, with provenance in `pkg/schema/testdata/README.md`. They are not complete provider schemas or response filters. See [pkg/schema/README.md](../pkg/schema/README.md) for the exact subset.

## Limits

| Boundary | Default | Maximum or configuration |
| --- | --- | --- |
| Configuration file, each schema file, policy data file | 4 MiB | Fixed |
| All policy modules together | 4 MiB | Fixed |
| Adapter script file | 1 MiB read, then the adapter source limit below | Fixed |
| `ca_file`, each interception CA file | 1 MiB | Fixed |
| JSON and schema nesting | 64 | Fixed |
| GraphQL field occurrences | 4096 | Fixed |
| Request body, schema-backed upstream or token path | 1 MiB | `limits.max_request_bytes`, at most 1 MiB |
| Response body, schema-backed upstream | 4 MiB | `limits.max_response_bytes`, at most 4 MiB |
| Request and response headers | 16 KiB | `limits.max_header_bytes`, 1 to 64 KiB |
| Concurrent requests | 32 | `limits.max_concurrent`, 1 to 1024 |
| Open connections per listener, open intercepted `CONNECT`s | 2 × `max_concurrent` | Follows `max_concurrent` |
| Schema-backed exchange, wait for upstream response headers | 15 s | `limits.request_timeout`, 1 ms to 1 min |
| Streamed response, WebSocket, tunnel | 10 min | `limits.stream_timeout`, from `request_timeout` to 24 h |
| Upstream connection reuse | On, idle for 30 s | `limits.disable_upstream_reuse` |
| Header read / idle connection | 5 s / 30 s | Fixed |
| Resolved addresses per destination | 16 | Fixed |
| Cached interception leaves | 1024 | Fixed |
| Concurrent DNS queries | 256 | Fixed |
| Adapter execution steps | 100,000 | `credentials.limits.max_steps`, at most 10,000,000 |
| Adapter timeout / concurrent acquisitions | 10 s / 8 | `timeout` 1 ms to 1 min, `max_concurrent` 1 to 128 |
| Adapter input / output | 8 KiB / 16 KiB | `max_input_bytes`, `max_output_bytes`, at most 1 MiB each |
| Adapter source / HTTPS response | 64 KiB / 256 KiB | `max_script_bytes`, `max_http_response_bytes`, at most 1 MiB each |
| Credential cache entries | 1024 | `cache_entries`, 1 to 100,000 |
| Credential expiry safety margin | 30 s | `expiry_margin`, at most 24 h |

Duration fields (`limits.request_timeout`, `limits.stream_timeout`, `credentials.limits.timeout`, `credentials.limits.expiry_margin`) accept strings such as `15s` or integer nanoseconds. A streamed request or response body has no byte limit. Only `stream_timeout` bounds it. Gateway limits are process-wide and fixed until restart. Starlark is trusted administrator code with step, time, byte and concurrency limits, not a hard memory sandbox. Run an untrusted adapter in a separately limited process instead.

## Credentials

`credentials.providers.<name>` takes `endpoints` (alias to exact HTTPS URL) and exactly one of `script` (inline Starlark) or `script_file`. `credentials.bindings.<name>` takes `provider`, `secrets` (alias to `{file}` or `{systemd_credential}`), `parameters`, `scopes`, `placeholder`, `headers`, `state_file`, `github` and `linear_actor`. `credentials.credentials_directory` and `credentials.limits` are optional. See [pkg/credential/README.md](../pkg/credential/README.md) for the adapter builtins.

Policy never sees credentials. Native helpers load mounted or systemd credentials only after `allow`. Adapter code cannot choose hosts, follow redirects, print secrets, import modules, or return a raw token string. Cache keys include provider, binding and canonical requested scopes. Each snapshot gets a fresh cache. An upstream `401` or `403` invalidates the lease without retrying the request.

### Injection

Before the credential is applied, PDP removes from the outgoing request the caller's `Authorization`, `Cookie`, the header the adapter result sets (`Authorization`, or the custom header of a `header` result), and every header whose value carries the binding's placeholder. It then sets the binding's fixed `headers`, sets `Accept-Encoding: identity`, and applies the credential.

`headers` are non-secret fixed values such as an account ID. Names must be valid HTTP tokens and cannot be `Host`, `Content-Length`, `Connection`, `Proxy-Authorization` or `Transfer-Encoding`. Values are at most 1024 bytes without control characters. The caller's values for these headers are replaced.

On a stream destination, a credentialed response with a `Content-Encoding` other than `identity`, or with the credential in a header, is refused with `502 invalid_upstream_response`. The body is scanned for the raw credential bytes as it is relayed, including a credential split across reads. On a match the connection is cut before the credential is written. JSON-escaped forms are caught only on schema-backed upstreams, whose responses are buffered. WebSocket frames are not scanned.

### Placeholders and token paths

`placeholder` is a non-secret string given to the workload in place of the real credential. It must be 8 to 256 bytes without spaces, commas, double quotes, backslashes or control characters. It selects a candidate binding and authorizes nothing.

- An upstream with one binding and no `token_paths` always uses that binding. No placeholder is needed.
- An upstream with several bindings, or with `token_paths`, needs a distinct placeholder on each binding. A request picks the binding whose placeholder appears as a header value, as the last space-separated word of a header value (`Bearer <placeholder>`), or as the user or password of a `Basic` header. A request that carries none has no binding and is evaluated without `input.binding`.
- The chosen binding reaches policy as `input.binding`. Policy must allow it for the verified caller. A caller that sends another account's placeholder is denied unless policy grants it that binding.

A request to a path in `token_paths` is never forwarded. PDP reads its body (at most `max_request_bytes`) to find the placeholder there or in the headers, evaluates policy once without addresses, and on allow answers `200` with `{"access_token": <placeholder>, "refresh_token": <placeholder>, "token_type": "Bearer", "expires_in": 3600}` and `Cache-Control: no-store`. No credential is acquired for it. The real access and refresh tokens stay in the binding's adapter state. Without a matching placeholder the answer is `403`.

Not established: whether Jcode, or any provider's own client, accepts these placeholder answers and the formats above for each provider.

### Packs

The packs use these adapters: a static mounted token (`minimal`, `github-read`, `github-spiffe`, `systemd`), a GitHub App installation token with fixed repository IDs and permissions (`github-comment`), Linear client credentials (`linear-read`) and a Linear refresh-token installation (`linear-comment`). The `subscription` pack shows several placeholder bindings on one host.

### Linear

Linear behavior checked against its primary OAuth documentation on November 9, 2026:

- Client credentials require the application's explicit client-credentials toggle and `linear_actor: app`. No refresh token is issued. Reacquire after expiry or invalidation.
- Authorization-code installations can be `app` or `user` actors. Both use rotating refresh state. `actor=app` does not remove the refresh requirement. The actor is attested administrator configuration from the original authorization, not something PDP can change during refresh.
- For issue reads and comments request `read` and `comments:create`, not `write` or `admin`. Initial browser consent and code exchange are outside PDP. Seed only an already authorized refresh installation.

For the refresh flow use the `linear_refresh` adapter, an explicit `linear_actor`, and a private writable `state_file`. Its initial JSON contains `refresh_token` and `scopes`. The directory must be `0700` and the file `0600`. Every writer must honor the adjacent lock. Native code serializes refreshes and replaces the complete token pair with an atomic rename, file sync and parent-directory sync before reporting success. A recovery-required marker preserves ambiguous refresh outcomes. Do not delete it or retry blindly. A read-only Secret volume cannot hold rotating token state.

Primary reference: <https://linear.app/developers/oauth-2-0-authentication>.

## Reload and revocation

Write the new schema, adapter and policy files first and atomically replace `pdp.json` last, with a new `revision`. Run `validate`, then send `SIGHUP` to `pdp serve`. PDP loads a complete new snapshot (policy, upstreams, schemas, bindings and a fresh credential manager) and publishes it atomically. `{"event":"reload_applied","revision":...}` on stderr acknowledges publication. A `reload_rejected` event with a reason leaves the old snapshot active. The reasons are `invalid_configuration`, `invalid_transport_or_revision`, `spiffe_source_unavailable`, `invalid_snapshot` and `publication_failed`.

Changing which callers or destinations are allowed is a policy edit and reloads without replacing listeners or open connections. `TestCLISocketReload` revokes a warm credential cache by rewriting the Rego file and sending `SIGHUP` to the real CLI.

Every request that starts after the acknowledgement uses the new snapshot. That includes each new request inside an already open intercepted `CONNECT`. A request already running keeps its snapshot. For a relayed stream, a WebSocket or an opaque tunnel this lasts until it ends or `stream_timeout` passes. Removing an allow rule does not revoke an issued provider token or undo a write. A warm provider-token cache cannot bypass the new policy because policy is evaluated on every request.

Reload rejects changes to `unix_socket`, `socket_mode`, `spiffe`, `transparent`, `interception`, `dns`, `limits`, the `ca_file` path and the CA certificates it contains. A change to `upstreams` that changes the set of names DNS steers is also rejected while `dns` is configured. Restart for those. With several replicas, revocation needs an acknowledgement from every serving replica, or the stale ones must stop serving. One replica reloading is not a fleet-wide guarantee.
