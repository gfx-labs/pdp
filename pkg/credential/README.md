# Credential runtime

This package runs administrator-owned Starlark adapters after gateway authorization. It does not evaluate policy. Policy receives identifiers and normalized request data, never credential handles, tokens, refresh state, signing keys or provider responses.

## API and integration

```go
manager, err := credential.New(credential.Config{
    Providers: map[string]credential.ProviderConfig{
        "linear": {
            Script: adapters.LinearClientCredentials,
            Endpoints: map[string]string{
                "token": "https://api.linear.app/oauth/token",
            },
        },
    },
    Bindings: map[string]credential.BindingConfig{
        "linear-reader": {
            Provider: "linear",
            LinearActor: "app",
            Parameters: map[string]string{"client_id": "ADMIN_CONFIGURED_CLIENT_ID"},
            Secrets: map[string]credential.SecretSource{
                "client_secret": {SystemdCredential: "linear-client-secret"},
            },
            Scopes: []string{"read"},
        },
    },
})
```

Check `err`, call `Close` when retiring the manager, and use `Validate(Request)` while building the gateway snapshot. `New` compiles source without contacting providers or reading secrets. Call `Get(ctx, Request{Provider, Binding, Scopes})` only after authorization. Use `Result.ApplyRequest(upstreamRequest)` for request signing or header credentials. Before applying, delete the caller's value for `Result.HeaderName()` (`Authorization`, or the custom header of a `header` result) so a caller-supplied value or placeholder never reaches the provider. Call `Apply` only for the authorized destination. On upstream authentication failure, call `Invalidate` without automatically replaying the request.

Check `Result.ContainsSecret` on bounded response bodies and forwarded headers before releasing them. It covers raw credential material, Basic encoding, and JSON string escapes, not arbitrary encodings or a malicious upstream covert channel. For a response relayed as it arrives, use `Result.Scanner()`. `Scanner.Next(chunk)` returns the bytes that are safe to send and reports a match. It holds back only a trailing run that could be the start of the credential, so a credential split across reads is still caught and no prefix of it is released. Call `Scanner.Flush()` when the response ends to release the held bytes. The scanner matches the raw token, `Bearer <token>` and the Basic encodings only. It does not catch JSON-escaped or compressed forms, so a caller that streams must refuse compressed responses itself. Error bodies should remain generic.

`Manager.Binding(name)` returns a `Binding` with the non-secret routing facts of one configured binding: `Provider`, `Placeholder` and `Headers`. The gateway uses it to choose among several bindings on one destination and to set fixed headers. It never returns secret material.

`Result` and `Manager` formatting is redacted. Results serialize only kind and expiry. `Apply` and `ApplyRequest` are the only operations that export authentication values. Never log applied headers. Reload with a newly validated manager and immutable upstream bindings. The gateway owns the retiring manager's lifecycle.

## Placeholders and fixed headers

A binding may set two non-secret fields:

- `Placeholder` (`placeholder` in `pdp.json`): a string the workload holds in place of the real credential. It must be 8 to 256 bytes with no spaces, commas, double quotes, backslashes or control characters. It selects a candidate binding when one destination has several, and is returned by the gateway's local token path answer. It authorizes nothing. Policy still decides whether the caller may use that binding.
- `Headers` (`headers`): fixed request headers sent with this credential, such as an account ID. Names must be HTTP tokens and cannot be `Host`, `Content-Length`, `Connection`, `Proxy-Authorization` or `Transfer-Encoding`. `ValidHeader` reports whether a name is allowed. Values are at most 1024 bytes with no control characters. The gateway replaces any caller value for these names.

```json
"bindings": {
  "team-account": {
    "provider": "provider",
    "placeholder": "pdp-placeholder-team-account",
    "headers": {"X-Account-Id": "REPLACE_TEAM_ACCOUNT_ID"},
    "parameters": {"client_id": "REPLACE_CLIENT_ID"},
    "secrets": {"client_secret": {"file": "/run/secrets/provider-client-secret"}},
    "state_file": "/var/lib/pdp/team-account/state.json"
  }
}
```

This is the binding shape the `subscription` pack uses. Whether a real provider client accepts a placeholder in place of its token has not been tested.

In `pdp.json` the same structure sits under `credentials` as `providers` and `bindings`, with snake_case keys such as `linear_actor`, `state_file`, `systemd_credential`, `placeholder` and `headers`. A provider takes exactly one of `script` and `script_file`. The `pkg/config` loader reads `script_file` relative to the configuration file and passes its content to `New` as `Script`, so `New` itself rejects `ScriptFile`. The files in `adapters/` are the same adapters the packs under `examples/packs` ship as `adapter.star`: `static.star` in `minimal`, `github-read`, `github-spiffe` and `systemd`, `github_app.star` in `github-comment`, `linear_client_credentials.star` in `linear-read` and `linear_refresh.star` in `linear-comment`.

## Adapter capabilities

An adapter defines `acquire(request)` and returns a native credential result. `request` is an immutable dictionary with `provider`, `binding`, and a canonical tuple of `scopes`. No module loading, environment access, file APIs or general HTTP API is exposed.

| Builtin | Behavior |
| --- | --- |
| `secret(name)` | Opaque handle for one named binding secret. No string/byte conversion. |
| `parameter(name)` | Administrator parameter string. Never put secrets here. |
| `static(handle, kind="bearer", username="", header_name="", ttl_seconds=300)` | Typed bearer, Basic or custom-header result. Mounted file is reread on acquisition. |
| `aws_sigv4(access_key, secret_key, region, service="s3", ttl_seconds=300)` | Opaque secret handles for both keys. Signs the final request using AWS Signature Version 4. |
| `jwt_rs256(key, issuer)` | Opaque RS256 JWT, backdated 60 seconds, expiry nine minutes ahead. RSA keys 2048 through 8192 bits only. |
| `github_installation(endpoint, key, kind="bearer", username="")` | Signs the configured app JWT and exchanges it with mandatory fixed repository IDs and permissions. The token is injected as a Bearer token. `kind="basic"` with a `username` such as `x-access-token` injects it as Basic credentials instead, which git over HTTPS on github.com requires (the REST API accepts both). |
| `oauth_client_credentials(endpoint, client_id, client_secret, authentication="body")` | Shared OAuth grant with space-separated authorized scopes. Supports `authentication="basic"`. |
| `oauth_refresh(endpoint, client_id, client_secret=None, authentication="body", encoding="form", send_scope=False)` | Serialized, durable token-pair rotation from binding state. Without `client_secret` the grant is a public client's and sends only `client_id`. `encoding="json"` sends the grant as a JSON object. `send_scope=True` adds the binding's scopes, space separated. |
| `linear_client_credentials(endpoint, client_id, client_secret)` | Explicit app-actor client-credentials grant, comma-separated scopes. |
| `linear_refresh(endpoint, client_id, client_secret)` | Existing authorization-code grant, explicit administrator-attested app or user actor. |

`endpoint` is a configured alias for an exact administrator-selected HTTPS URL. Scripts cannot construct destination hosts, paths or query parameters. The transport disables environment proxies, redirects and compression, verifies certificates with TLS 1.2 or later, bounds response headers/bodies and connections, and applies context, connect, handshake and response deadlines. Token exchanges use fresh HTTP/1 connections with keep-alive disabled, `Request.Close` set, and no `GetBody` replay function. HTTP/2 and reused-connection transport retries are excluded. There is no automatic application-level refresh retry. An unknown rotating-grant outcome retains its durable recovery marker. Private provider CAs can be configured through `RootCAs`, never through disabled verification.

Secret files must be regular, bounded files without group/world write permission. Mounted symlinks are allowed for read-only secret rotation. Systemd names resolve under the configured `CredentialsDirectory` or `CREDENTIALS_DIRECTORY`. Exactly one file/name selector is accepted. One terminal text newline is removed. Secret bytes and provider token responses stay native. `print` is discarded, public errors are fixed codes, and script tracebacks or provider error bodies are never returned.

## Provider configuration

The executable adapters are embedded from `adapters/*.star`, rather than copied strings in tests.

### AWS Signature Version 4

An adapter returns `aws_sigv4(secret("access_key"), secret("secret_key"), region=parameter("region"))`. Both keys stay opaque in Starlark and are reread on acquisition. Apply the result with `ApplyRequest`, after authorization and after finalizing the URL and headers. An empty body uses the empty SHA256 hash. A replayable `GetBody` is hashed without consuming the request body. Non-replayable bodies, including multipart PUT streams, use `UNSIGNED-PAYLOAD` without buffering. Caller signatures, dates, payload hashes and security tokens are replaced. Presigned query authentication and signed `aws-chunked` bodies are rejected, not silently relayed with the wrong key. Temporary AWS session credentials are not supported.

Plain HTTP credential injection stays off by default. An exact upstream host and port can set `allow_http: true`, but Rego must independently allow that scheme and its resolved private addresses. The setting grants no network permission. Do not enable it for public upstreams.

S3 CopyObject and UploadPartCopy read a source named in `x-amz-copy-source`. Configure `policy_headers: [x-amz-copy-source]` on the upstream and require Rego to authorize both source and destination paths. These selected headers appear as lowercase keys with arrays of values at `input.http.headers`. Only select non-secret headers. Authorization, Cookie and hop-by-hop credential headers cannot be selected. Do not authorize bucket-wide bulk delete or listing when granting only one object's prefix.

The AWS published GET, PUT, lifecycle and list vectors are checked in `TestAWSPublishedSigV4Vectors`. `TestS3SigningIntegration` runs through the real gateway against an authenticated S3 server with streaming PUT, GET, HEAD, copy, multipart complete and abort. Set `PDP_TEST_S3_ENDPOINT`, `PDP_TEST_S3_ACCESS_KEY` and `PDP_TEST_S3_SECRET_KEY` for a disposable server. CI runs it with SeaweedFS 4.31 and also proves that anonymous and incorrect signatures are refused.

## GitHub App

Use `adapters.GitHubApp`. Configure endpoint alias `token` to the complete installation access-token endpoint, such as `https://api.github.com/app/installations/123/access_tokens`. Configure `Secrets.private_key` as a mounted RSA PEM, and `GitHub` with app ID, one to 500 repository IDs, and an explicit permission map. Empty restrictions are rejected. The helper always sends both restrictions, validates returned authority, and permits GitHub's implicit read-only metadata permission. It does not list installations or repositories. Scope requests must equal the fixed binding scope set.

Official protocol reference, verified November 9, 2026:
https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app

### Linear actors and grants

For automation, `adapters.LinearClientCredentials` requires the OAuth application's client-credentials toggle and `LinearActor: "app"`. This grant uses the app actor, returns no refresh token, and normally lasts 30 days. The runtime uses returned `expires_in`, not a hard-coded lifetime.

For an existing authorization-code installation, use `adapters.LinearRefresh`, an administrator-attested `LinearActor: "app"` or `"user"`, and a private state file. `actor=app` belongs in the initial authorization URL. It changes identity, not renewal. Authorization-code access tokens normally last 24 hours and use rotating refresh tokens with a 30-day lifetime.

All Linear scope sets must exactly match the binding, because changing client-credentials scopes can revoke sibling app-actor credentials. Keep scopes consistent across processes. Authorization-code bootstrap, browser consent, scope updates and reauthorization remain administrator workflows outside this package.

Official references, verified November 9, 2026:
https://linear.app/developers/oauth-2-0-authentication
https://linear.app/developers/oauth-actor-authorization

## Refresh durability and recovery

Provision `StateFile` in a dedicated writable directory with mode `0700`, and the state file with mode `0600`. An initial administrator-provisioned file contains `refresh_token` and the original granted `scopes`. No refresh-token value belongs in provider configuration or Starlark. The runtime stores `access_token`, `refresh_token`, `expires_at`, and `scopes` together. Generic OAuth refresh may retain an unchanged refresh token when the provider omits a replacement. Linear requires a replacement.

Every refresh locks the adjacent `.lock` file with a context-aware OS advisory lock. Every process sharing the authorization must use this locking protocol and the same local filesystem. The lock covers loading the last pair, persisting intent, exchanging, and replacing the pair. Do not use a read-only systemd credential or a projected secret mount as a writable state file. Bootstrap a separate writable state file instead.

Before sending a refresh, the runtime atomically writes and fsyncs `recovery_required: true`. It persists through cancellation, process death, unknown responses, malformed responses and failed replacement persistence. A valid replacement refresh token is retained even when access-token validation fails, with the recovery marker still set. No new access credential is returned until a complete usable pair has been written to a same-directory `0600` temporary file, fsynced, renamed, and its parent directory fsynced.

A state marked `recovery_required` cannot refresh again, including after manager reload or process restart. This is intentionally conservative: even a definitive provider error requires administrator reconciliation. Recover through the provider's documented authorization/recovery process, replace the complete state under the same lock, and reload. Never merely clear the marker or replay a historical refresh token without reconciling its outcome. Persistence failure also poisons the running binding. Removing the manager does not make marked state usable.

A login made by a provider's own CLI is usually a public client: call `oauth_refresh("token", parameter("client_id"))` with no secret, and add `encoding="json"` and `send_scope=True` when the provider's token endpoint takes a JSON body or wants the scope repeated. A public client cannot use `authentication="basic"`. The other OAuth builtins still require a client secret and a form body.

Refresh scopes must equal the binding's entire original scope set. The helper does not pretend that a broader installation can mint arbitrary requested subscopes. An omitted response scope means the provider retained the explicitly attested grant. An explicit response scope must exactly match the requested set.

## Bounds and cache semantics

Defaults: 100,000 Starlark steps, 10 seconds per acquisition, eight concurrent acquisitions, 8 KiB binding/request input, 16 KiB credential output, 64 KiB script/secret files, 256 KiB provider responses, 1,024 cache entries and a 30-second expiry margin. Configuration limits themselves have upper bounds. Acquisition saturation fails closed instead of creating an unbounded waiter queue. Identical concurrent provider/binding/canonical-scope keys share one acquisition.

Only fresh successful credentials enter the cache. Expiry-margin refresh removes the old entry before attempting acquisition. Errors never return stale tokens. Invalidation also prevents an in-flight acquisition from repopulating its invalidated entry. Different bindings and scope sets never share cached authority. Refresh rotation is serialized across processes, but token caches are process-local.

`Manager.Stats()` returns a coherent cumulative `Stats` snapshot with `Hits`, `Misses`, `Coalesced`, `Acquisitions`, `Failures`, `InFlight`, and `AcquisitionNanoseconds`. It uses the existing cache mutex without additional hot-path atomics, goroutines or provider/credential labels. Misses count valid noncached requests, including joins and concurrency saturation. Coalesced counts joining callers, including callers canceled while waiting. Acquisitions count actual adapter executions. Failures count failed actual executions, not invalid requests, saturation or joined-caller cancellation. InFlight counts executions still running. AcquisitionNanoseconds totals completed execution time including script, network, disk and rotation-lock work, excluding input validation and joined waiters. Reloading the manager resets its counters. Stats remain readable after `Close`.

Starlark is **not a hard memory sandbox**. A single native string/sequence operation can allocate substantial memory or run beyond cooperative cancellation before another instruction executes. Step, input/output, deadline and concurrency limits do not establish a heap limit. Scripts and configuration must be trusted administrator code. Hostile scripts require a separate process with operating-system memory/CPU controls, which this package does not provide. Go strings also cannot guarantee cryptographic zeroization, although native mutable secret buffers are cleared after acquisition.
