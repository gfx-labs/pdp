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

Check `err`, call `Close` when retiring the manager, and use `Validate(Request)` while building the gateway snapshot. `New` compiles source without contacting providers or reading secrets. Call `Get(ctx, Request{Provider, Binding, Scopes})` only after authorization. Call `Result.Apply(upstreamHeaders)` only for the fixed authorized upstream. On upstream authentication failure, call `Invalidate` without automatically replaying the request. Check `Result.ContainsSecret` on bounded response bodies and forwarded headers before releasing them. Error bodies should remain generic. Reflection detection covers raw credential material, Basic encoding, and JSON string escapes, not arbitrary encodings or a malicious upstream covert channel.

`Result` and `Manager` formatting is redacted. Results serialize only kind and expiry. `Apply` is deliberately the only operation that exports an authentication value. Never log applied headers. Reload with a newly validated manager and immutable route bindings. The gateway owns the retiring manager's lifecycle.

In `pdp.json` the same structure sits under `credentials` as `providers` and `bindings`, with snake_case keys such as `linear_actor`, `state_file` and `systemd_credential`. A provider takes exactly one of `script` and `script_file`. The `pkg/config` loader reads `script_file` relative to the configuration file and passes its content to `New` as `Script`, so `New` itself rejects `ScriptFile`. The files in `adapters/` are the same adapters the packs under `examples/packs` ship as `adapter.star`: `static.star` in `minimal`, `github-read`, `github-spiffe` and `systemd`, `github_app.star` in `github-comment`, `linear_client_credentials.star` in `linear-read` and `linear_refresh.star` in `linear-comment`.

## Adapter capabilities

An adapter defines `acquire(request)` and returns a native credential result. `request` is an immutable dictionary with `provider`, `binding`, and a canonical tuple of `scopes`. No module loading, environment access, file APIs or general HTTP API is exposed.

| Builtin | Behavior |
| --- | --- |
| `secret(name)` | Opaque handle for one named binding secret. No string/byte conversion. |
| `parameter(name)` | Administrator parameter string. Never put secrets here. |
| `static(handle, kind="bearer", username="", header_name="", ttl_seconds=300)` | Typed bearer, Basic or custom-header result. Mounted file is reread on acquisition. |
| `jwt_rs256(key, issuer)` | Opaque RS256 JWT, backdated 60 seconds, expiry nine minutes ahead. RSA keys 2048 through 8192 bits only. |
| `github_installation(endpoint, key)` | Signs the configured app JWT and exchanges it with mandatory fixed repository IDs and permissions. |
| `oauth_client_credentials(endpoint, client_id, client_secret, authentication="body")` | Shared OAuth grant with space-separated authorized scopes. Supports `authentication="basic"`. |
| `oauth_refresh(endpoint, client_id, client_secret, authentication="body")` | Serialized, durable token-pair rotation from binding state. |
| `linear_client_credentials(endpoint, client_id, client_secret)` | Explicit app-actor client-credentials grant, comma-separated scopes. |
| `linear_refresh(endpoint, client_id, client_secret)` | Existing authorization-code grant, explicit administrator-attested app or user actor. |

`endpoint` is a configured alias for an exact administrator-selected HTTPS URL. Scripts cannot construct destination hosts, paths or query parameters. The transport disables environment proxies, redirects and compression, verifies certificates with TLS 1.2 or later, bounds response headers/bodies and connections, and applies context, connect, handshake and response deadlines. Token exchanges use fresh HTTP/1 connections with keep-alive disabled, `Request.Close` set, and no `GetBody` replay function. HTTP/2 and reused-connection transport retries are excluded. There is no automatic application-level refresh retry. An unknown rotating-grant outcome retains its durable recovery marker. Private provider CAs can be configured through `RootCAs`, never through disabled verification.

Secret files must be regular, bounded files without group/world write permission. Mounted symlinks are allowed for read-only secret rotation. Systemd names resolve under the configured `CredentialsDirectory` or `CREDENTIALS_DIRECTORY`. Exactly one file/name selector is accepted. One terminal text newline is removed. Secret bytes and provider token responses stay native. `print` is discarded, public errors are fixed codes, and script tracebacks or provider error bodies are never returned.

## Provider configuration

The executable adapters are embedded from `adapters/*.star`, rather than copied strings in tests.

### GitHub App

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

Refresh scopes must equal the binding's entire original scope set. The helper does not pretend that a broader installation can mint arbitrary requested subscopes. An omitted response scope means the provider retained the explicitly attested grant. An explicit response scope must exactly match the requested set.

## Bounds and cache semantics

Defaults: 100,000 Starlark steps, 10 seconds per acquisition, eight concurrent acquisitions, 8 KiB binding/request input, 16 KiB credential output, 64 KiB script/secret files, 256 KiB provider responses, 1,024 cache entries and a 30-second expiry margin. Configuration limits themselves have upper bounds. Acquisition saturation fails closed instead of creating an unbounded waiter queue. Identical concurrent provider/binding/canonical-scope keys share one acquisition.

Only fresh successful credentials enter the cache. Expiry-margin refresh removes the old entry before attempting acquisition. Errors never return stale tokens. Invalidation also prevents an in-flight acquisition from repopulating its invalidated entry. Different bindings and scope sets never share cached authority. Refresh rotation is serialized across processes, but token caches are process-local.

`Manager.Stats()` returns a coherent cumulative `Stats` snapshot with `Hits`, `Misses`, `Coalesced`, `Acquisitions`, `Failures`, `InFlight`, and `AcquisitionNanoseconds`. It uses the existing cache mutex without additional hot-path atomics, goroutines or provider/credential labels. Misses count valid noncached requests, including joins and concurrency saturation. Coalesced counts joining callers, including callers canceled while waiting. Acquisitions count actual adapter executions. Failures count failed actual executions, not invalid requests, saturation or joined-caller cancellation. InFlight counts executions still running. AcquisitionNanoseconds totals completed execution time including script, network, disk and rotation-lock work, excluding input validation and joined waiters. Reloading the manager resets its counters. Stats remain readable after `Close`.

Starlark is **not a hard memory sandbox**. A single native string/sequence operation can allocate substantial memory or run beyond cooperative cancellation before another instruction executes. Step, input/output, deadline and concurrency limits do not establish a heap limit. Scripts and configuration must be trusted administrator code. Hostile scripts require a separate process with operating-system memory/CPU controls, which this package does not provide. Go strings also cannot guarantee cryptographic zeroization, although native mutable secret buffers are cleared after acquisition.
