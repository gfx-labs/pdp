# Acceptance and operator runbook

## Scope of evidence

The checked-in tests exercise PDP's code, real local Unix listeners and TLS sockets, the actual CLI lifecycle, pinned provider request-schema projections, and local credential exchange and persistence contracts. A local HTTPS server is transport and security evidence. It does not show that a real GitHub installation or Linear workspace accepts a request.

No real provider read or write, SPIRE deployment, Kubernetes deployment or installed systemd unit has been run against this design. No real-provider, SPIRE or Kubernetes acceptance has been done.

| Acceptance boundary | Evidence and status |
| --- | --- |
| Five packs serve their own Rego, schema and adapter over a real Unix socket against a local TLS server: 16 request cases and 5 other-UID denials. Denied requests neither acquire a credential nor reach the upstream. | `TestPacksServeTheirRequests` in `cmd/pdp` |
| SPIFFE and systemd packs load, and the SPIFFE policy separates the named workload from a neighbor in the same trust domain | `TestDeploymentPacksValidate`, offline only |
| Actual CLI, direct Unix listener and inherited FD activation. Forged identity headers ignored. Credentials injected only after authorization. | `TestCLISocketReload` |
| Invalid reload keeps the old snapshot. Rewriting the Rego file and sending `SIGHUP` revokes a warm credential cache on reused connections. | `TestCLISocketReload` |
| Default deny, malformed results fail closed, removed builtins, exact JSON numbers, snapshot freezing | `pkg/policy` tests |
| Loader accepts only JSON `pdp.config/v2`, rejects removed fields, resolves files and policy data | `pkg/config` tests |
| Unix peer binding, inherited socket, socket path ownership | `pkg/auth` tests |
| SPIFFE verification and rotation against a local Workload API server | `TestSPIFFERotation`. This is not SPIRE. |
| Gateway ambiguity, response boundary, TLS, reload and GraphQL occurrence tests | `pkg/gateway` tests |
| Pinned GitHub and Linear request surfaces | `pkg/schema` tests and `pkg/schema/testdata/README.md` |
| Concurrent scoped acquisition, expiry, invalidation, durable rotating-token state | `pkg/credential` tests. These are not real account acceptance. |
| Independent review of the direct-Rego engine and the identity change | Not done. See [security-review.md](security-review.md). |
| Real provider reads and the correct Linear app or user actor | Pending approved credentials and account scope |
| Real provider comments and writes | Pending explicit approval for named disposable issues and repositories |
| Installed systemd unit lifecycle, cross-UID filesystem isolation | Pending administrator account and unit installation |
| Deployed SPIRE SVID and bundle rotation, service-account attestation | Pending installed SPIRE and registered identities |
| Kubernetes deployment and all-replica revocation | Pending explicit cluster authorization |

A policy author who omits the `input.schema_digest` or `input.identity` check gets exactly what they wrote. No test can catch that in a policy it has not seen. Review each deployed `policy.rego` and run `pdp explain` with an unnamed caller and a changed digest.

## Local checks

```sh
make build
go test -count=1 ./...
go vet ./...
go test -race -count=1 ./...
for pack in minimal github-read github-comment linear-read linear-comment github-spiffe; do
  bin/pdp validate --config examples/packs/$pack/pdp.json
done
CREDENTIALS_DIRECTORY=/run/credentials/pdp.service \
  bin/pdp validate --config examples/packs/systemd/pdp.json
bin/pdp explain --config examples/packs/github-read/pdp.json \
  --input examples/packs/github-read/explain/read-issue.json
bin/pdp explain --config examples/packs/github-read/pdp.json \
  --input examples/packs/github-read/explain/other-uid.json
bin/pdp explain --config examples/packs/github-spiffe/pdp.json \
  --input examples/packs/github-spiffe/explain/neighbor-workload.json
```

`CREDENTIALS_DIRECTORY` supplies context for validation and no secret content. Validation of the SPIFFE pack does not open the Workload API. Each `explain` is offline and makes no upstream request. The first prints `"allow": true`. The second and third print `"allow": false` with a reason.

Run the transport and lifecycle tests alone:

```sh
go test -race -count=1 -run '^(TestPacksServeTheirRequests|TestDeploymentPacksValidate|TestCLISocketReload)$' -v ./cmd/pdp
```

No test requires real provider credentials. Keep the focused security regressions and transport tests rather than replacing them with mocked provider success claims.

## Real GitHub acceptance, pending

Use the `github-read` pack, or `github-comment` for the write step. An administrator must name an approved repository and issue, set `allowed_uids` and `allowed_repositories` in `policy.rego`, and supply the token (or the GitHub App key, App ID, repository IDs and permissions for `github-comment`) to the distinct daemon UID. Do not paste credentials into CLI options, logs or policy input. Start the daemon from the reviewed configuration and run read-only requests as an allowed workload UID:

```sh
bin/pdp request --socket /run/pdp/pdp.sock \
  --path /upstreams/github/repos/APPROVED_OWNER/APPROVED_REPOSITORY
bin/pdp request --socket /run/pdp/pdp.sock \
  --path /upstreams/github/repos/APPROVED_OWNER/APPROVED_REPOSITORY/issues/APPROVED_ISSUE_NUMBER
bin/pdp request --socket /run/pdp/pdp.sock \
  --path /upstreams/github/repos/APPROVED_OWNER/APPROVED_REPOSITORY/issues/APPROVED_ISSUE_NUMBER/comments
```

Verify that the request succeeds only for the allowed UID. A request from another UID must return `403`. A same-name repository under a different owner must deny. A comment under the `github-read` policy must deny before the provider. Use a local counting endpoint or provider audit records to show non-forwarding, not the status code alone.

Only after explicit permission for a **named disposable issue**, create a body file and exercise the write against the `github-comment` pack:

```sh
# DO NOT RUN until the named issue has explicit write approval.
: "${PDP_APPROVED_DISPOSABLE_ISSUE_NUMBER:?Requires explicit named-issue approval}"
printf '%s\n' '{"body":"PDP approved disposable acceptance comment"}' > approved-comment.json
bin/pdp request --socket /run/pdp/pdp.sock --method POST \
  --path "/upstreams/github/repos/APPROVED_OWNER/APPROVED_REPOSITORY/issues/$PDP_APPROVED_DISPOSABLE_ISSUE_NUMBER/comments" \
  --body approved-comment.json
```

The `github-comment` policy allows comments on every issue in the repository. To limit it to named issues, add a check on `input.http.path_params.issue_number` first. Record the comment ID and actor without recording tokens. Verify the installation's repository IDs and effective permissions. Cleanup is another provider write that needs authorization.

## Real Linear acceptance, pending

Choose the OAuth grant and actor before provisioning. `linear-read` uses client credentials and the app actor, which requires the application's client-credentials toggle. `linear-comment` uses an existing authorization-code installation with refresh and private durable state. Do not replace one with the other. Scope the binding to `read` and `comments:create`, and set `allowed_issues` in `policy.rego` to approved issue UUIDs.

Copy `examples/packs/linear-read/requests/read-issue.json`, replace `APPROVED_ISSUE_UUID`, and send it:

```sh
bin/pdp request --socket /run/pdp/pdp.sock --method POST \
  --path /upstreams/linear/graphql --body approved-read.json
```

Send `requests/read-mixed-scope.json` (one approved and one unapproved issue) and require denial of the whole request. A team ID does not authorize an unlisted issue. Verify the actor from provider-side evidence, not from a field in caller data. A provider HTTP 200 can contain GraphQL errors, so inspect the JSON result.

Only after explicit write approval for a named disposable issue, send `examples/packs/linear-comment/requests/create-comment.json` with `APPROVED_ISSUE_UUID` replaced. Record the resulting actor and comment ID. Verify that `reject-alternate-target.json` denies and that the `linear-read` policy cannot create the comment. Reuse the same installation to test refresh persistence across a daemon restart. Never overwrite an ambiguous recovery-required state to force a retry.

## Revocation and deployment acceptance, pending external setup

With a warm provider token, remove the caller from `allowed_uids` (or `allowed_workloads`), set a new `revision` in `pdp.json`, replace the files atomically, and send `SIGHUP`. Wait for `reload_applied` with the exact new `revision`. New requests must return `403`, including on a reused connection. Already-authorized requests may finish within their deadlines. `TestCLISocketReload` shows this against a local upstream. With several replicas, collect the acknowledgement from each or remove the stale ones from service.

For SPIRE, rotate the gateway and caller SVIDs and trust bundles independently while sending requests. Confirm that named current identities continue, that a removed identity fails on a reused connection, and that a caller certificate is never taken for a provider credential. Confirm that attestation uses the intended namespace, service account and agent parent, and that a neighboring workload in the trust domain gets `403`.

For systemd, install the reviewed units only with approval, verify socket group access and a distinct daemon UID, stop and restart the service with the socket unit active, and confirm that the socket is not removed or replaced. For Kubernetes, review the manifest through an explicitly discovered `kubie` context before any authorized apply. Template validation and TCP readiness prove neither provider nor mTLS acceptance.

## Resource measurements

Reproduce with:

```sh
make build
go run ./cmd/pdpbench -pdp ./bin/pdp -requests 1000 -concurrency 4
```

All three runs below use Go 1.27.3 on Linux x86_64, Intel Core i9-14900, 1,000 warm requests at client concurrency 4. The harness starts the real daemon with kernel UID authentication, embedded OPA, a Starlark OAuth adapter and a loopback TLS upstream, with no schema. The runs do not include pinned-schema normalization, real provider latency or SPIRE processes. Each is a single run, not a controlled comparison. RSS comes from the daemon's `/proc` data. Active RSS is sampled, not an allocator high-water mark. A zero idle CPU count is a result at 10 ms tick resolution, not a guarantee of zero CPU use.

### Design 1: grants evaluated in Go, November 9, 2026, 09:56 UTC

This measured the first design, with one schema-free full grant and the grant check in Go before it moved into Rego. That design no longer exists.

| Measurement | Result |
| --- | --- |
| Idle gateway RSS | 30,120 KiB, approximately 29.4 MiB |
| Sampled active peak RSS | 34,456 KiB, approximately 33.6 MiB |
| Idle process CPU over 1.000 seconds | 0 observed CPU ticks |
| Active process CPU / elapsed time | 1,310 ms / 821.6 ms |
| Warm request p50 / p95 / p99 | 3.079 / 4.526 / 4.903 ms |
| Cold request including local token acquisition | 6.026 ms |
| Separate local client-credentials reacquisition | 2.444 ms |
| Daemon credential exchanges | 1, including the cold request |

### Design 2: embedded base.rego over YAML data, November 10, 2026, 07:37 UTC

This measured the design that embedded a fixed `base.rego` and loaded YAML or JSON configuration as `data.pdp.config`. That design no longer exists. The report that accompanied it compared 1,296 decisions against Design 1 and ran nine configuration examples. The comparison was outside the repository. It does not apply to the current engine.

| Measurement | Result |
| --- | --- |
| Idle gateway RSS | 31,188 KiB, approximately 30.5 MiB |
| Sampled active peak RSS | 39,748 KiB, approximately 38.8 MiB |
| Idle process CPU over 1.000 seconds | 0 observed CPU ticks |
| Active process CPU / elapsed time | 1,860 ms / 1,048.2 ms |
| Warm request p50 / p95 / p99 | 3.927 / 6.047 / 7.140 ms |
| Cold request including local token acquisition | 7.616 ms |
| Separate local client-credentials reacquisition | 2.494 ms |
| Daemon credential exchanges | 1, including the cold request |

### Design 3: direct administrator Rego, November 11, 2026

This is the current design. The binary was built from the working tree on top of commit `feeb336`. The policy is one `allow` rule on auth method, UID, provider and binding. It is much smaller than the shipped pack policies. The numbers below come from one run of the command above and are exact:

| Measurement | Result |
| --- | --- |
| Idle gateway RSS | 28,168 KiB, approximately 27.5 MiB |
| Sampled active peak RSS | 33,760 KiB, approximately 33.0 MiB |
| Idle process CPU over 1.000 seconds | 0 ms |
| Active process CPU / elapsed time | 1,510 ms / 1,259.3 ms |
| Warm request p50 / p95 / p99 | 4.303 / 9.067 / 16.297 ms |
| Cold request including local token acquisition | 6.781 ms |
| Separate local client-credentials reacquisition | 3.437 ms |
| Daemon credential exchanges | 1, including the cold request |

The p95 and p99 are higher than in Design 1 and 2, and a single run cannot say whether that is the design or machine noise. Do not read these as a performance target. Provider refresh latency, schema-restricted workloads, the shipped pack policies, SPIRE server and agent resource use, and installed deployments have not been measured.

For later measurements, record the binary revision, Go version, schema and policy sizes, request mix, concurrency and hardware. Measure gateway idle RSS and CPU, warm authorized-request latency, acquisition and refresh latency, and active memory separately. Measure SPIRE server and agent separately when they are deployed. Do not infer that a combined deployment is lightweight from gateway numbers alone.
