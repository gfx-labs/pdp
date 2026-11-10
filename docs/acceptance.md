# Acceptance and operator runbook

## Scope of evidence

The checked-in tests exercise PDP's code, real local Unix listeners/TLS sockets, the actual CLI lifecycle, pinned provider request-schema projections and local credential exchange/persistence contracts. A local HTTPS server is transport/security evidence, not proof that a real GitHub installation or Linear workspace accepted a request. No real provider write, deployment or SPIRE registration was authorized or executed by this implementation task.

| Acceptance boundary | Evidence/status |
| --- | --- |
| Actual CLI, direct Unix listener and inherited FD activation | `TestCLISocketReload`, including a real local TLS upstream |
| Schema-free full grant, forged headers ignored, credentials injected only after authorization | Same CLI test and gateway transport regressions |
| Invalid reload retains old snapshot, valid UID-map reload revokes a warm token cache on reused connections | Same CLI test, real `SIGHUP` lifecycle |
| Typed deny references, precise large numeric constraints and reviewed schema drift | Config loader security regression |
| Pinned real GitHub/Linear request surfaces | Schema tests and checked-in provenance |
| Concurrent scoped acquisition, expiry/invalidation and durable rotating-token state | Credential package tests, not real account acceptance |
| Real provider reads and correct Linear app/user actor | Pending approved credentials and account/workspace scope |
| Real provider comments/writes | Pending explicit approval for named disposable issues/repositories |
| Installed systemd unit lifecycle, cross-UID filesystem isolation | Pending administrator account/unit installation |
| Deployed SPIRE SVID/bundle rotation and service-account attestation | Pending installed SPIRE infrastructure and registered identities |
| Kubernetes deployment and all-replica revocation | Pending explicit cluster/deployment authorization |

## Local checks

```sh
go test -count=1 ./...
go vet ./...
go test -race -count=1 ./...
go build -o pdp ./cmd/pdp
./pdp validate --config examples/minimal.yaml
./pdp validate --config examples/github-read.yaml
./pdp validate --config examples/github-read-write.yaml
./pdp validate --config examples/linear-read.yaml
./pdp validate --config examples/linear-read-write.yaml
./pdp validate --config examples/github-app.yaml
./pdp validate --config examples/linear-oauth.yaml
./pdp validate --config examples/kubernetes/pdp.yaml
CREDENTIALS_DIRECTORY=/run/credentials/pdp.service \
  ./pdp validate --config examples/systemd/pdp.yaml
```

The systemd-credential environment supplies context for reference validation, not secret content. The Kubernetes config's offline validation does not open the Workload API. Run `TestCLISocketReload` alone to reproduce CLI acceptance without creating a real provider credential:

```sh
go test -race -count=1 -run '^TestCLISocketReload$' -v ./cmd/pdp
```

No retained test requires real provider credentials. There are no throwaway test fixtures in the acceptance path. Keep the focused security regressions and actual transport/lifecycle tests, rather than replacing them with mocked provider API success claims.

## Real GitHub acceptance, pending

An administrator must name an approved repository and issue, configure the exact `OWNER/REPOSITORY` gateway scope and GitHub App repository ID/permissions, and supply the mounted private key or token to the distinct daemon UID. Do not paste credentials into CLI options, logs or policy inputs. Start the daemon from the reviewed configuration and run read-only requests as the mapped workload UID:

```sh
./pdp request --socket /run/pdp/pdp.sock \
  --path /upstreams/github/repos/APPROVED_OWNER/APPROVED_REPOSITORY
./pdp request --socket /run/pdp/pdp.sock \
  --path /upstreams/github/repos/APPROVED_OWNER/APPROVED_REPOSITORY/issues/APPROVED_ISSUE_NUMBER
./pdp request --socket /run/pdp/pdp.sock \
  --path /upstreams/github/repos/APPROVED_OWNER/APPROVED_REPOSITORY/issues/APPROVED_ISSUE_NUMBER/comments
```

Verify the request succeeds only with the mapped identity and intended binding. A same-basename repository under a different owner must deny. A comment under the read-only profile must deny before the provider. Use a configured local counting endpoint or provider audit records to establish non-forwarding, not status alone.

Only after explicit permission for a **named disposable issue**, create a local body file and exercise the write:

```sh
# DO NOT RUN until the named issue has explicit write approval.
: "${PDP_APPROVED_DISPOSABLE_ISSUE_NUMBER:?Requires explicit named-issue approval}"
printf '%s\n' '{"body":"PDP approved disposable acceptance comment"}' > approved-comment.json
./pdp request --socket /run/pdp/pdp.sock --method POST \
  --path "/upstreams/github/repos/APPROVED_OWNER/APPROVED_REPOSITORY/issues/$PDP_APPROVED_DISPOSABLE_ISSUE_NUMBER/comments" \
  --body approved-comment.json
```

Record the resulting comment ID and actor without recording tokens. Verify the designated provider installation repository IDs and effective permissions. Any cleanup is another provider write requiring authorization. Do not silently delete comments or broaden the token to make a test pass.

## Real Linear acceptance, pending

Choose the OAuth grant and actor explicitly before provisioning. The client-credentials example uses an app actor and requires its app toggle. An already authorized user/app installation uses the refresh adapter and private durable state. Do not silently replace it with client credentials. Scope the binding to `read` and `comments:create`, and restrict gateway issues to approved UUIDs.

Create a local `approved-read.json` using an approved issue UUID:

```json
{"query":"query ApprovedIssue($id: String!) { issue(id: $id) { id identifier title } }","operationName":"ApprovedIssue","variables":{"id":"APPROVED_ISSUE_UUID"}}
```

Then issue the read request:

```sh
./pdp request --socket /run/pdp/pdp.sock --method POST \
  --path /upstreams/linear/graphql --body approved-read.json
```

Test aliases/repeated issue calls with one out-of-scope UUID and require denial of the whole request. An approved team ID does not authorize an unlisted issue. Verify the selected actor from provider-side evidence, not from an `actor` field in caller data. A provider HTTP 200 can still contain GraphQL errors, so inspect the JSON result and selected resource rather than treating the HTTP code alone as success.

Only after explicit write approval for a named disposable issue, use a local body of this form:

```json
{"query":"mutation ApprovedComment($input: CommentCreateInput!) { commentCreate(input: $input) { success comment { id body } } }","operationName":"ApprovedComment","variables":{"input":{"issueId":"APPROVED_DISPOSABLE_ISSUE_UUID","body":"PDP approved disposable acceptance comment"}}}
```

Send it with the same gateway path only after that approval. Record the actual resulting actor/comment ID, verify another issue UUID denies, and verify the `read` profile cannot create the comment. Reuse the same approved installation to test refresh persistence across daemon restart. Never overwrite an ambiguous recovery-required state to force a successful retry.

## Revocation and deployment acceptance, pending external setup

With a warm provider token, atomically install a new revision removing the principal/grant or expiring its relationship edge. Send `SIGHUP` and wait for `reload_applied` with the exact new `revision`. New authorizations must deny, including requests on a reused connection. Already-authorized requests may finish within their deadlines. On several replicas, collect acknowledgement from each or remove the stale replicas from service.

For SPIRE acceptance, rotate the gateway and caller SVIDs and trust bundles independently while sending requests. Confirm trusted current identities continue, removed identities fail on reused connections, and no caller certificate is mistaken for a provider credential. Verify attestation uses the intended namespace/service account/agent parent and an unauthorized neighboring workload cannot obtain the same identity.

For systemd, install the reviewed units only with approval, verify socket group access and a distinct daemon UID, stop/restart the service with the socket unit active, and confirm the socket is not removed or replaced. For Kubernetes, review the manifests through an explicitly discovered `kubie` context before any authorized apply. Neither template validation nor TCP readiness proves provider or mTLS acceptance.

## Resource measurements

Measured on November 9, 2026 with Go 1.27.3 on Linux x86_64, Intel Core i9-14900. Reproduce with:

```sh
make build
go run ./cmd/pdpbench -pdp ./bin/pdp -requests 1000 -concurrency 4
```

The harness starts the actual daemon with kernel UID authentication, one schema-free full grant, embedded OPA, a Starlark OAuth adapter and a loopback TLS upstream. These results do not include pinned-schema normalization, real provider latency or SPIRE processes. The November 9 run at 09:56 UTC, before moving grant evaluation from Go into Rego, produced:

| Measurement | Result |
| --- | --- |
| Idle gateway RSS | 30,120 KiB, approximately 29.4 MiB |
| Sampled active peak RSS | 34,456 KiB, approximately 33.6 MiB |
| Idle process CPU over 1.000 seconds | 0 observed CPU ticks, with 10 ms tick resolution |
| Active process CPU / elapsed time | 1,310 ms / 821.6 ms, with concurrent execution |
| Warm request p50 / p95 / p99 | 3.079 / 4.526 / 4.903 ms |
| Cold request including local token acquisition | 6.026 ms |
| Separate local client-credentials reacquisition | 2.444 ms |
| Warm requests / client concurrency | 1,000 / 4 |
| Daemon credential exchanges | 1, including the cold request |

RSS comes from the daemon's `/proc` data, not the benchmark client. Active RSS is sampled, not an exact allocator high-water mark. Acquisition uses fresh HTTP/1 TLS connections. The separate invalidation/reacquisition check adds two exchanges outside the daemon's single-exchange count. A zero observed idle CPU count is a measurement-resolution result, not a guarantee of zero CPU consumption. Provider refresh latency, schema-restricted workload costs, SPIRE server/agent resource use and installed deployment measurements remain pending.

Final local verification also passed the uncached race suite, vet, build, all eight offline configuration examples, the checked-in explanation and both structured catalogs. `go mod verify` verified all modules, and `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` reported no vulnerabilities on November 9, 2026. These are point-in-time results, not a substitute for later dependency scans.

### Rego authorization migration, November 10, 2026

The migrated source embeds `pkg/policy/base.rego` as the authorization policy and
loads YAML/JSON configuration as `data.pdp.config`. Go no longer supplies matched
grants or denials. The unchanged full race suite, vet and build passed. An
isolated old/new comparison matched all 1,296 tested decisions across profiles,
grant/deny/mandatory constraints, resource scopes, object shapes and numeric
values. That comparison remained outside the repository. All nine current
configuration examples and 20 GitHub/Linear request cases passed against real
local Unix/TLS connections. Denied requests did not acquire credentials or reach
the local upstream. Existing security regressions remain, with no migration
scaffolding tests committed. This does not establish real-provider acceptance.

The same benchmark command on the migrated working tree at 07:37 UTC, using
the same Go version, hardware, schema-free policy and local upstream, produced:

| Measurement | Rego authorization result |
| --- | --- |
| Idle gateway RSS | 31,188 KiB, approximately 30.5 MiB |
| Sampled active peak RSS | 39,748 KiB, approximately 38.8 MiB |
| Idle process CPU over 1.000 seconds | 0 observed CPU ticks, with 10 ms tick resolution |
| Active process CPU / elapsed time | 1,860 ms / 1,048.2 ms |
| Warm request p50 / p95 / p99 | 3.927 / 6.047 / 7.140 ms |
| Cold request including local token acquisition | 7.616 ms |
| Separate local client-credentials reacquisition | 2.494 ms |
| Warm requests / client concurrency | 1,000 / 4 |
| Daemon credential exchanges | 1, including the cold request |

These single-run measurements show additional evaluation cost rather than a
claim that moving rules into Rego is free. They are not a controlled performance
comparison, a schema-restricted workload measurement or a production latency
target.

For subsequent measurements, record the binary revision, Go version, selected schema/policy sizes, request mix, concurrency and hardware. Measure gateway idle RSS/CPU, warm authorized-request latency, acquisition/refresh latency and active memory separately. Use sanitized credential and gateway counters to distinguish cached requests from refreshes. Measure SPIRE server and agent separately when deployed. Keep the tested boundary and external gaps explicit.
