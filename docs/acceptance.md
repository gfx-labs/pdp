# Acceptance and operator runbook

## Scope of evidence

The checked-in tests exercise PDP's code, real local Unix listeners and TLS sockets, a generated interception CA, a local DNS server, the actual CLI lifecycle, pinned provider request-schema projections, and local credential exchange and persistence contracts. A local HTTPS server is transport and security evidence. It does not show that a real GitHub installation, Linear workspace or any other provider accepts a request.

The SPIFFE listener and `pdp forward` were also run by hand against a real SPIRE server and agent as local processes on one machine. See [SPIRE run on one machine](#spire-run-on-one-machine). That run used the `unix` workload attestor and a join token. It is not a SPIRE deployment.

No real provider read or write, SPIRE deployment with the Kubernetes attestor or the SPIFFE CSI driver, Kubernetes deployment, cert-manager or trust-manager setup, or installed systemd unit has been run against this design. Not established either: whether Jcode accepts each provider's placeholder in the format that provider's client expects, and whether DNS steering and TLS interception cover every connection a subscription client makes. HTTP/2 and DNS over TCP are not implemented.

| Acceptance boundary | Evidence and status |
| --- | --- |
| The packs serve their own Rego, schema and adapter over a real Unix socket against a local TLS server, with absolute-form `https://` requests, and deny the same requests from another UID. Denied requests neither acquire a credential nor reach the upstream. | `TestPacksServeTheirRequests` in `cmd/pdp` |
| SPIFFE and systemd packs load, and the SPIFFE policy separates the named workload from a neighbor in the same trust domain | `TestDeploymentPacksValidate`, offline only |
| Actual CLI, direct Unix listener and inherited FD activation. Forged identity headers ignored. Credentials injected only after authorization. | `TestCLISocketReload` |
| Invalid reload keeps the old snapshot. Rewriting the Rego file and sending `SIGHUP` revokes a warm credential cache on reused connections. | `TestCLISocketReload` |
| Default deny, malformed results fail closed, removed builtins, exact JSON numbers, snapshot freezing | `pkg/policy` tests |
| Loader accepts only JSON `pdp.config/v3`, rejects `pdp.config/v2` and removed fields such as `routes`, resolves files and policy data | `pkg/config` tests |
| Unix peer binding, inherited socket, socket path ownership | `pkg/auth` tests |
| SPIFFE verification and rotation against a local Workload API server | `TestSPIFFERotation`. This is not SPIRE. For real SPIRE see the manual run below. |
| `pdp forward` relays a plain loopback connection over SPIFFE mTLS: the gateway listener authenticates the workload's ID, a half-closed client gets its response, a gateway with another ID is refused | `TestForwardPresentsWorkloadSVID`, local Workload API server. Not run in a pod. For curl and git through it see the manual run below. |
| `pdp forward --check` passes against a running forwarder without making it dial its gateway, and fails against a closed port | `TestForwardCheck`. Not run as a kubelet probe. |
| A request that fails authentication on a kept-alive connection gets `401` with `Connection: close`, and the connection is closed | `TestUnauthenticatedConnectionIsClosed` |
| A SPIFFE connection whose certificate is in the last quarter of its validity gets its normal `200` with `Connection: close` and is then closed, for a direct request and inside an intercepted `CONNECT`, where the tunnel closes too. A fresh certificate and a Unix caller keep their connections. | `TestSPIFFEConnectionRetiresBeforeExpiry`, real TLS with SVIDs from a local Workload API server |
| Gateway ambiguity, response boundary, TLS, reload and GraphQL occurrence tests on schema-backed upstreams | `pkg/gateway` tests |
| A destination with no upstream entry is decided by policy and gets no credential. A denied name is never resolved. Policy sees resolved addresses and can refuse a name that resolves to loopback. | `TestUnlistedDestinationsAreDecidedByPolicy` |
| `CONNECT` is intercepted with a CA leaf, each inner request is authorized and credentialed, an inner request naming another host is refused, and `CONNECT` without a CA is refused | `TestConnectInterception` |
| A tunnel upstream is relayed unread with the real server certificate and no credential. A denied tunnel is not opened. | `TestOpaqueTunnel` |
| A WebSocket upgrade is authorized, credentialed and relayed both ways, directly and inside intercepted TLS CONNECT. Real binary echo and unsolicited server messages survive both timeouts. Origin close terminates the relay. A denied host gets 403 without DNS or origin traffic. | `TestWebSocketRelay`, `TestWebSocketConnectRelay` |
| A streamed response is relayed before it ends. A credential split across two writes cuts the connection before it is sent. | `TestStreamedResponse` |
| Placeholders select one of two bindings, policy refuses an ungranted one, token paths are answered locally with `expires_in` 3600, and caller authentication headers are replaced | `TestPlaceholderBindings` |
| A transparent TLS caller is identified as `ip:127.0.0.1`, and `Host` that disagrees with SNI is refused | `TestTransparentListener` |
| DNS answers only configured names with the gateway address and forwards or refuses the rest | `TestSteersOnlyConfiguredNames` in `pkg/steer` |
| Pinned GitHub and Linear request surfaces | `pkg/schema` tests and `pkg/schema/testdata/README.md` |
| Concurrent scoped acquisition, expiry, invalidation, durable rotating-token state | `pkg/credential` tests. These are not real account acceptance. |
| Independent review of the direct-Rego engine, the identity change and the forward proxy | Not done. See [security-review.md](security-review.md). |
| Real provider reads and the correct Linear app or user actor | Pending approved credentials and account scope |
| Real provider comments and writes | Pending explicit approval for named disposable issues and repositories |
| Installed systemd unit lifecycle, cross-UID filesystem isolation | Pending administrator account and unit installation |
| SPIRE issuance and SVID rotation with the `unix` attestor on one machine | Run by hand once. See [SPIRE run on one machine](#spire-run-on-one-machine). |
| Deployed SPIRE: Kubernetes service-account attestation, the SPIFFE CSI driver, trust bundle rotation | Pending installed SPIRE and registered identities |
| Kubernetes deployment and all-replica revocation | Pending explicit cluster authorization |
| The interception CA replaced under PDP in the kubelet's Secret volume layout, with a new intermediate and key under the same root | Run by hand once. See [Interception CA replaced while serving](#interception-ca-replaced-while-serving). |
| cert-manager issuance and renewal of the interception CA, trust-manager distribution of its root | Not tried |
| A real subscription client (such as Jcode) working through placeholders, DNS steering and interception | Not tried |

A policy author who omits the `input.identity`, `input.destination`, `input.binding` or `input.schema_digest` check gets exactly what they wrote. No test can catch that in a policy it has not seen. Review each deployed `policy.rego` and run `pdp explain` with an unnamed caller and a changed digest.

## Local checks

```sh
make build
go test -count=1 ./...
go vet ./...
go test -race -count=1 ./...
for pack in minimal github-read github-comment linear-read linear-comment github-spiffe egress subscription; do
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

## SPIRE run on one machine

Run once by hand on November 14, 2026 (UTC), on Linux x86_64. It is not a checked-in test and nothing reruns it. Every process ran as one UID on loopback and Unix sockets. No container, cluster or real provider credential was involved.

Versions: SPIRE 1.16.0 (`spire-1.16.0-linux-amd64-musl.tar.gz` from the GitHub release, SHA-256 checked against the published `_sha256sum.txt`), Go 1.27.3, curl 8.14.1, git 2.47.3, OpenSSL 3.5.7.

Setup:

- `spire-server run` with trust domain `p7.test`, the `sql` datastore on sqlite3, the `disk` key manager and the `join_token` node attestor. `spire-agent run -joinToken ...` with the `unix` workload attestor and `discover_workload_path = true`.
- All workloads share one UID, so the entries tell them apart by executable path. The built `pdp` binary was copied to four paths. Three entries were created with `spire-server entry create -selector unix:uid:1000 -selector unix:path:<copy> -x509SVIDTTL 90`:

  | Copy | SPIFFE ID | Ran as |
  | --- | --- | --- |
  | `bin/pdp-gateway` | `spiffe://p7.test/pdp` | `pdp serve` |
  | `bin/pdp-worker` | `spiffe://p7.test/workload/worker` | `pdp forward` on `127.0.0.1:13128` |
  | `bin/pdp-other` | `spiffe://p7.test/workload/other` | `pdp forward` on `127.0.0.1:13129` |
  | `bin/pdp-unregistered` | none | `pdp forward` |

- `pdp serve` had only `transport.spiffe` on `127.0.0.1:18443`, an `interception` CA made with `openssl`, `ca_file` naming a second generated CA, and one upstream, `localhost:19443`, with a `static` binding whose token file held a dummy string. The policy allowed `spiffe://p7.test/workload/worker` to reach `localhost:19443` with that binding and nothing else.
- The upstream was a small Go TLS server on `127.0.0.1:19443` with a certificate from the second CA. `/echo` answered with the count and SHA-256 of the `Authorization` values it received. It also served a bare git repository as static files.
- The clients were `curl` and `git` with `HTTPS_PROXY=http://127.0.0.1:13128` and a CA bundle holding only the interception CA.

Results:

| Check | Result |
| --- | --- |
| `curl -H 'Authorization: Bearer caller-supplied-value' https://localhost:19443/echo` through the worker forwarder | `200`. The upstream received one `Authorization` value, and its SHA-256 was that of `Bearer <dummy token>`, not of the caller's value. The audit line had `"principal":"spiffe://p7.test/workload/worker"`, `"binding":"local-upstream"`, `"matched_rules":["worker-call"]`, `"outcome":"forwarded"`. |
| `git ls-remote https://localhost:19443/repo.git` through the worker forwarder | Printed the seeded commit for `refs/heads/main`. This is the dumb HTTP protocol, read only. |
| `curl https://127.0.0.1:19443/echo` and `curl https://example.com/` through the worker forwarder | `403` with `{"error":"forbidden"}` for both. `CONNECT` itself answered `200`, and the refusal came on the request inside it. |
| `curl https://localhost:19443/echo` through the forwarder running as `workload/other` | `403`. The audit line named `spiffe://p7.test/workload/other`. |
| `pdp forward` from the unregistered copy | Exited 1 after 10 seconds with `cannot initialize SPIFFE Workload API`. The agent logged `No identity issued` with `registered=false`. |
| Rotation, new connections: one request every 15 seconds for 210 seconds through each forwarder | Worker `200` and other `403` every time. The gateway presented six different SVID serial numbers in that time, and the agent renewed the worker SVID about every 40 seconds. |
| Rotation, one kept-alive connection: 12 requests 20 seconds apart from one `curl` | Requests 40 and 60 seconds after the connection opened, after both the worker and gateway SVIDs had been renewed, got `200` on the same connection. The request at 80 seconds, after the SVID the connection was opened with had expired, got `401`. PDP closed the connection, curl opened a new one and the next request got `200`. The same happened once more at 180 seconds. |

Two things this run found:

1. **A kept-alive connection does not outlive the SVID it was opened with.** PDP verifies the client certificate again on every request, and that check includes the certificate's expiry. Renewal does not help an open connection, because TLS 1.3 has no way to present a new certificate on it. Before this run, PDP answered such a request with `401` and kept the connection open, so a client that reuses connections got `401` for every later request. In the first pass of this run, six requests in a row failed that way. PDP now sends `Connection: close` with the `401` and closes the connection. In this run the request that met the expiry still failed once, and curl did not retry it. That is fixed by retiring the connection earlier, see [the second run](#second-run-connections-retired-before-expiry).
2. **An upstream that echoes the injected credential is cut off.** The first version of the `/echo` handler returned the `Authorization` value. PDP ended that response with outcome `credential_reflected`, as designed, and curl reported an empty reply. The handler was changed to return a hash.

### Second run: connections retired before expiry

PDP now closes a SPIFFE connection after a response once less than a quarter of its certificate's validity remains. See [Transport](configuration.md#transport). This was run once by hand on November 14, 2026 (UTC), with the same versions and the same kind of setup as above, in its own directory with its own SPIRE server and agent, trust domain `rot2.test` and 90 second SVIDs.

One `curl` process sent a request every 10 seconds for 5 minutes through `pdp forward`, with connection reuse on:

| Measure | Result |
| --- | --- |
| Requests | 31 |
| `200` | 31 |
| `401` | 0, in curl's output and in PDP's audit log |
| Connections curl opened | 6. It reused a connection for 4 to 8 requests, then opened a new one after PDP closed the old one. |
| SVID renewals logged by the agent in the whole run | 18, for the two entries together |

The forwarder logged nothing. A first attempt got `403` for every request because the policy written for the run named the wrong upstream port. That was an error in the test setup, and the numbers above are from the run after it was corrected.

### Third run: a response that streams past the SVID's expiry

Run once by hand on November 14, 2026 (UTC), with PDP built from `cfd86c5`, in its own directory with its own SPIRE server and agent, trust domain `rot3.test` and 90 second SVIDs. The upstream sent one server-sent event every 5 seconds for 240 seconds, 48 events and 711 bytes in all. A small Go client opened a `CONNECT` through `pdp forward`, spoke TLS inside it and read the stream.

| Case | Client received | PDP audit line | After the stream |
| --- | --- | --- | --- |
| The stream starts on a new connection. Its SVID expired 79 seconds later, 161 seconds before the stream ended. | 48 of 48 events, no read error. The response did not carry `Connection: close`. | `forwarded`, `200`, `bytes_received` 711, `duration_ms` 240045 | The next request on the same connection got `401` with `Connection: close`. |
| The stream starts on a connection already in its last quarter. Its SVID expired 25 seconds later, 216 seconds before the stream ended. | 48 of 48 events, no read error. The response carried `Connection: close`. | `forwarded`, `200`, `bytes_received` 711, `duration_ms` 240165 | PDP closed the connection. The next write got end of file. |

Neither PDP nor the forwarder logged anything at the moment of expiry, and the upstream sent all 48 events both times. For the second case the client held two connections opened together, sent a request a second on both, and started the stream on one as soon as the other was marked `Connection: close`.

Nothing is cut because nothing looks at the certificate while a response is being relayed. PDP verifies it once, when the request arrives, in `exchange` in `pkg/gateway/gateway.go`. TLS checks a certificate only during the handshake, and the go-spiffe configuration adds no later check. `pdp forward` copies bytes and reads no certificate after its own handshake. The bound on a relayed response is `limits.stream_timeout`.

The first case shows what is left. A response that starts before the last quarter and runs past the expiry leaves a connection whose next request gets `401`. A response is bounded by `limits.stream_timeout`, and it starts with at least a quarter of the SVID's validity left, or else the connection is already retiring. So this cannot happen while `stream_timeout` is at most a quarter of the SVID lifetime. With 4 hour SVIDs that is `stream_timeout` of one hour or less. This run broke that condition on purpose: 90 second SVIDs against the default `stream_timeout` of ten minutes.

Not covered by the SPIRE runs: the Kubernetes workload attestor, the SPIFFE CSI driver, a cluster, trust bundle or CA rotation, removal of a registration entry while its workload runs, the server and agent on different hosts, a real provider, `git` over the smart HTTP protocol or a push, the Go toolchain and `gh` as clients, and the container image.

## Interception CA replaced while serving

Run once by hand on November 14, 2026 (UTC), with PDP built from `cfd86c5`. It is not a checked-in test. PDP served a Unix socket. No kubelet, cert-manager or cluster was involved.

The CA files were laid out the way the kubelet lays out a Secret volume: a timestamped directory holding `tls.crt` and `tls.key`, `..data` as a symlink to it, and `tls.crt` and `tls.key` as symlinks to `..data/tls.crt` and `..data/tls.key`. PDP's `interception` paths named the two outer symlinks. A rotation wrote a new timestamped directory, renamed a new `..data` symlink over the old one, and removed the old directory. The chain was a root made with `openssl` and intermediate CAs signed by it, each with its own key. PDP got an intermediate and its key. The client trusted only the root.

The client sent a request every 200 milliseconds for 330 seconds, each on a new connection with a new `CONNECT` and a new inner TLS handshake, and recorded which intermediate had signed the leaf it was shown.

| Step | Result |
| --- | --- |
| Start with intermediate 1 | Requests succeed. The leaf is signed by intermediate 1, PDP presents the leaf and the intermediate, and the chain verifies to the root. |
| Rotate to intermediate 2, a new key under the same root | 38 seconds later the leaf is signed by intermediate 2. No restart and no `SIGHUP`. |
| Publish the certificate of intermediate 3 with the key of intermediate 2, and leave it for 90 seconds | PDP kept signing with intermediate 2. No request failed. |
| Rotate to intermediate 3 with its own key | 39 seconds later the leaf is signed by intermediate 3. |
| Whole run | 1613 requests, 1613 answered `200`, 0 failures. 287 saw intermediate 1, 890 intermediate 2 and 436 intermediate 3. |

The third step is what PDP sees if it reads the certificate and the key on different sides of a swap. The two paths are resolved one after the other, so a swap between the two reads gives a certificate and a key that do not match. `reload` in `pkg/intercept/intercept.go` then fails at `tls.X509KeyPair`, and `refresh` keeps the CA already loaded. The recorded modification times are only updated by a successful reload, so PDP tries again at the next recheck, a minute later, and loads the pair once both files are from the same generation. A real torn read lasts one recheck. The run held the mismatch for 90 seconds to cover at least one.

Two limits. At the time of this run a failed reload wrote nothing to PDP's log. It now logs `interception_ca_reload_failed` with the cause and both paths, once until the cause changes, which `TestFailedReloadKeepsAuthorityAndIsLogged` covers. And PDP rechecks only when a client starts an intercepted TLS handshake, at most once a minute, so an idle PDP loads a new CA on the first handshake after the swap.

Not covered: a real kubelet or cert-manager, a new root, an expired intermediate, a connection whose inner TLS session was opened before the swap and is still in use, and the SPIFFE listener in the same run.

## Real GitHub acceptance, pending

Use the `github-read` pack, or `github-comment` for the write step. An administrator must name an approved repository and issue, set `allowed_uids` and `allowed_repositories` in `policy.rego`, and supply the token (or the GitHub App key, App ID, repository IDs and permissions for `github-comment`) to the distinct daemon UID. Do not paste credentials into CLI options, logs or policy input. Start the daemon from the reviewed configuration and run read-only requests as an allowed workload UID:

```sh
bin/pdp request --socket /run/pdp/pdp.sock \
  --url https://api.github.com/repos/APPROVED_OWNER/APPROVED_REPOSITORY
bin/pdp request --socket /run/pdp/pdp.sock \
  --url https://api.github.com/repos/APPROVED_OWNER/APPROVED_REPOSITORY/issues/APPROVED_ISSUE_NUMBER
bin/pdp request --socket /run/pdp/pdp.sock \
  --url https://api.github.com/repos/APPROVED_OWNER/APPROVED_REPOSITORY/issues/APPROVED_ISSUE_NUMBER/comments
```

Verify that the request succeeds only for the allowed UID. A request from another UID must return `403`. A same-name repository under a different owner must deny. A comment under the `github-read` policy must deny before the provider. Use a local counting endpoint or provider audit records to show non-forwarding, not the status code alone.

Only after explicit permission for a **named disposable issue**, create a body file and exercise the write against the `github-comment` pack:

```sh
# DO NOT RUN until the named issue has explicit write approval.
: "${PDP_APPROVED_DISPOSABLE_ISSUE_NUMBER:?Requires explicit named-issue approval}"
printf '%s\n' '{"body":"PDP approved disposable acceptance comment"}' > approved-comment.json
bin/pdp request --socket /run/pdp/pdp.sock --method POST \
  --url "https://api.github.com/repos/APPROVED_OWNER/APPROVED_REPOSITORY/issues/$PDP_APPROVED_DISPOSABLE_ISSUE_NUMBER/comments" \
  --body approved-comment.json
```

The `github-comment` policy allows comments on every issue in the repository. To limit it to named issues, add a check on `input.http.path_params.issue_number` first. Record the comment ID and actor without recording tokens. Verify the installation's repository IDs and effective permissions. Cleanup is another provider write that needs authorization.

## Real Linear acceptance, pending

Choose the OAuth grant and actor before provisioning. `linear-read` uses client credentials and the app actor, which requires the application's client-credentials toggle. `linear-comment` uses an existing authorization-code installation with refresh and private durable state. Do not replace one with the other. Scope the binding to `read` and `comments:create`, and set `allowed_issues` in `policy.rego` to approved issue UUIDs.

Copy `examples/packs/linear-read/requests/read-issue.json`, replace `APPROVED_ISSUE_UUID`, and send it:

```sh
bin/pdp request --socket /run/pdp/pdp.sock --method POST \
  --url https://api.linear.app/graphql --body approved-read.json
```

Send `requests/read-mixed-scope.json` (one approved and one unapproved issue) and require denial of the whole request. A team ID does not authorize an unlisted issue. Verify the actor from provider-side evidence, not from a field in caller data. A provider HTTP 200 can contain GraphQL errors, so inspect the JSON result.

Only after explicit write approval for a named disposable issue, send `examples/packs/linear-comment/requests/create-comment.json` with `APPROVED_ISSUE_UUID` replaced. Record the resulting actor and comment ID. Verify that `reject-alternate-target.json` denies and that the `linear-read` policy cannot create the comment. Reuse the same installation to test refresh persistence across a daemon restart. Never overwrite an ambiguous recovery-required state to force a retry.

## Revocation and deployment acceptance, pending external setup

With a warm provider token, remove the caller from `allowed_uids` (or `allowed_workloads`), set a new `revision` in `pdp.json`, replace the files atomically, and send `SIGHUP`. Wait for `reload_applied` with the exact new `revision`. New requests must return `403`, including on a reused connection and inside an open intercepted `CONNECT`. Already-authorized requests may finish within their deadlines. An open HTTP stream or opaque tunnel keeps the old snapshot until it ends or `stream_timeout` passes. An upgraded WebSocket keeps the old snapshot until either peer closes, without a duration or idle timeout. `TestCLISocketReload` shows revocation against a local upstream. With several replicas, collect the acknowledgement from each or remove the stale ones from service.

SVID rotation with real SPIRE on one machine is recorded under [SPIRE run on one machine](#spire-run-on-one-machine). Still pending for a deployed SPIRE: rotate the gateway and caller SVIDs and trust bundles independently while sending requests. Confirm that named current identities continue, that a removed identity fails on a reused connection, and that a caller certificate is never taken for a provider credential. Confirm that attestation uses the intended namespace, service account and agent parent, and that a neighboring workload in the trust domain gets `403`.

For systemd, install the reviewed units only with approval, verify socket group access and a distinct daemon UID, stop and restart the service with the socket unit active, and confirm that the socket is not removed or replaced. For Kubernetes, review the manifest through an explicitly discovered `kubie` context before any authorized apply. Template validation and TCP readiness prove neither provider nor mTLS acceptance.

For interception and DNS steering, run a real client with `HTTPS_PROXY` or with its resolver pointed at PDP, record every connection it opens, and confirm that each one reaches PDP and is either authorized or refused. Confirm that a direct connection to an IP literal is blocked outside PDP. For a subscription client, confirm that it accepts the placeholder and the local token path answer, and that no real token appears in its files or logs. None of this has been done.

## Resource measurements

Reproduce with:

```sh
make build
go run ./cmd/pdpbench -pdp ./bin/pdp -requests 1000 -concurrency 4
```

All three runs below were measured on the previous route-based gateway, not on the forward proxy. They use Go 1.27.3 on Linux x86_64, Intel Core i9-14900, 1,000 warm requests at client concurrency 4. The harness starts the real daemon with kernel UID authentication, embedded OPA, a Starlark OAuth adapter and a loopback TLS upstream, with no schema. The runs do not include pinned-schema normalization, real provider latency or SPIRE processes. Each is a single run, not a controlled comparison. RSS comes from the daemon's `/proc` data. Active RSS is sampled, not an allocator high-water mark. A zero idle CPU count is a result at 10 ms tick resolution, not a guarantee of zero CPU use.

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

### Design 3: direct administrator Rego on the route-based gateway, November 11, 2026

This measured the route-based gateway before the forward-proxy change, with the policy written directly in Rego. The binary was built from the working tree on top of commit `feeb336`. The policy is one `allow` rule on auth method, UID, provider and binding. It is much smaller than the shipped pack policies. The numbers below come from one run of the command above and are exact:

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

### Forward proxy: not measured

All three runs above measured the previous route-based gateway, with requests sent to `/upstreams/github/...`. The forward proxy has not been measured. The harness now sends absolute-form requests to the proxy, but no run of it is recorded here. Two policy evaluations per request, DNS resolution, interception leaf minting, `CONNECT`, streamed responses and the DNS server are all unmeasured.

For later measurements, record the binary revision, Go version, schema and policy sizes, request mix, concurrency and hardware. Measure gateway idle RSS and CPU, warm authorized-request latency, acquisition and refresh latency, and active memory separately. Measure SPIRE server and agent separately when they are deployed. Do not infer that a combined deployment is lightweight from gateway numbers alone.
