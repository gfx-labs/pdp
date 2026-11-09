# Independent security review

Date: November 9, 2026.

Status: implementation and independent verification are still in progress. This report is not deployment approval. The review baseline is `docs/design.md`, including its progressive-permission and acceptance contracts.

## Scope and method

The reviewer read `internal/auth`, `internal/gateway`, `internal/policy`, `internal/schema`, `internal/credential`, `internal/config` and their CLI callers while separate owners implemented them. Findings were sent to the responsible owner and coordinator. The reviewer did not change worker-owned implementation. Temporary independent policy probes run through a Go overlay outside this repository, so no scaffolding tests are shipped.

No real provider writes, credential extraction, SPIRE deployment or Kubernetes operations were performed. Local TLS endpoints in the retained integration tests are transport-boundary checks, not proof of provider compatibility.

## Findings tracked during implementation

| ID | Scenario and affected code | Owner response and independent status |
| --- | --- | --- |
| SR-01 | `internal/policy/engine.go`, explicit deny matching. A broad full grant plus a repository/value deny accepted a request mixing a forbidden value with another value because the deny used all-value grant matching. | Owner changed denies to any-match and kept grants/mandatory restrictions conjunctive. Independent mixed-resource probe passes. |
| SR-02 | `internal/policy/engine.go`, JSON freezing. Exact neighboring integer IDs above 2^53 collapsed through `float64`, allowing a different numeric target. | Owner uses `UseNumber` for frozen configuration/input and exact resource IDs. Independent neighboring-int64 probe passes. Config-loader precision is separately tracked in SR-09. |
| SR-03 | `internal/policy/constraints.go`, wildcard deny. A forbidden selected value plus a missing/null array member caused the deny to stop matching. | Owner keeps missing values fail-closed for grants/mandatory rules but does not let them cancel a matching deny. Independent mixed-missing-member probe passes. |
| SR-04 | `internal/policy/constraints.go`, numeric equality. Numeric deny `1` could be bypassed with equivalent JSON spellings `1.0` or `1e0`. | Owner added exact numeric equivalence. Independent numeric-spelling probes pass. |
| SR-05 | `internal/schema/rest.go`, catalog signatures and bounds. Shared JSON tags omitted bound fields from operation signatures, and floating-point bound checks accepted an integer below a large exact minimum. | Owner split bound fields and introduced bounded exact comparisons. Owner regression covers minimum 9007199254740993 and catalog drift. Final independent suite rerun pending. |
| SR-06 | `internal/credential/oauth.go`, refresh durability. A successful provider rotation followed by an unusable access-token response discarded the replacement refresh token. In-memory poison did not survive reload/restart. | Owner added a durable recovery-required marker before exchange and preserves received replacement state without claiming success. Final code and restart-regression verification pending. |
| SR-07 | `internal/gateway/gateway.go`, response credential echo. An upstream body reflecting its injected authentication credential was forwarded to the caller. Header allowlisting alone did not prevent this leak. | Owners are adding generic provider-error bodies and lease-owned detection of credentials in success responses, including Basic and JSON-escaped strings. Final integration verification pending. |
| SR-08 | `internal/config/config.go`, schema-free restrictions. A typed operation deny on a schema-free full route never matched the gateway's synthetic untyped operation ID. Unknown operation references could remain diagnostics rather than validation errors. | Owner added route/catalog reference checks, schema requirements for typed restrictions, and digest pinning. Final executable config verification pending. |
| SR-09 | `internal/config/config.go`, numeric policy decoding. The configuration decoder could round `Values` before the policy engine's exact decoder saw them. | Reported to config owner. Final loaded-config precision verification pending. |
| SR-10 | `internal/gateway/request.go`, optional relationships. Policy input never carried a selected task, so relationship-gated grants could not succeed. | Owners are adding administrator-controlled principal-to-task mapping. No caller label establishes assignment. Final assigned/unassigned/cross-task verification pending. |
| SR-11 | `internal/gateway/gateway.go`, audit provenance. Events lacked the schema digest, relationship revision and matched grant identifiers needed to explain the actual decision snapshot. | Reported to gateway owner. Final trace verification pending. |

## Acceptance trace

The table distinguishes source review from executable evidence. A passing local test is not external acceptance.

| Requirement | Enforcement and evidence | Current limit |
| --- | --- | --- |
| Verified local identity | `internal/auth/peer_linux.go` obtains Linux `SO_PEERCRED`; UID mappings are copied into an authenticator. Header values are not identity. | Shared UID means shared authority. Final real-socket regression run pending. |
| Optional SPIFFE identity | `internal/auth/spiffe.go` uses the maintained Workload API X509 source and mTLS verification. Requests reverify the current bundle, including reused connections. | No real SPIRE certificate issuance/rotation acceptance has run. |
| Fixed destination and binding | Gateway routes select administrator-fixed HTTPS endpoints and bindings. Fresh upstream requests discard caller headers. | Final destination/header/redirect integration checks pending. |
| Request ambiguity and bounded forwarding | Gateway rejects unsupported encodings, chunked ingress, noncanonical paths, duplicate query parameters and unsupported protocols. Schemas reject duplicate JSON keys and unsupported request shapes. | Supported subset is intentionally narrower than generic HTTP, OpenAPI and GraphQL. |
| Default deny and full-mode restrictions | Embedded OPA requires a grant for every normalized unit; explicit denies and mandatory restrictions override full grants. | Four independent temporary security probes pass. Final retained race suite pending. |
| Restricted profiles and schema drift | Policy classifications are reviewed configuration, not inferred from verbs or query/mutation syntax. Config validation checks references against route catalogs. | Real provider fixtures/profile contents and executable examples still need final review. |
| GraphQL occurrence authorization | Schema normalization retains separate coordinates, alias paths and normalized arguments for repeated selections, variables/defaults and fragments. | Final conditional-selection and end-to-end denial checks pending. |
| Credential cache isolation | Manager keys include provider, binding and canonical scopes; acquisitions coalesce and invalidation rejects in-flight stale results. Reload creates a new manager. | Final concurrency/invalidation tests pending. |
| Durable rotating refresh | Refresh state is file-locked and atomically replaced with file/directory fsync. Owner is adding pre-exchange recovery state. | An uncertain exchange must require explicit recovery, not automatic predecessor reuse. Final restart tests pending. |
| Starlark secret boundary | Scripts receive opaque secret/result handles; native helpers own network, JWT signing and secret parsing. Errors and print output are sanitized. Steps, time, input/output and concurrency are bounded. | Trusted administrator scripts only. Starlark is not a hard memory sandbox. |
| Atomic revocation and reload | Snapshot publication is atomic; old snapshots remain alive until their requests drain. No positive authorization cache bypasses policy evaluation. | Final real lifecycle/revocation checks pending. Already authorized requests may finish within deadlines. |
| Caller/log credential non-disclosure | Caller headers are reconstructed, audit omits bodies/arguments, errors use fixed codes. Response reflection finding is tracked in SR-07. | No claim of protection from an intentionally malicious provider encoding arbitrary secret transformations. |

## Checks observed so far

- `go test ./internal/policy ./internal/auth` initially compiled policy but was blocked on missing SPIFFE transitive checksums. Dependency owner was notified.
- A later `go test ./...` compiled every package. Policy and schema passed. Credential refresh tests failed while the durable recovery-marker change and corresponding tests were in flight. This is not a final result.
- Independent temporary overlay probes pass mixed-resource deny precedence, neighboring exact-int64 rejection, missing wildcard-member deny precedence and equivalent numeric-spelling denial.

Final build, vet, formatting, race, executable CLI and acceptance results will replace this interim section after implementation owners finish.

## External acceptance not established

Real GitHub App issuance, real Linear app/user OAuth refresh and provider reads/writes have not been exercised by this review. No real SPIRE server/agent, Kubernetes deployment, multi-replica revision acknowledgement or workload attestation has been validated. Resource and latency measurements must be reported separately and cannot be inferred from unit tests. These remain explicit acceptance gaps rather than implied passes.
