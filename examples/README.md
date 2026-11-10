# Provider use cases

These walkthroughs pair the checked-in configurations with caller requests. Run commands from the repository root. No caller command needs a GitHub token, Linear token, App private key or OAuth client secret.

**Rego is the policy; YAML specifies its data.** Every `policy:` section is loaded into immutable `data.pdp.config` for [the embedded authorization rules](../pkg/policy/base.rego). Go validates configuration and normalizes requests, not grant decisions. Read the [YAML-to-Rego walkthrough](policy.md) for the actual rule path, input contract and a runnable custom Rego denial. Existing YAML fields and provider request bodies did not change in the migration.

| Use case | Walkthrough | Configuration |
| --- | --- | --- |
| Read one GitHub repository and its issues | [GitHub](github.md#read-a-repository-and-issue) | [github-read.yaml](github-read.yaml) |
| Comment on an approved GitHub repository's issue | [GitHub](github.md#allow-approved-issue-comments) | [github-read-write.yaml](github-read-write.yaml) |
| Override an allowed GitHub comment with a custom Rego denial | [Policy walkthrough](policy.md#run-a-custom-rego-denial) | [github-comment-freeze.yaml](github-comment-freeze.yaml) |
| Read approved Linear issues | [Linear](linear.md#read-an-approved-issue) | [linear-read.yaml](linear-read.yaml) |
| Comment on approved Linear issues | [Linear](linear.md#allow-comments-on-approved-issues) | [linear-read-write.yaml](linear-read-write.yaml) |
| Reuse an existing Linear OAuth installation | [Linear](linear.md#use-an-existing-oauth-installation) | [linear-oauth.yaml](linear-oauth.yaml) |
| Shield credentials without schema restrictions | [GitHub](github.md#credential-shielding-with-full-access), [Linear](linear.md#use-an-existing-oauth-installation) | [github-app.yaml](github-app.yaml), [linear-oauth.yaml](linear-oauth.yaml) |

## Check the templates offline

```sh
make build
bin/pdp validate --config examples/github-read.yaml
bin/pdp validate --config examples/github-read-write.yaml
bin/pdp validate --config examples/github-comment-freeze.yaml
bin/pdp validate --config examples/linear-read.yaml
bin/pdp validate --config examples/linear-read-write.yaml
bin/pdp validate --config examples/github-app.yaml
bin/pdp validate --config examples/linear-oauth.yaml
bin/pdp validate --config examples/minimal.yaml
bin/pdp validate --config examples/kubernetes/pdp.yaml
CREDENTIALS_DIRECTORY=/run/credentials/pdp.service \
  bin/pdp validate --config examples/systemd/pdp.yaml
```

Validation imports schemas and compiles authorization and adapters. It does not read provider credentials, obtain tokens or contact either provider. Placeholders are accepted for offline review, not evidence that an account is configured.

`explain-full.json` is an administrator-supplied normalized input, not a caller authentication mechanism. The request JSON files remain ordinary provider payloads. Neither includes grants, denials or `_pdp` facts: the engine constructs trusted facts and Rego determines the outcome.

## Set up the identity boundary

1. Run PDP under a daemon UID distinct from the workload UID. Only the daemon can read provider secrets and OAuth refresh state.
2. Map the actual workload UID to `local-worker` in `identities`. Processes sharing that UID share its permissions.
3. Configure a protected socket parent, such as `/run/pdp`, owned by root or the daemon and not writable by workloads. For distinct UIDs, arrange a client group and use socket mode `0660`. The templates' `0600` is for a same-user transport smoke test, not credential isolation.
4. Install an administrator-owned copy of the selected configuration. Paths to schemas are relative to that file, so change `schemas.*.file` to an absolute path when moving it out of `examples/`. Keep adapters, policy and secrets outside caller write access.
5. Start PDP as the daemon account. Run `pdp request` as the mapped workload account. The [systemd templates](systemd/) show separated accounts and socket-group access. SPIFFE mTLS is an [optional alternative](../docs/deployment.md#optional-spiffe-mtls), not required by these walkthroughs.

Replace every `APPROVED_*`, `UNAPPROVED_*` and `REPLACE_*` value before a live request. Request JSON files are templates too. Use a real approved issue UUID for Linear and an approved issue number for GitHub. Do not send credentials in caller headers or store them in request files.

## Safety and expected results

Live reads require an approved account/resource scope. Comment examples are **provider writes**: run them only after explicit approval for a named disposable issue. There is no automatic write, cleanup or retry script. A timeout does not prove a write failed; inspect provider state before deciding whether to retry.

The guides describe expected PDP authorization. Success also depends on provider permissions and account setup. A Linear HTTP 200 may contain GraphQL errors, so inspect `data` and `errors`. A denied request must not reach the provider or acquire a credential. Local regression tests establish that ordering; an HTTP error alone is not proof of non-forwarding in a deployed system.

The supported schema projections and built-in profiles are deliberately small. `read_write` means reviewed reads and comments, not arbitrary provider writes. Unknown operations and unsupported fields deny. Grants are additive: do not leave a broad `full` grant in place and expect a new narrow grant to restrict it. See [profile contents](../docs/configuration.md#exact-built-in-profiles) and [acceptance boundaries](../docs/acceptance.md).
