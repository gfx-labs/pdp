# GitHub: repository reader and issue-comment worker

Follow the [shared identity and socket setup](README.md#set-up-the-identity-boundary) first. These examples need no SPIRE, custom Rego or relationship graph. Commands assume the prepared daemon is listening at `/run/pdp/pdp.sock` and the caller UID is mapped to `local-worker`.

All grants below are YAML data for the embedded [Rego policy](../pkg/policy/base.rego), not authorization logic implemented in Go. Rego matches the verified identity/provider/binding, evaluates the reviewed operation profile and checks the repository allowlist. The [YAML-to-Rego walkthrough](policy.md) shows the actual rule path and a runnable custom-denial example. No custom module is required for the ordinary profiles.

## Read a repository and issue

Use [github-read.yaml](github-read.yaml). Configure:

- The real caller UID and a protected socket accessible to it.
- `constraints.repositories`: exactly `APPROVED_OWNER/APPROVED_REPOSITORY`, replaced with the approved owner and repository. Matching only a repository basename is not sufficient.
- `/run/secrets/github-token`: a daemon-readable mounted token with the repository read permissions required by these endpoints. The workload must not be able to read that file.
- An absolute pinned schema path if you relocate the YAML.

Validate the prepared config, then start it under the distinct daemon account:

```sh
bin/pdp validate --config /etc/pdp/github-read.yaml
bin/pdp serve --config /etc/pdp/github-read.yaml
```

From the mapped workload account, set public resource identifiers and read:

```sh
PDP_SOCKET=/run/pdp/pdp.sock
PDP_REPOSITORY=APPROVED_OWNER/APPROVED_REPOSITORY
PDP_ISSUE_NUMBER=123 # Replace with the approved issue number.

bin/pdp request --socket "$PDP_SOCKET" \
  --path "/upstreams/github/repos/$PDP_REPOSITORY"
bin/pdp request --socket "$PDP_SOCKET" \
  --path "/upstreams/github/repos/$PDP_REPOSITORY/issues/$PDP_ISSUE_NUMBER"
bin/pdp request --socket "$PDP_SOCKET" \
  --path "/upstreams/github/repos/$PDP_REPOSITORY/issues/$PDP_ISSUE_NUMBER/comments?per_page=10"
```

Go validates the pinned REST operation and extracts its canonical repository resource. Rego checks the grant and returns the decision. Only after allow does PDP obtain the token, remove `/upstreams/github` and inject authorization for the fixed GitHub endpoint. The caller gets the provider JSON, not the token.

Expected restrictions:

| Request | Expected PDP result |
| --- | --- |
| Repository, issue or comment-list read in the configured repository | Allow |
| Same repository name under another owner | Deny |
| Comment creation under the `read` profile | Deny |
| Repository deletion or an unsupported REST operation | Reject before forwarding |
| Forged identity or authorization headers | Cannot change the kernel-authenticated principal or selected binding |

For example, replacing only the owner must not preserve access:

```sh
# Expected denial, not a provider request.
bin/pdp request --socket "$PDP_SOCKET" \
  --path /upstreams/github/repos/UNAPPROVED_OWNER/APPROVED_REPOSITORY
```

If you need machine-level evidence of non-forwarding, use local regression tests or provider audit evidence as described in the [acceptance runbook](../docs/acceptance.md). The CLI exits nonzero on non-2xx responses.

## Allow approved issue comments

Use [github-read-write.yaml](github-read-write.yaml) instead of the read-only config. This template uses a GitHub App adapter. Configure the App ID, exact installation endpoint, numeric repository ID, daemon-only private-key file and matching repository policy scope. Its requested installation permissions are `contents: read` and `issues: write`; the provider's actual installation must authorize them.

The template's `read_write` profile adds only `issues/create-comment` to the supported reads. It grants comment access across the approved repository, **not only one issue**. If narrower issue-level permissions are required, add explicit argument restrictions before serving. Do not describe this repository grant as an issue allowlist.

Start the prepared read/write config as the daemon, not a second listener on the same socket. A running service can also load an administrator-installed config with a new revision through `SIGHUP`; wait for `reload_applied` naming that revision. Remove the previous broad grants if replacing a policy.

[requests/github/create-comment.json](requests/github/create-comment.json) contains only the comment body. After explicit write approval for a **named disposable issue**:

```sh
# DO NOT RUN without named-issue write approval.
: "${PDP_APPROVED_DISPOSABLE_ISSUE_NUMBER:?Set the explicitly approved issue number}"
bin/pdp request --socket "$PDP_SOCKET" --method POST \
  --path "/upstreams/github/repos/$PDP_REPOSITORY/issues/$PDP_APPROVED_DISPOSABLE_ISSUE_NUMBER/comments" \
  --body examples/requests/github/create-comment.json
```

This same request must deny under `github-read.yaml`, and a comment targeting another repository must deny under `github-read-write.yaml`. No comment command in this guide has been executed against GitHub. Do not automatically retry uncertain writes or delete the resulting comment without separate cleanup approval.

For an additional Rego restriction, [github-comment-freeze.yaml](github-comment-freeze.yaml) keeps the same read/write grant data but adds a custom denial for `issues/create-comment`. Reads remain allowed; the custom denial overrides the matching grant. Verify that behavior without credentials or provider calls using the [offline explanation](policy.md#run-a-custom-rego-denial).

## Credential shielding with full access

[github-app.yaml](github-app.yaml) uses the same native App installation helper with a schema-free `full` gateway grant. It is suitable when the objective is hiding an already appropriately scoped provider credential rather than operation restrictions. Reads and comments use the same route and caller commands.

`full` is not a repository read-only profile. It permits all supported operations within that configured binding and the installation token's authority, including destructive/admin operations when the credential itself permits them. Repository IDs and installation permissions restrict the provider token, but do not silently narrow a separate gateway grant. Use the read/read-write configurations above when PDP must enforce the listed operation and resource restrictions.
