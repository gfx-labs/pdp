# github-comment

Read one GitHub repository and create issue comments in it, for named Unix UIDs. Uses a GitHub App installation token.

The policy allows comments on every issue in the repository. To limit it to named issues, add a check on `input.http.path_params.issue_number` in `policy.rego`.

## Edit

- `policy.rego`: `allowed_uids` and `allowed_repositories`.
- `pdp.json`:
  - `credentials.providers.github.endpoints.token`: replace `REPLACE_INSTALLATION_ID`.
  - `credentials.bindings.github-app-repo.github`: `app_id`, the numeric `repository_ids`, and `permissions`. The installation must actually hold these permissions.
  - The App private key path. PDP signs the App JWT and requests a token restricted to those repository IDs and permissions.

## Check

```sh
bin/pdp validate --config examples/packs/github-comment/pdp.json
bin/pdp explain --config examples/packs/github-comment/pdp.json \
  --input examples/packs/github-comment/explain/create-comment.json
```

## Serve and call

Reads work as in [github-read](../github-read/README.md). A comment is a provider write. Send it only to a disposable issue you have approval to write to:

```sh
# Writes to GitHub. Set the approved issue number first.
: "${PDP_APPROVED_DISPOSABLE_ISSUE_NUMBER:?Set the approved issue number}"
bin/pdp request --socket /run/pdp/pdp.sock --method POST \
  --path "/upstreams/github/repos/APPROVED_OWNER/APPROVED_REPOSITORY/issues/$PDP_APPROVED_DISPOSABLE_ISSUE_NUMBER/comments" \
  --body examples/packs/github-comment/requests/create-comment.json
```

| Request | Result |
| --- | --- |
| Read or comment in an allowed repository | Allowed |
| Comment with a blank `body` | Denied |
| Read or comment in another repository | 403 |
| Caller UID not in `allowed_uids` | 403 |

Do not retry a comment that timed out without checking the issue first.
