# linear-comment

Read named Linear issues and comment on them, for named Unix UIDs. Uses an existing Linear OAuth installation through its refresh token, with scopes `read` and `comments:create`. `pdp.json` attaches the `linear-installation` binding and the `linear` GraphQL schema to `api.linear.app`.

## Edit

- `policy.rego`: `allowed_uids` and `allowed_issues` (issue UUIDs).
- `pdp.json`: `REPLACE_CLIENT_ID`, the client secret path, `linear_actor` (`app` or `user`, matching how the installation was authorized) and `state_file`.
- `requests/*.json`: replace `APPROVED_ISSUE_UUID`.

### OAuth state

`state_file` holds the rotating refresh token. The administrator creates it once from the original authorization:

```json
{"refresh_token": "FROM_THE_AUTHORIZATION", "scopes": ["read", "comments:create"]}
```

Its directory must be private to the daemon (mode `0700`) and writable, and the file mode `0600`. PDP rewrites it on every refresh. If a refresh outcome is uncertain the file is marked `recovery_required` and PDP stops using it. Reauthorize through Linear in that case. Do not clear the marker and replay an old refresh token.

To use client credentials instead, take `adapter.star` and the binding from [linear-read](../linear-read/README.md) and add the `comments:create` scope to the `api.linear.app` upstream entry and to the binding.

## Check

```sh
bin/pdp validate --config examples/packs/linear-comment/pdp.json
```

## Serve and call

Reads work as in [linear-read](../linear-read/README.md). A comment is a provider write. Send it only for a disposable issue you have approval to write to:

```sh
# Writes to Linear.
bin/pdp request --socket /run/pdp/pdp.sock --method POST \
  --url https://api.linear.app/graphql \
  --body examples/packs/linear-comment/requests/create-comment.json
```

| Request | Result |
| --- | --- |
| Read an allowed issue | Allowed |
| `create-comment.json`: `issueId` of an allowed issue and a nonempty `body` | Allowed |
| `reject-alternate-target.json`: adds `projectId` to the input | 403 |
| Any other input key, such as `parentId` or `createAsUser` | 403 |
| Read or comment on another issue | 403 |

`reject-alternate-target.json` is there to be denied. The pack's test sends it and expects 403.
