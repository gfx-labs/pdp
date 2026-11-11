# linear-read

Read named Linear issues, for named Unix UIDs. Uses Linear client credentials with the app actor and the `read` scope. `pdp.json` attaches the `linear-app` binding and the `linear` GraphQL schema to `api.linear.app`. Only `POST /graphql` is accepted there.

## Edit

- `policy.rego`: `allowed_uids` and `allowed_issues`. Issues are UUIDs. A team ID does not grant access.
- `pdp.json`: `REPLACE_CLIENT_ID` and the client secret path. The Linear OAuth app must have client credentials enabled.
- `requests/*.json`: replace `APPROVED_ISSUE_UUID` with the same UUID. Shell variables are not expanded inside these files.

## Check

```sh
bin/pdp validate --config examples/packs/linear-read/pdp.json
```

## Serve and call

```sh
bin/pdp serve --config /etc/pdp/pdp.json
bin/pdp request --socket /run/pdp/pdp.sock --method POST \
  --url https://api.linear.app/graphql \
  --body examples/packs/linear-read/requests/read-issue.json
```

| Request | Result |
| --- | --- |
| `read-issue.json`: `id`, `identifier`, `title`, `description` of an allowed issue | Allowed |
| `read-mixed-scope.json`: one allowed and one other issue through aliases and a fragment | 403 for the whole request |
| `create-comment.json` | 403 |
| A field not listed in `issue_fields`, even one in the schema | 403 |
| A field not in `linear.graphql`, a batch or a subscription | 400, rejected before the policy runs |

The policy checks every selected field, and finds each field's parent by path. An allowed alias does not make a sibling alias allowed. A field behind `@skip` or `@include` is checked whether or not it would run.

A Linear HTTP 200 can carry GraphQL errors. Check `data` and `errors`.
