# github-read

Read one GitHub repository, its issues and issue comments, for named Unix UIDs. Uses a static token.

## Edit

- `policy.rego`: `allowed_uids` and `allowed_repositories`. A repository is the full `OWNER/REPOSITORY` pair.
- `pdp.json`: `transport.unix_socket` and the token path. The token needs read access to the repository.

## Check

```sh
bin/pdp validate --config examples/packs/github-read/pdp.json
bin/pdp explain --config examples/packs/github-read/pdp.json \
  --input examples/packs/github-read/explain/read-issue.json
bin/pdp explain --config examples/packs/github-read/pdp.json \
  --input examples/packs/github-read/explain/other-uid.json
```

The first allows. The second is the same request from UID 2000 and denies with the reason `caller UID is not allowed`.

## Serve and call

```sh
bin/pdp serve --config /etc/pdp/pdp.json

PDP_SOCKET=/run/pdp/pdp.sock
PDP_REPOSITORY=APPROVED_OWNER/APPROVED_REPOSITORY
bin/pdp request --socket "$PDP_SOCKET" \
  --path "/upstreams/github/repos/$PDP_REPOSITORY"
bin/pdp request --socket "$PDP_SOCKET" \
  --path "/upstreams/github/repos/$PDP_REPOSITORY/issues/123"
bin/pdp request --socket "$PDP_SOCKET" \
  --path "/upstreams/github/repos/$PDP_REPOSITORY/issues/123/comments?per_page=10"
```

| Request | Result |
| --- | --- |
| Repository, issue or comment list in an allowed repository | Allowed |
| Same repository name under another owner | 403 |
| `POST .../issues/123/comments` with `requests/create-comment.json` | 403 |
| An operation not in `github-rest.json` | Rejected before the policy runs |
| Caller UID not in `allowed_uids` | 403 |

Denied requests do not read the token or reach GitHub.
