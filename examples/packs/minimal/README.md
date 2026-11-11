# minimal

Full access to one GitHub credential for named Unix UIDs. `pdp.json` attaches the `github-local` binding to `api.github.com`. No schema is pinned, so requests are not classified: the policy allows the destination and binding, and the provider credential's own scope is the only other limit. Use a narrowly scoped token.

The policy allows nothing else. A request to any other host reaches the policy and is denied.

## Edit

- `policy.rego`: `allowed_uids`.
- `pdp.json`: `transport.unix_socket`, and the token path under `credentials.bindings.github-local.secrets.token.file`. The file holds a GitHub token readable only by the daemon account.

## Check

```sh
bin/pdp validate --config examples/packs/minimal/pdp.json
bin/pdp explain --config examples/packs/minimal/pdp.json \
  --input examples/packs/minimal/explain/get-repository.json
```

The explanation allows UID 1000 with `matched_rules` `github-full`.

## Serve and call

```sh
bin/pdp serve --config /etc/pdp/pdp.json
bin/pdp request --socket /run/pdp/pdp.sock \
  --url https://api.github.com/repos/OWNER/REPOSITORY
```

`pdp request` sends the full URL in the request line, and PDP makes the TLS connection to GitHub itself. No interception CA is needed. A caller whose UID is not in `allowed_uids` gets HTTP 403 and no credential is read.
