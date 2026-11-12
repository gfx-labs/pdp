# subscription

Two accounts on one provider host. The workload holds a placeholder, never a real token. PDP swaps the placeholder for the real credential after the policy allows the caller to use that account.

The provider here is a stand-in (`api.provider.example`). Replace the host, token endpoint, token path and account header with the real provider's values.

## How a request is handled

1. The client sends `Authorization: Bearer pdp-placeholder-team-account`.
2. PDP finds the binding with that placeholder among the upstream's `bindings`. The placeholder only picks a candidate. It proves nothing.
3. `policy.rego` receives the candidate as `input.binding` and checks it against `grants.yaml` for the verified caller.
4. If allowed, PDP drops the caller's `Authorization`, `Cookie` and any header carrying a placeholder, then sets the real token and the binding's fixed `headers` (here `X-Account-Id`).

A caller who learns another account's placeholder is denied at step 3. See `explain/other-accounts-placeholder.json`.

## Token endpoint

Clients with a subscription login try to refresh their own token. `token_paths` lists the paths where they do that. PDP answers those requests itself with the placeholder and `expires_in: 3600`, after the same policy check. The request is not forwarded and the real refresh token never leaves PDP. The real refresh happens in `adapter.star` through `oauth_refresh`, with tokens kept in each binding's `state_file`.

## Edit

- `grants.yaml`: which identity may use which binding. It is policy data, so it may be YAML or JSON.
- `pdp.json`: upstream host, `token_paths`, the token endpoint, `REPLACE_` values, secret and state paths, and the `interception` CA paths. Give each binding its own placeholder of at least 8 characters with no spaces, commas, quotes or backslashes. A placeholder is not a secret.
- `policy.rego`: the destination host.

Each `state_file` must exist before serving and hold the initial refresh token obtained from the provider's own login flow. This pack does not perform that login.

The pack's stand-in provider has a client secret. A login made by a provider's own CLI usually has none. For one, drop `secrets` from the binding and call `oauth_refresh("token", parameter("client_id"))` in `adapter.star`, with `encoding="json"` or `send_scope=True` where the provider's token endpoint needs them. See [pkg/credential/README.md](../../../pkg/credential/README.md).

## Check

```sh
bin/pdp validate --config examples/packs/subscription/pdp.json
for input in examples/packs/subscription/explain/*.json; do
  bin/pdp explain --config examples/packs/subscription/pdp.json --input "$input"
done
```

| Input | Result |
| --- | --- |
| `granted-account.json` | allowed, `uid:1000` holds `team-account` |
| `other-accounts-placeholder.json` | denied, `uid:1000` does not hold `personal-account` |
| `no-placeholder.json` | denied, no binding was selected |

## Client setup

Point the client at PDP as its HTTPS proxy, make it trust the interception CA, and give it the placeholder wherever it expects its token.

## Limits

- Not tested against any real provider. Whether a given client accepts a placeholder in place of its token format, and whether every connection it makes goes through the proxy, has to be checked per client.
- Streamed responses are scanned for the raw credential bytes only. WebSocket frames are not scanned.
- A provider that binds tokens to a client certificate or device key cannot be served this way.
