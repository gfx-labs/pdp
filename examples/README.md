# Packs

A pack is a complete, runnable configuration in one directory. Copy it, edit the marked values, serve it.

| Pack | Caller | What the policy allows |
| --- | --- | --- |
| [minimal](packs/minimal/README.md) | Unix UID | Everything the GitHub credential can do. No schema. |
| [github-read](packs/github-read/README.md) | Unix UID | Read one repository, its issues and issue comments. |
| [github-comment](packs/github-comment/README.md) | Unix UID | The reads above, plus creating issue comments in that repository. GitHub App credential. |
| [linear-read](packs/linear-read/README.md) | Unix UID | Read named issues. Client-credentials app actor. |
| [linear-comment](packs/linear-comment/README.md) | Unix UID | Read named issues and comment on them. Existing OAuth installation with refresh. |
| [github-spiffe](packs/github-spiffe/README.md) | SPIFFE ID | Read one repository. Kubernetes manifest included. |
| [systemd](packs/systemd/README.md) | Unix UID | Same policy as minimal, with service and socket units and a systemd credential. |
| [egress](packs/egress/README.md) | Unix UID | Host, method and tunnel allowlist for any destination. No credential, no schema. |
| [subscription](packs/subscription/README.md) | Unix UID | Two accounts on one host, picked by placeholder and granted per caller. Local token endpoint. |
| [kubernetes](packs/kubernetes/README.md) | SPIFFE ID or pod IP | Credentialed calls for SVID holders, credential-free reads for DNS-steered pods. cert-manager, trust-manager and NetworkPolicy manifests. |

## What is in a pack

| File | Purpose |
| --- | --- |
| `policy.rego` | The authorization policy. Allowed callers, repositories or issues are sets at the top of the file. |
| `pdp.json` or `pdp.yaml` | Runtime wiring: listeners, upstreams, schema file, credential bindings, secret paths. An upstream entry attaches a credential, schema or TLS mode to a host. It does not allow the host. Only `policy.rego` does. |
| `adapter.star` | Starlark that obtains the provider credential after the policy allows. |
| `github-rest.json`, `linear.graphql` | The pinned request schema. Its digest is checked in `policy.rego`. |
| `requests/` | Request bodies for `pdp request`, in packs that send one. |
| `explain/` | Trusted inputs for `pdp explain`, to check the policy without serving. The Linear and systemd packs have none. |

The configuration, policy data, OpenAPI schemas and explain inputs can each be JSON or YAML with the same fields. The egress pack uses YAML for its configuration and explain inputs, and the subscription pack uses YAML for `grants.yaml`. The rest are JSON.

All paths in the configuration except secrets and the socket are relative to the pack, so the directory can be moved as a unit.

## Use a pack

Run from the repository root.

```sh
make build
bin/pdp validate --config examples/packs/github-read/pdp.json
bin/pdp explain --config examples/packs/github-read/pdp.json \
  --input examples/packs/github-read/explain/read-issue.json
```

Then:

1. Copy the pack to an administrator-owned directory such as `/etc/pdp`. Workloads must not be able to write it.
2. In `policy.rego`, replace the values under "Edit these": the caller UID or SPIFFE ID, and the repository or issue IDs.
3. In `pdp.json`, set the secret file paths and any `REPLACE_` values.
4. Run PDP under its own account. Only that account may read the secrets. Give callers access to the socket through a group, with `socket_mode` `0660`. The socket's parent directory must be owned by root or the daemon and not writable by callers.
5. `bin/pdp validate --config /etc/pdp/pdp.json`, then `bin/pdp serve --config /etc/pdp/pdp.json`.

To change policy on a running daemon, edit `policy.rego`, set a new `revision` in `pdp.json` and send `SIGHUP`.

## If you change the schema

`policy.rego` pins the schema by digest. After editing the schema file, print the new digest and review what changed before updating the policy:

```sh
bin/pdp catalog --protocol rest --schema examples/packs/github-read/github-rest.json
bin/pdp schema diff --protocol rest old.json new.json
```

The schema files are small reviewed request projections, not the providers' full APIs. An operation or field that is not in the schema is rejected before the policy runs.

## Safety

- The policy names the callers it allows. Any local UID that can open the socket reaches the policy and is refused by default deny. Keep the socket permissions tight as well.
- Comment requests are provider writes. Send them only to a disposable issue you have approval to write to. Nothing here retries or cleans up. A timeout does not prove a write failed.
- A Linear HTTP 200 can contain GraphQL errors. Check `data` and `errors` in the response.
- These packs are tested against a local TLS server, with each pack's own policy, schema and adapter. No pack has been run against a real GitHub or Linear account, SPIRE or a cluster.
