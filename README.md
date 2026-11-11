# PDP

PDP is a standalone Go gateway that lets a verified workload call GitHub REST or Linear GraphQL without receiving the upstream credential. It authenticates the connection, asks your Rego policy whether the complete request is allowed, then obtains and injects the credential. Provider destinations and credential bindings are administrator configuration, never caller input.

## The parts

| Part | Written in | Does |
| --- | --- | --- |
| Policy | Rego, package `pdp.authz` | Decides who may do what. This is the only place permissions are defined. |
| Runtime configuration | JSON, `pdp.config/v2` | Wiring: listeners, routes, schema files, credential bindings, secret file paths, policy file paths. No permissions. |
| Schema | OpenAPI JSON or GraphQL SDL | Lets Go validate a request and turn it into the input the policy sees. Optional. |
| Credential adapter | Starlark | Obtains the provider token after the policy allows. |

Go authenticates the caller and normalizes the request. It does not map identities to names or decide anything about permissions.

## Start with a pack

A pack is a directory holding all four parts plus example requests. Copy one, edit the marked values, and serve it. See [examples](examples/README.md) for the list.

```sh
make build
bin/pdp validate --config examples/packs/minimal/pdp.json
bin/pdp explain --config examples/packs/minimal/pdp.json \
  --input examples/packs/minimal/explain/get-repository.json
```

Validation compiles the policy, schema and adapter. It does not open provider secrets or contact a provider. To serve, copy the pack to an administrator-owned directory, set the caller UID in `policy.rego` and the secret path in `pdp.json`, then:

```sh
bin/pdp serve --config /etc/pdp/pdp.json
bin/pdp request --socket /run/pdp/pdp.sock \
  --path /upstreams/github/repos/OWNER/REPOSITORY
```

Linux Unix-domain HTTP is the minimum deployment. SPIFFE mTLS and schemas are optional. **Credential isolation requires the daemon and the workload to run under different UIDs.** A workload sharing the daemon UID can read its mounted secrets directly. The [systemd pack](examples/packs/systemd/README.md) shows a separated setup.

## Writing policy

```rego
package pdp.authz

import rego.v1

default allow := false

allow if {
	input.identity.auth_method == "unix"
	input.identity.uid == 1000
	input.provider == "github"
	input.binding == "github-local"
}
```

- Every module uses `package pdp.authz`. Only a boolean `allow` authorizes. An undefined, malformed or failing evaluation denies.
- Optional `reasons` and `matched_rules` are sets of strings shown by `pdp explain` and, for `matched_rules`, in audit events.
- `input.identity` carries verified facts: `id` (`uid:<n>` or the SPIFFE ID), `auth_method` (`unix` or `spiffe`), `uid`, `spiffe_id`. The policy must name the callers it allows. Any UID that can open the socket, and any workload in a trusted SPIFFE domain, reaches the policy and is refused only by default deny.
- `input.provider`, `input.binding` and `input.schema_digest` come from the route. Compare `input.schema_digest` to a reviewed value so a changed schema denies until you review it.
- REST requests give `input.operations[0].id` and `input.http` (`path_params`, `normalized_query`, `body`). GraphQL requests give `input.graphql`, one entry per selected field with `coordinate`, `path` and `arguments`, including aliases, fragments and fields behind `@skip` or `@include`.
- Without a schema the request is not classified. The policy sees only the method and path, so it can gate access to the binding but not individual operations.
- `http.send`, `net.lookup_ip_addr` and `opa.runtime` are unavailable. Optional static data goes in one JSON file named by `policy.data` and is read as `data.<key>`.

## CLI

```sh
bin/pdp validate --config pdp.json
bin/pdp explain --config pdp.json --input input.json
bin/pdp catalog --protocol rest --schema examples/packs/github-read/github-rest.json
bin/pdp catalog --protocol graphql --schema examples/packs/linear-read/linear.graphql
bin/pdp schema diff --protocol rest before.json after.json
bin/pdp request --socket /run/pdp/pdp.sock --method POST \
  --path /upstreams/linear/graphql --body query.json
```

`catalog` prints the schema digest and each operation's request contract. `schema diff` reports added, removed and changed operations. `explain` takes a trusted `pdp.authz/v1` input for administrator debugging. It is not a caller endpoint and contacts no provider. A denied explanation is normal output. `request` exits nonzero on non-2xx responses.

`SIGHUP` validates and atomically publishes a new snapshot: policy, schemas, routes, credential bindings and adapters together. Use a new revision for each update. A failed reload keeps the previous snapshot. Removing a caller from the policy and reloading revokes it, including on connections already open. Listener addresses, socket mode, CA file and limits need a restart.

## More

- [Packs](examples/README.md)
- [Configuration and limits](docs/configuration.md)
- [systemd, Kubernetes and Workload API setup](docs/deployment.md)
- [Acceptance commands and gaps](docs/acceptance.md)
- [Design](docs/design.md)
- [Security review record](docs/security-review.md)

```sh
go vet ./...
go test -race ./...
```

The tests serve the checked-in packs over a real Unix socket against a local TLS server. They are not evidence of successful GitHub or Linear account operations, deployed SPIRE rotation or a Kubernetes deployment. None of those has been run.
