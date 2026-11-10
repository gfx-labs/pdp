# PDP

PDP is a standalone Go gateway that lets a verified workload call GitHub REST or Linear GraphQL without receiving the upstream credential. It authenticates the connection, authorizes the complete request, then obtains and injects the credential. Provider destinations and credential bindings are administrator configuration, never caller input.

## Start with one UID and one binding

Linux Unix-domain HTTP is the minimum deployment. SPIRE, schemas, task records, relationships and custom Rego are optional. Processes sharing a Unix UID share an identity. **Credential isolation also requires the daemon and workload to run under different UIDs.** A workload sharing the daemon UID can generally read its mounted secrets and rotating token state directly. The same-user command below is a transport smoke test, not a secret-isolation boundary. Use the dedicated `pdp` account and caller socket group in the systemd example for a separated deployment.

```sh
go build -o pdp ./cmd/pdp
./pdp validate --config examples/minimal.yaml
```

Copy `examples/minimal.yaml` to a private administrator-owned location. Set the real caller UID, an absolute socket path in an existing protected directory, and an existing mounted credential file. The daemon account must be able to read the credential. Validation compiles configuration without opening provider credentials or calling the provider.

```sh
./pdp serve --config /etc/pdp/pdp.yaml
./pdp request --socket /run/pdp/pdp.sock \
  --path /upstreams/github/repos/OWNER/REPOSITORY
```

`full` permits every supported bounded operation within that provider credential's authority, including destructive and administrative operations. It does not authorize other bindings, destinations, gateway administration or credential retrieval. Use a narrowly scoped provider credential even for a full gateway grant. No provider request in this guide has been executed against a real account as part of local acceptance.

## Permission levels

The policy is [Rego](pkg/policy/base.rego). YAML/JSON supplies its grants, reviewed operations, constraints and optional relationships as immutable `data.pdp.config`. Go authenticates and normalizes requests, then asks OPA for the decision. Grant matching and denial rules are not duplicated in Go. See the [policy model](policies/README.md) for the evaluation contract.

| Mode | Authority |
| --- | --- |
| `full` | Supported valid operations on the explicitly scoped identity/provider/binding. A schema is optional. |
| `read` | Only reviewed operations classified `read` in the pinned schema's operation metadata. Unknown operations deny. |
| `read_write` | Reviewed `read` and `write` operations. Destructive and administrative operations remain excluded. |
| Explicit operations | Only named operations satisfying all grant constraints. |

A schema describes operations, not permissions. Classification is explicit reviewed metadata, never guessed from an HTTP verb or GraphQL query/mutation. See [configuration](docs/configuration.md) for the shipped profile contents and direct repository/issue restrictions. See the examples for schema-pinned read and read/write configurations. Every selected GraphQL field, including nested and repeated fields, must have a grant.

Each grant's constraints are conjunctive. Multiple grants are additive. A narrower grant does not restrict a separate broader grant. Explicit denies and mandatory restrictions override every allow, including `full`. Validation reports overlapping grants. Only selected relationship-constrained grants require graph data.

## CLI

```sh
./pdp validate --config /etc/pdp/pdp.yaml
./pdp explain --config examples/minimal.yaml --input examples/explain-full.json
./pdp catalog --protocol rest --schema pkg/schema/testdata/github-rest.json
./pdp catalog --protocol graphql --schema pkg/schema/testdata/linear.graphql
./pdp schema diff --protocol rest before.json after.json
./pdp request --socket /run/pdp/pdp.sock --method POST \
  --path /upstreams/linear/graphql --body query.json
```

`catalog` includes each operation's structured request contract and stable signature. `schema diff` reports sorted added, removed and changed operation IDs, plus full `before` and `after` contracts in `changed_operations`. Schema changes do not automatically approve new permissions.

`explain` accepts a trusted `pdp.authz/v1` input envelope for administrator debugging. It is not a caller authentication endpoint and does not contact providers. Its output explains the decision and matched grant IDs. A denied explanation is valid output, not a CLI execution failure. `request` exits nonzero on non-2xx responses. It follows no redirects and cannot select an arbitrary URL.

`SIGHUP` validates and atomically publishes a complete new snapshot. Use a new revision for each update. Failed reloads retain the previous snapshot. Listener locations, socket mode, transport/CA configuration and gateway limits require restart. UID and SPIFFE principal mappings, policies, schemas, routes, credential bindings and adapters reload together, including on reused connections. See [configuration](docs/configuration.md#reload-and-revocation) for the exact revocation boundary.

## Deployment and validation

- [GitHub and Linear use-case walkthroughs](examples/README.md), including read-only access, approved comments and denied requests with concrete JSON bodies.
- [YAML-to-Rego policy walkthrough](examples/policy.md), with an offline example of a custom Rego denial overriding a matching grant.
- Native provider setup: [GitHub App](examples/github-app.yaml) and [existing Linear OAuth refresh installation](examples/linear-oauth.yaml). The separate [Linear read/write example](examples/linear-read-write.yaml) deliberately uses app-actor client credentials.
- [Configuration, profiles, limits and OAuth modes](docs/configuration.md)
- [systemd, Kubernetes and Workload API setup](docs/deployment.md)
- [Acceptance commands and external acceptance gaps](docs/acceptance.md)
- [Design and acceptance contract](docs/design.md)
- [Independent security review](docs/security-review.md)

```sh
go test ./...
go vet ./...
go test -race ./...
```

The retained CLI integration test starts the actual Unix server, exercises direct and inherited sockets, forwards to a local TLS endpoint, and revokes a warm credential cache by reloading the verified UID mapping. Local transport tests are not evidence of successful GitHub/Linear account operations, deployed SPIRE certificate rotation or Kubernetes deployment acceptance. Those require approved credentials and infrastructure, and remain pending until measured explicitly.
