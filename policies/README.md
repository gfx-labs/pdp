# Policy examples and security model

`direct.json` is a minimum policy configuration. It grants one trusted identity
full access to one provider binding. It needs no operation registry, schema
coverage, task graph or custom Rego. The gateway still validates any configured
schema and controls the provider endpoint and credentials.

`restricted.json` demonstrates reviewed operation classification, schema pinning,
direct repository and issue allowlists, mandatory restrictions and explicit deny.
Replace its placeholder digest with the digest of the reviewed local schema.
The path parameter names must match that schema. It allows issue 1 in repository
gfx-labs/pdp and denies issue 2 despite the matching grant.

## Evaluation

The authorization rules live in [`pkg/policy/base.rego`](../pkg/policy/base.rego),
embedded into the daemon. YAML/JSON specifies policy data, not a separate policy
implementation. The loader validates that data and installs an immutable
normalized document at `data.pdp.config`. Rego evaluates grant scope, profiles,
reviewed-operation guards, every constraint, explicit denies, mandatory rules
and optional relationships. It returns the decision and per-occurrence grant
matches used by `pdp explain`.

Go authenticates the connection, validates the input envelope and extracts
resources and selector values from normalized requests. It does not decide
which grants match or precompute denials. Wildcard selectors and exact numeric
canonicalization remain request normalization, with matching performed in Rego.

- Default is deny. Each normalized REST operation or GraphQL field occurrence
  must match at least one complete grant. Aliases and repeated fields retain
  their individual arguments, including when their coordinates are identical.
- A grant names identities, providers and credential bindings explicitly. Empty
  lists are not permitted for those grant scope dimensions. `*` is not a wildcard.
- `full` needs no operation classification. `read` requires a reviewed `read`
  operation. `read_write` permits reviewed `read` and `write` operations only.
  Neither restricted mode admits unknown, unreviewed, destructive or admin
  operations, regardless of HTTP method. An explicit operation grant with no
  mode requires a reviewed registry entry and can deliberately grant a
  destructive or admin operation. Its scope must list the operations.
- Reviewed operation metadata can attach `constraints` that every restricted
  profile and explicit operation grant must satisfy. Object constraints select
  an object using `source`, `field` and `path`, reject keys outside
  `allowed_keys`, and require every `required_string_keys` entry to be a
  nonempty string. They do not flatten an array into a valid object. The
  reviewed Linear comment operation allows only `issueId` and `body`, both
  required. An approved issue alongside `projectId`, `parentId`, actor, Slack
  or other alternate-target keys is not an authorized issue-only comment.
  Full grants deliberately bypass reviewed operation constraints. Put a shape
  restriction in `mandatory` to apply it to full grants as well.
- The `untyped:` operation ID namespace is reserved for schema-free gateway
  requests. Registry entries cannot use it, so restricted modes cannot authorize
  a schema-free synthetic operation by configuration accident.
- All constraints on one grant are conjunctive. Repository and issue lists use
  resource types `repository` and `issue`. Every requested resource of that type
  must match, and the type must be present. Resources come from trusted normalized
  operation metadata or explicit resource selectors in the reviewed registry.
  An absent optional resource selector produces no resource. Resource-constrained
  grants and mandatory rules still require their requested resource types, but
  an unrelated full grant does not acquire a profile's optional target requirement.
  Resource IDs are exact scalar strings or JSON integers, never rounded floats.
  Numeric IDs normalize equivalent decimal/exponent forms and are limited to
  1024 decimal digits. Fractions or larger numeric IDs fail closed.
  Repository IDs must include the owner, not only a repository basename.
  Resource selectors can use `components: [["owner"], ["repo"]]` instead of
  `path` to join exactly one nonempty string per component with `/`. Slashes in
  components are forbidden, preventing ambiguous joins across owners.
- Grants are independent alternatives. Constraints are never combined across
  grants. Overlapping scope diagnostics make those alternatives visible.
- A matching explicit deny overrides every grant. Deny lists match if any
  requested resource or selected value is forbidden. Other constraints on that
  deny remain conjunctive. A mandatory rule instead requires every applicable
  value to satisfy its constraints. Mandatory failure overrides every grant,
  including `full`. Empty rule scopes apply globally.
- Value selectors read `path`, `query`, `body`, `graphql`, `variables` or
  `resource`. `path` is the normalized HTTP path-parameter map. `query` retains
  the schema-normalized value types, including integers and booleans, from
  `http.normalized_query`. Schema-backed inputs never fall back to raw query
  strings when normalized values are absent. Only schema-free legacy inputs
  without a normalized query use raw `http.query`, retaining every URL value.
  `graphql` reads only the current field occurrence's argument map.
  Its optional `field` limits applicability to one schema coordinate.
  `resource` reads the current operation's supplied resource metadata. `*` path
  segments select every array/object member. Missing required values fail,
  including a missing member beside a matching member. For grants and mandatory
  rules every selected value must match an allowed value. Explicit null is not
  a present required value. A missing sibling never hides a forbidden value
  from an explicit deny. JSON numbers compare by exact mathematical value,
  including equivalent decimal/exponent forms, without float rounding.
  GraphQL descendants inherit resources only from strict ancestor occurrence
  paths. Sibling aliases cannot lend their resource context to each other.
  A descendant's additional resources cannot erase inherited restrictions.
- A registry entry's optional `schema_digest` pins its reviewed classification
  to that schema. Mandatory `schema_digests` restrictions also apply to full
  grants. The trusted gateway supplies the digest, never a request header.

## Optional relationship requirements

Only grants or mandatory rules with `constraints.relationship` depend on the
snapshot. A requirement supplies an exact `permission` and optional
`resource_types`. It requires a trusted selected task, an unexpired
identity-to-task membership, and an unexpired task-to-resource edge carrying the
exact permission for every selected resource. No transitive graph traversal,
custom relationship types or permission hierarchy is supported.

A relationship snapshot has a nonempty revision, `issued_at`, `expires_at`, a
positive `max_age`, `identity_tasks`, and `task_resources`. Times are RFC3339.
`max_age` is a Go duration encoded as integer nanoseconds in JSON. Each edge has
an explicit `expires_at`. Future-issued, stale or expired required snapshots
fail closed. Missing required snapshots deny. Unrelated direct grants remain
usable without relationships. No positive decision cache exists, so expiration
is checked on each decision. The decision includes both policy and relationship
revisions.

## Custom Rego

`restrict.rego` is an optional Rego v1 constraint. Put its text in a
`custom_modules` map entry when loading configuration. Every module must use
`package pdp.custom`. The public contract is `deny`, a set of reason strings.
An `allow` rule cannot grant authority or bypass a base restriction. Custom code
cannot replace the embedded policy namespace. Network builtins and runtime
introspection are disabled. Compilation and evaluation failures deny.

Custom Rego sees the versioned normalized input at its top level, including the
trusted `identity`, `provider`, `binding`, `schema_digest`, normalized `http`,
`operations`, and ordered `graphql` occurrence list. `_pdp` is an engine-owned
facts envelope containing `units`, `revision` and decision time `now_ns`. Each
unit has an operation ID, optional field coordinate, extracted resources,
resource-normalization error and selected `values`/`objects`. Values use canonical
JSON keys for exact numeric equality. These are request facts, not precomputed
grants or denials. `_pdp` is an internal contract, not a caller-supplied extension.
Request content cannot replace those facts. The gateway must never populate
trusted envelope fields from unauthenticated request metadata.
Verified identity metadata includes `auth_method`, `spiffe_id` when authenticated
by SPIFFE, and `uid` when authenticated by Unix peer credentials. UID zero is
present, not confused with absent metadata. A configured principal alias does
not replace the authentication proof identity. Custom Rego should use
`http.normalized_query` for schema-typed conditions, not raw `http.query` strings.

## Publication and diagnostics

`policy.New` copies configuration, validates it and prepares embedded OPA v1
queries. An engine is immutable and safe for concurrent evaluation. Build and
validate a replacement snapshot before the gateway atomically publishes its
pointer. The gateway owns atomic swaps with provider schemas and bindings.
Every decision reports the selected policy revision, including denials and
errors. Diagnostics report unknown configured operation references, unreviewed
operations and overlapping grants. Custom literal operation-ID/coordinate
comparisons are reference-checked. Dynamic Rego references cannot be checked
exhaustively at load time. The root configuration loader rejects unknown
operation-reference diagnostics. Evaluate explanations list matched grants,
per-operation matches and overriding denial reasons.
