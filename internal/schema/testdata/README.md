# Recorded public schema inputs

These are pinned upstream schema inputs or explicit restricted projections of them. They are not invented provider API models. Tests load them locally and never call provider APIs. Restricted projections describe an allowlisted request surface, not the complete provider schema or complete OpenAPI support.

| File | Primary source revision | Source SHA-256 |
| --- | --- | --- |
| `github-rest.json` | `github/rest-api-description` commit `2f8f80e47ea4d3292cf4e37ba9d9b25475e06140`, `descriptions/api.github.com/api.github.com.json` | `b8973e498305c0e45891c45a109901f9caf6ecbf8ad0e53404a7947c503e120f` |
| `linear.graphql` | `linear/linear` commit `9ba7b299eb5fb0036d14d2e8299e18e7c4bd13e3`, `packages/sdk/src/schema.graphql` | `dc0f838785760f8daa692e438fcd15071c5bc39c6997758d5c2d303364f98e56` |
| `swapi.graphql` | `vektah/gqlparser` tag `v2.5.64`, `validator/testdata/swapi.graphql` | `06036fb3998a211b111cc28f94e4fe16df8dd275b5f89839ec06528515359ba9` |
| `oai-petstore.json` | `OAI/OpenAPI-Specification` tag `3.0.4`, `examples/v3.0/petstore.json` | `be0224057e99580bbbd7285f23249e6ed9f94278ff06abda269fafce6cde521a` |

Recorded November 9, 2026. GitHub, Linear and gqlparser source files use their repositories' MIT licenses, reproduced in `LICENSE-GitHub`, `LICENSE-Linear` and `LICENSE-gqlparser` respectively. The OpenAPI example is from the Apache-2.0 licensed OpenAPI Specification repository, whose license is included as `LICENSE-OpenAPI`.

## Projection decisions

`generate.go` deterministically generates the two provider projections and verifies the complete downloaded source digests before processing them.

- GitHub retains `repos/get`, `issues/get`, `issues/list-comments` and `issues/create-comment`, including their actual path parameter types and comment request body shape. Shared path/query parameters are resolved to their upstream definitions. The `since` query parameter is omitted because its date-time format is unsupported by the narrow importer. Parameter `default` annotations for pagination are removed, so supplied values remain explicit and policy cannot mistake a documentation default for a forwarded value. Response status codes/descriptions are retained, but response schemas, links, headers and unrelated components are omitted because this package validates requests, not responses. Servers, security schemes, examples unrelated to retained request bodies, extension annotations and unrelated operations are omitted.
- Linear retains the exact upstream `Query.issue` and `Mutation.commentCreate` field definitions, the complete `CommentCreateInput` definition, `DateTime`/`JSON` declarations, `Node`, and selected actual return fields on `Issue`, `Comment` and `CommentPayload`. No field types, optionality, argument types or defaults are invented. Optional custom-scalar input fields remain in the schema so their use fails closed rather than being silently treated as ordinary JSON. Other provider entry points are deliberately absent.
- The original OAI Petstore fixture is unchanged on disk. Tests first verify its unsupported server base path fails import, then explicitly remove that metadata and unsupported `format` annotations in memory to exercise its real operations, references, typed parameters and body shape. The projection does not claim the original file is accepted unmodified.
- The SWAPI fixture is unchanged. Some tests explicitly change a default/type on this recorded schema to verify catalog drift and input coercion.

The full provider schemas are intentionally not vendored. The generated narrow inputs total about 12 KiB instead of importing the complete GitHub and Linear API surfaces.

## Reproduce provider projections

From the repository root, with a scratch directory:

```sh
curl -fsSL https://raw.githubusercontent.com/github/rest-api-description/2f8f80e47ea4d3292cf4e37ba9d9b25475e06140/descriptions/api.github.com/api.github.com.json -o "$JCODE_SCRATCH_DIR/github-openapi.json"
curl -fsSL https://raw.githubusercontent.com/linear/linear/9ba7b299eb5fb0036d14d2e8299e18e7c4bd13e3/packages/sdk/src/schema.graphql -o "$JCODE_SCRATCH_DIR/linear-original.graphql"
go run internal/schema/testdata/generate.go "$JCODE_SCRATCH_DIR/github-openapi.json" "$JCODE_SCRATCH_DIR/linear-original.graphql"
go test -race ./internal/schema
```

Schema membership is not an authorization grant. In particular, actual Linear `CommentCreateInput.body` and `issueId` are optional, and alternative targets exist. A restricted comment policy must require its approved issue ID and body and deny alternative target fields. A team ID supplied in a comment is not proof of issue membership.
