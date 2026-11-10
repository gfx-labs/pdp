# YAML data and Rego policy

Rego defines authorization. YAML supplies data for those rules. The normal
`full`, `read` and `read_write` configurations do not require a user-written
module because PDP embeds [base.rego](../pkg/policy/base.rego). They still run
through Rego, not an alternative Go authorization path.

## Follow one repository grant

This is the policy data from [github-read.yaml](github-read.yaml):

```yaml
policy:
  grants:
    - id: approved-repository-read
      mode: read
      scope:
        identities: [local-worker]
        providers: [github]
        bindings: [github-repo]
      constraints:
        repositories: [APPROVED_OWNER/APPROVED_REPOSITORY]
```

The loader validates the configuration and installs normalized policy data at
`data.pdp.config`. Normalization fills absent lists and constraints, incorporates
reviewed provider operation metadata and builds selector references. The complete
YAML is not simply passed through unchanged. Credentials and adapter secrets
never enter policy data or input.

These excerpts are the actual rule structure in the embedded module, not a
standalone replacement module. Its `config` alias is `data.pdp.config`:

```rego
package pdp.base

import rego.v1

config := data.pdp.config

default grant_matches(_, _) := false

grant_matches(grant, unit) if {
    scope_matches(grant.scope, unit)
    mode_matches(grant, unit)
    operation_allows(grant, unit)
    satisfied(grant.constraints, unit)
}

scope_matches(scope, unit) if {
    listed(scope.identities, input.identity.id)
    listed(scope.providers, input.provider)
    listed(scope.bindings, input.binding)
    listed(scope.operations, unit.id)
}

mode_matches(grant, unit) if {
    grant.mode == "read"
    reviewed(unit)
    operation(unit).classification == "read"
}
```

The rest of the embedded module defines those helpers, including their
fail-closed defaults. Rego checks the repository list against the canonical
`owner/repo` resource Go extracted from the validated request. Every requested
repository must be allowed. An operation ID or HTTP method alone is not enough;
restricted access also needs reviewed operation metadata for the pinned schema.

For [linear-read-write.yaml](linear-read-write.yaml), the YAML instead supplies
`mode: read_write` and `constraints.issues`. Go produces separate field
occurrences, resolved arguments and ancestor resource context. Rego checks each
occurrence, the issue allowlist and the reviewed comment object's required
`issueId`/`body` keys. A second alias targeting an unapproved issue denies the
whole request, even when the first alias is approved.

## How allow and deny combine

The complete embedded policy defaults to deny. Each normalized REST operation
or GraphQL field occurrence needs at least one complete matching grant. Several
grants are alternatives, not fragments that can be combined to satisfy a
request. Explicit denies, failed mandatory restrictions and custom denials
override matching grants, including `full`.

Go supplies trusted identity, provider, binding, schema digest and normalized
request values. The engine constructs its private `_pdp` fact envelope; callers
do not supply grant matches or denials. Rego returns `allow`, overriding rules
and per-occurrence grant matches. Go formats those results for `pdp explain`.
See the [full evaluation contract](../policies/README.md).

## Run a custom Rego denial

[github-comment-freeze.yaml](github-comment-freeze.yaml) is a complete runnable
configuration. It keeps the repository's `read_write` grant and adds:

```yaml
policy:
  # Keep the grants from github-comment-freeze.yaml here too.
  custom_modules:
    comment-freeze.rego: |
      package pdp.custom

      import rego.v1

      deny contains "GitHub comments are temporarily frozen" if {
          input.provider == "github"
          some operation in input.operations
          operation.id == "issues/create-comment"
      }
```

`comment-freeze.rego` is the module's name for diagnostics. Its value is inline
Rego source, not a path to a file. Custom modules must use `package pdp.custom`
and contribute reason strings to `deny`. They cannot grant access or replace
`pdp.base`. The YAML `grants` remain data evaluated by the base Rego rules.

Run these commands from the repository root. They do not open a provider secret,
contact GitHub or create a comment:

```sh
make build
bin/pdp validate --config examples/github-comment-freeze.yaml
bin/pdp explain --config examples/github-read-write.yaml \
  --input examples/explain-github-comment-freeze.json
bin/pdp explain --config examples/github-comment-freeze.yaml \
  --input examples/explain-github-comment-freeze.json
```

The same input matches the repository read/write grant in both configurations:

| Configuration | `allow` | `matched_grants` | `denied_by` |
| --- | --- | --- | --- |
| `github-read-write.yaml` | `true` | `approved-repository-read-comment` | empty |
| `github-comment-freeze.yaml` | `false` | `approved-repository-read-comment` | `custom` |

The frozen result includes the reason `custom deny: GitHub comments are
temporarily frozen`. Ordinary supported reads on the same repository remain
allowed. The custom denial is not a replacement for the repository constraint;
requests outside that constraint still lack a grant.

The JSON is a trusted administrator explanation input, not a provider payload
and not an endpoint for selecting caller identity. Normal workload requests
still use the unchanged [GitHub](github.md) and [Linear](linear.md) request
examples. Authorization explanations do not establish real-provider acceptance.
