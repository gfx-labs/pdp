# Linear: issue reader and comment worker

Follow the [shared identity and socket setup](README.md#set-up-the-identity-boundary) first. These configurations use direct issue allowlists, without custom Rego, task records or relationship services. Caller requests always use `/upstreams/linear/graphql`; the caller cannot select a workspace credential or destination.

## Read an approved issue

Start with [linear-read.yaml](linear-read.yaml), the read-only app-actor client-credentials configuration. Prepare an approved Linear OAuth app for this flow, replace `REPLACE_CLIENT_ID`, and mount its client secret at `/run/secrets/linear-client-secret` for the daemon alone. Use this flow only when app-actor client credentials are the intended integration. An existing user-authorized installation is not interchangeable with it; see [refresh installations](#use-an-existing-oauth-installation).

Replace `APPROVED_ISSUE_UUID` in both the config's `constraints.issues` and [requests/linear/read-issue.json](requests/linear/read-issue.json) with the same approved UUID. Replace the caller UID and socket permissions, and fix schema paths if relocating the YAML. The examples use exact issue IDs; a team ID or caller-provided task label does not grant access.

As the daemon account, validate and serve the prepared config:

```sh
bin/pdp validate --config /etc/pdp/linear-read.yaml
bin/pdp serve --config /etc/pdp/linear-read.yaml
```

As the mapped workload account, read the approved issue:

```sh
PDP_SOCKET=/run/pdp/pdp.sock
bin/pdp request --socket "$PDP_SOCKET" --method POST \
  --path /upstreams/linear/graphql \
  --body examples/requests/linear/read-issue.json
```

The request selects `id`, `identifier`, `title` and `description` using a typed variable and explicit `operationName`. PDP resolves the schema coordinates and arguments, checks the issue scope and injects the app's credential only after allow. No secret appears in the body or caller command. Edit JSON files directly or generate prepared copies: shell variables are not interpolated inside the supplied files.

Inspect the provider's JSON `data` and `errors`, not just HTTP status. Successful HTTP transport does not establish a successful GraphQL operation or the intended provider actor.

## Reject a mixed-scope query

[requests/linear/read-mixed-scope.json](requests/linear/read-mixed-scope.json) selects an approved issue and a different issue through aliases and a fragment. Replace its approved ID consistently, and keep the second ID outside the allowlist. Under either restricted Linear configuration:

```sh
# Expected denial of the entire request, not a partial result.
bin/pdp request --socket "$PDP_SOCKET" --method POST \
  --path /upstreams/linear/graphql \
  --body examples/requests/linear/read-mixed-scope.json
```

The expected PDP result is HTTP 403 with no upstream request. An approved selection does not make another selection permissible. Changing aliases, using fragments, repeating a field or putting a forbidden field behind `@skip`/`@include` does not bypass authorization: conditional selections are authorized conservatively.

## Allow comments on approved issues

Use [linear-read-write.yaml](linear-read-write.yaml) instead of the read-only config. It uses the same app-actor flow and exact issue allowlist, adds the configured `comments:create` scope and changes the gateway grant to `read_write`. The provider installation must support the requested scopes. Do not expand a refresh installation's scopes merely by editing this configuration.

[requests/linear/create-comment.json](requests/linear/create-comment.json) uses `CommentCreateInput` with exactly `issueId` and `body`. Replace the issue ID with a **named disposable issue approved for writes**, include it in the daemon's allowlist and obtain explicit write approval before submitting:

```sh
# DO NOT RUN without named-issue write approval and a prepared request file.
bin/pdp request --socket "$PDP_SOCKET" --method POST \
  --path /upstreams/linear/graphql \
  --body examples/requests/linear/create-comment.json
```

The same mutation must deny under `linear-read.yaml`. Under `linear-read-write.yaml`, it is permitted only for approved issues and the reviewed input shape. A successful provider response should have `data.commentCreate.success` and the resulting comment; inspect any `errors` and record the provider actor without credentials. No live comment has been created for this example. Do not automatically retry an uncertain mutation or perform cleanup without separate approval.

| Request under `linear-read-write.yaml` | Expected PDP result |
| --- | --- |
| Read selected supported fields on an allowed issue | Allow |
| Comment with nonempty `issueId` and `body` on an allowed issue | Allow |
| Read or comment on another issue | Deny |
| Add `projectId`, `parentId`, `createAsUser` or another input key | Deny, even if `issueId` is approved |
| Select an unreviewed field such as `Issue.url` | Deny |
| Unsupported mutation, batch or subscription | Reject before forwarding |

[requests/linear/reject-alternate-target.json](requests/linear/reject-alternate-target.json) records the mixed issue/project input that restricted profiles must reject. It is an **offline regression probe**, not a command to send to a live installation. Do not try negative mutation probes under `full`: full mode intentionally does not apply restricted-profile object guards and may allow the write.

## Use an existing OAuth installation

[linear-oauth.yaml](linear-oauth.yaml) demonstrates refresh-token acquisition for an already authorized app-actor installation. It is deliberately a **full-access credential-shielding template**, not the issue-restricted read/write example. Its gateway route is unchanged, but `full` has no issue allowlist or operation restrictions. The provider credential's scopes still apply.

For an existing restricted integration, start from `linear-read.yaml` or `linear-read-write.yaml` and use the refresh provider/binding setup from `linear-oauth.yaml`, retaining the pinned schema, restricted grant and issue allowlist. Keep the route and grant binding names consistent. Set the actual originally authorized actor and exact granted scopes. Do not copy a broad full grant alongside the narrow one, and do not replace the installation with a client-credentials grant without intentionally choosing that actor model.

The daemon needs a mounted client secret and a private, durable, writable OAuth state directory. Provision its initial state through the administrator-owned authorization setup, never a caller request. Refresh replacements are serialized and persisted before successful use. If the state records an uncertain refresh outcome, reconcile or reauthorize through the provider instead of clearing `recovery_required` and replaying an old refresh token. See the [credential adapter contract](../pkg/credential/README.md) and [OAuth configuration](../docs/configuration.md) for state requirements.
