# PDP development

PDP is a standalone prototype. Development and subagent coordination run in this checkout, not through jobcity. This repository is an explicit exception to the general GFX/Oku jobcity routing convention.

Use Go and commit scoped changes. Keep provider credentials out of source, policy input, logs, errors and caller responses. Never execute real provider writes without authorization for named disposable resources. Local tests do not establish real-provider or SPIRE deployment acceptance.

Place Go library packages under `pkg/` so downstream modules can import them. Keep executable entry points under `cmd/`.

Rego is the only policy path. Administrators write modules in package `pdp.authz`, and only a boolean `allow` authorizes. That includes which UID or SPIFFE ID is allowed: Go authenticates and passes verified facts, with no identity maps. Go also validates and normalizes requests, invokes OPA and formats the result. Do not add permission semantics, grant or profile formats, or identity mapping in Go or in configuration.

Runtime configuration is JSON (`pdp.config/v2`) and holds wiring only. There is no YAML configuration.

Examples are packs under `examples/packs/<name>/`, each complete and runnable: `pdp.json`, `policy.rego`, `adapter.star`, any schema, `requests/`, `explain/` and a README. A change to policy input, configuration or adapters updates every affected pack and its README, and `TestPacksServeTheirRequests` in `cmd/pdp` must serve the packs as shipped.

Unix peer credentials are a supported authentication mode, not a development bypass. A shared Unix UID is a shared identity. SPIFFE mTLS is optional and must not be required for the minimal deployment.
