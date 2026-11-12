# PDP development

PDP is a standalone prototype. Development and subagent coordination run in this checkout, not through jobcity. This repository is an explicit exception to the general GFX/Oku jobcity routing convention.

PDP is an identity-aware HTTP forward proxy. Callers reach it over a Unix socket, optional SPIFFE mTLS, or optional DNS-steered transparent listeners. It authorizes every request with Rego and injects a provider credential only for a destination whose upstream entry names a binding.

Use Go and commit scoped changes. Keep provider credentials and the interception CA key out of source, policy input, logs, errors and caller responses. Never execute real provider writes without authorization for named disposable resources. Local tests do not establish real-provider, SPIRE, Kubernetes, cert-manager or trust-manager deployment acceptance.

Place Go library packages under `pkg/` so downstream modules can import them. Keep executable entry points under `cmd/`.

Rego is the only policy path. Administrators write modules in package `pdp.authz`, and only a boolean `allow` authorizes. That includes which UID, SPIFFE ID or source address is allowed, and which destinations are reachable: Go authenticates and passes verified facts, with no identity maps. Go also reads the destination, validates and normalizes requests, invokes OPA and formats the result. Do not add permission semantics, grant or profile formats, identity mapping or destination allowlists in Go or in configuration. An `upstreams` entry attaches a binding, schema, TLS mode or token paths. It never allows a destination.

Runtime configuration is one YAML or JSON document (`pdp.config/v3`), decoded by `goccy/go-yaml`, and holds wiring only. Both formats go through the same strict loader: unknown fields, duplicate keys, several documents, anchors, aliases, merge keys and tags are rejected. The same decoder, `schema.DecodeDocument`, reads every other administrator-authored document: policy data, OpenAPI schemas and `pdp explain` inputs. Caller request bodies never go through it and stay strict JSON. YAML is a file format here, not a policy language. Permissions stay in Rego.

Examples are packs under `examples/packs/<name>/`, each complete and runnable: `pdp.json` or `pdp.yaml`, `policy.rego`, `adapter.star` where a credential is used, any schema, `requests/`, `explain/` and a README. A change to policy input, configuration or adapters updates every affected pack and its README, and `TestPacksServeTheirRequests` in `cmd/pdp` must serve the packs as shipped.

Unix peer credentials are a supported authentication mode, not a development bypass. A shared Unix UID is a shared identity. SPIFFE mTLS is optional and must not be required for the minimal deployment. A transparent listener identifies a caller by source address only, which is as trustworthy as the network's protection against spoofing.
