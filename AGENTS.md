# PDP development

PDP is a standalone prototype. Development and subagent coordination run in this checkout, not through jobcity. This repository is an explicit exception to the general GFX/Oku jobcity routing convention.

Use Go and commit scoped changes. Keep provider credentials out of source, policy input, logs, errors and caller responses. Never execute real provider writes without authorization for named disposable resources. Local tests do not establish real-provider or SPIRE deployment acceptance.

Place Go library packages under `pkg/` so downstream modules can import them. Keep executable entry points under `cmd/`.

Rego owns authorization: grant matching, profiles, constraints, explicit denies, mandatory restrictions and relationship checks. YAML/JSON specifies policy data. Go validates configuration and trusted input, normalizes request facts, invokes OPA and formats explanations. Do not compute authorization candidates or denials in Go for Rego to tally.

Policy architecture and configuration changes include every affected example and provider walkthrough. Show the YAML-to-Rego relationship explicitly and validate the documented examples through the CLI, not only the underlying engine tests.

Unix peer credentials are a supported authentication mode, not a development bypass. A shared Unix UID is a shared identity. SPIFFE mTLS is optional and must not be required for the minimal deployment.
