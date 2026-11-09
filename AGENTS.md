# PDP development

PDP is a standalone prototype. Development and subagent coordination run in this checkout, not through jobcity. This repository is an explicit exception to the general GFX/Oku jobcity routing convention.

Use Go and commit scoped changes. Keep provider credentials out of source, policy input, logs, errors and caller responses. Never execute real provider writes without authorization for named disposable resources. Local tests do not establish real-provider or SPIRE deployment acceptance.

Unix peer credentials are a supported authentication mode, not a development bypass. A shared Unix UID is a shared identity. SPIFFE mTLS is optional and must not be required for the minimal deployment.
