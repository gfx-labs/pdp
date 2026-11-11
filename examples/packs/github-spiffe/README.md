# github-spiffe

Read one GitHub repository, for named SPIFFE workloads over mTLS. Includes a Kubernetes manifest.

PDP gets its own certificate and the trust bundle from the SPIFFE Workload API and verifies the caller's certificate on every request. The policy then decides which SPIFFE IDs are allowed. Every workload in a trusted domain can connect, so the policy must name exact IDs.

## Edit

- `policy.rego`: `allowed_workloads` and `allowed_repositories`.
- `pdp.json`: `transport.spiffe.address`, `transport.spiffe.workload_api` and the token path.
- `deployment.yaml`: the image, namespace, ConfigMap and Secret names. The ConfigMap must hold every file in this pack that `pdp.json` names: `pdp.json`, `policy.rego`, `adapter.star` and `github-rest.json`.

## Check

```sh
bin/pdp validate --config examples/packs/github-spiffe/pdp.json
bin/pdp explain --config examples/packs/github-spiffe/pdp.json \
  --input examples/packs/github-spiffe/explain/approved-workload.json
bin/pdp explain --config examples/packs/github-spiffe/pdp.json \
  --input examples/packs/github-spiffe/explain/neighbor-workload.json
```

The first allows. The second is another workload in the same trust domain and denies with `caller SPIFFE ID is not allowed`. Validation does not open the Workload API.

## Status

This pack is validated and explained offline only. It has not been served against SPIRE or applied to a cluster. The SPIFFE listener and certificate rotation are covered by a test that runs a local Workload API server, not a SPIRE deployment.
