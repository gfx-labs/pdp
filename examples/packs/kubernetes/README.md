# kubernetes

PDP as the egress point for a namespace, with two kinds of caller:

| Caller | How it reaches PDP | Identity in policy | Allowed here |
| --- | --- | --- | --- |
| Proxy-aware workload | mTLS with its SVID to `:8443`, then absolute-form or `CONNECT` | SPIFFE ID | `api.example.com` with the `example-api` credential |
| Steered workload | Its resolver is PDP. Listed names resolve to PDP's Service IP. | Pod IP only | `GET`/`HEAD` to the steered hosts, no credential |

A source IP is weaker than an SVID. `policy.rego` never gives a steered caller a binding.

Not applied to any cluster. `manifests.yaml` is a template that has only been read, not run.

## What the manifests set up

- **Interception CA.** A cert-manager `Certificate` with `isCA: true` under a private root. Its Secret is mounted only into the PDP pod. PDP rereads the files when they change, so renewal needs no restart.
- **Workload trust.** A trust-manager `Bundle` publishes the private root with the public roots to namespaces labelled `pdp.example.org/egress: gateway`. Workloads trust the root, so the interception CA can be renewed without touching them. PDP must serve the CA certificate in its chain: `tls.crt` from cert-manager holds it.
- **Name constraints.** The CA may only sign for the listed hosts. The client's TLS library enforces this, so check that yours does. The `NameConstraints` feature gate is on by default from cert-manager 1.17. Earlier versions need it enabled on the controller and webhook.
- **Bypass.** One `NetworkPolicy` limits workload egress to PDP. Another limits who can reach PDP. Without the first, a pod can connect to an IP address directly and PDP never sees it. Your CNI must enforce NetworkPolicy.
- **DNS.** `dns.address` in `pdp.json` must equal the Service `clusterIP`. Only upstream hosts and `dns.intercept` names are answered with it. Other names go to `dns.resolver`, here the cluster DNS. Set `"unlisted": "refuse"` and remove `resolver` to refuse them.

## Edit

- `policy.rego`: `allowed_workloads`, `steered_pods` (the pod CIDR), `steered_hosts`.
- `pdp.json`: `dns.address`, `dns.resolver`, `dns.intercept`, the upstream and its secret path.
- `manifests.yaml`: image digests, `clusterIP`, namespaces, `nameConstraints` hosts. Keep the hosts in `nameConstraints`, `dns.intercept` plus upstreams, and the policy in step.

## Check

```sh
bin/pdp validate --config examples/packs/kubernetes/pdp.json
for input in examples/packs/kubernetes/explain/*.json; do
  bin/pdp explain --config examples/packs/kubernetes/pdp.json --input "$input"
done
```

| Input | Result |
| --- | --- |
| `spiffe-workload.json` | allowed with the credential |
| `steered-read.json` | allowed, no credential |
| `steered-credentialed-host.json` | denied, an IP-identified caller asked for the credentialed host |

## Limits

- No cluster, SPIRE, cert-manager or trust-manager run has been done with these files.
- Pod IPs are reused. A decision keyed on `identity.ip` applies to whichever pod holds the address.
- If the CNI rewrites the source address before traffic reaches the pod (some Service or node-port paths do), every steered caller looks the same. Check what PDP logs as `principal`.
- DNS steering is UDP only. A changed set of steered names needs a restart, not a reload.
- A proxy-aware client must be able to present a client certificate to its proxy. Many HTTP clients cannot.
- PDP runs one replica here. Credential state files and the DNS address assume that.
