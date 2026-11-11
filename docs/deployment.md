# Deployment

The files under `examples/packs/systemd` and `examples/packs/github-spiffe` are templates. Nothing in this repository creates accounts, copies secrets, installs units, registers SPIFFE identities or applies Kubernetes resources. Tests validate the two packs offline and run the Unix transport, socket activation and a local Workload API server. No SPIRE server, systemd installation or Kubernetes cluster has been used.

## What the outer boundary is

Go authenticates and does nothing else with the result:

- **Unix socket.** The kernel peer UID of the connection becomes `input.identity` with `id` `uid:<n>`, `auth_method` `unix` and `uid`.
- **SPIFFE mTLS.** The client certificate is verified against the current Workload API bundle on every request, including reused connections. The verified ID becomes `input.identity` with `auth_method` `spiffe` and `spiffe_id`.

PDP does not map these identities to principals and does not hold an allowlist. Any local UID that can open the socket, and any workload in a trusted SPIFFE domain, reaches policy. Default deny in Rego then refuses the ones the policy does not name, with `403`. Earlier versions answered `401` to an unmapped caller. The outer boundary is therefore the socket's file permissions and the trust bundle. Treat both as part of the access control, and name exact UIDs or SPIFFE IDs in `policy.rego`.

## Unix isolation

Use a daemon account distinct from every credentialless workload account. Only the daemon account should read mounted provider secrets or writable OAuth token state. A caller that shares the daemon's UID can usually read those files directly, whatever the policy says. A private socket alone does not separate processes with the same UID. `SO_PEERCRED` supplies the kernel UID, not a unit or session. A UID shared by several sandboxes is one identity and gives no per-session isolation. PID, systemd unit names, cgroups and environment labels are not identities.

The socket's parent must exist, be owned by the daemon or root, and not be group or world writable. Parent symlinks are rejected. Use `/run/pdp/pdp.sock` or a private administrator-managed directory, never `/tmp/pdp.sock`. No caller identity header is trusted. Headers are not passed to policy.

For a non-systemd service, use a trusted parent with a caller-accessible group, set `socket_mode` to `0660`, and arrange the created socket's group through the daemon's primary group or the parent's setgid group. Do not give workloads write access to the parent directory or the secret directories. Mode `0600` suits a same-user smoke test, not secret isolation.

## systemd

`examples/packs/systemd` holds `pdp.service`, `pdp.socket`, `pdp.json`, `policy.rego` and `adapter.star`. The policy is the `minimal` pack policy (`examples/packs/minimal/policy.rego`): named Unix UIDs get everything the GitHub credential can do on one binding.

Before installing, an administrator must:

1. Create distinct `pdp` and `pdp-clients` accounts and groups, and add only intended callers to the client group.
2. Install the `pdp` binary at `/usr/local/bin/pdp`, and `pdp.json`, `policy.rego` and `adapter.star` in `/etc/pdp`, owned by root.
3. Put the token in `/etc/pdp/secrets/github-token`.
4. Edit `allowed_uids` in `policy.rego` to the real caller UIDs. This is the only place callers are named.

The socket unit sets owner `pdp`, group `pdp-clients` and mode `0660`. The service runs as `pdp` with no capabilities, a read-only system, explicit runtime and state directories, and `LoadCredential` for the token. The parent directory is traversable but not writable by clients. `RuntimeDirectoryPreserve=yes` stops a service stop from unlinking a socket the socket unit still owns. Review `MemoryMax`, `TasksMax` and `LimitNOFILE` against your schemas and policy.

Offline checks:

```sh
make build
CREDENTIALS_DIRECTORY=/run/credentials/pdp.service \
  bin/pdp validate --config examples/packs/systemd/pdp.json
systemd-analyze verify examples/packs/systemd/pdp.service examples/packs/systemd/pdp.socket
```

`CREDENTIALS_DIRECTORY` tells validation where the credential would be. No secret is read. `systemd-analyze verify` reports that `/usr/local/bin/pdp` is missing until the binary is installed. That is the only complaint about these two units. It may also print warnings about unrelated units on the host.

Socket activation accepts exactly one Unix stream descriptor (FD 3) with a matching `LISTEN_PID` and `LISTEN_FDS=1`. The inherited path must equal `transport.unix_socket`. PDP does not unlink the activated socket on exit. Without activation PDP creates the socket and refuses an existing path. Remove a stale socket only after checking that nothing serves it.

`ExecReload` sends `SIGHUP`. Successful delivery does not mean the configuration was accepted. Wait for `reload_applied` with the new `revision` in the journal, and see [Reload and revocation](configuration.md#reload-and-revocation). Changing `allowed_uids` needs a new `revision` and a reload, not a restart.

Primary socket-activation contract: <https://www.freedesktop.org/software/systemd/man/latest/sd_listen_fds.html>.

## Optional SPIFFE mTLS

SPIFFE is optional. The minimal deployment is Unix peer credentials only. PDP uses `github.com/spiffe/go-spiffe/v2` with an X.509 Workload API source, not copied SVID files. The listener requires TLS 1.3 and disables session resumption. The listener accepts any peer whose certificate verifies against the bundle. The policy then compares `input.identity.spiffe_id` with the IDs it allows. The gateway's own SVID is a workload identity, not a GitHub or Linear credential.

Configure `transport.spiffe` alone for a network deployment, or together with `transport.unix_socket` for two listeners. The `github-spiffe` pack sets only SPIFFE. Restrict the Workload API socket to approved processes. At startup PDP waits up to 10 seconds for the Workload API and exits if it cannot get an identity. Offline `validate` and `explain` do not open the Workload API and cannot establish an installed SPIRE deployment or certificate rotation.

```sh
bin/pdp validate --config examples/packs/github-spiffe/pdp.json
bin/pdp explain --config examples/packs/github-spiffe/pdp.json \
  --input examples/packs/github-spiffe/explain/approved-workload.json
bin/pdp explain --config examples/packs/github-spiffe/pdp.json \
  --input examples/packs/github-spiffe/explain/neighbor-workload.json
```

The first `explain` allows. The second is another workload in the same trust domain and denies with `caller SPIFFE ID is not allowed`.

Primary library and workload references:

- <https://github.com/spiffe/go-spiffe>
- <https://spiffe.io/docs/latest/deploying/configuring/>

## Kubernetes and service-account attestation

`examples/packs/github-spiffe/deployment.yaml` holds a ServiceAccount, a Deployment and a Service. It requires:

- an existing `pdp` namespace
- installed SPIRE server and agents and the SPIFFE CSI driver
- a `pdp-config` ConfigMap holding `pdp.json`, `policy.rego`, `adapter.star` and `github-rest.json`, because `pdp.json` names all four
- a `pdp-provider-credentials` Secret with the token at the path `pdp.json` names

Replace the deliberately invalid image with an approved immutable digest. The CSI volume mounts the Workload API without a hostPath. The Secret is read-only and the container filesystem is read-only. The example uses a static mounted token. A refresh installation also needs a private, durable, daemon-writable state volume, not a read-only Secret.

Register a SPIFFE ID for the gateway and one for each caller. Selectors must come from trusted attestation, including the intended namespace and service account and the real agent parent. `k8s:ns` and `k8s:sa` are attestor selectors, not caller labels. Do not let unrelated users create workloads under an authorized service account. A mutable pod label is not enough. Node or root compromise is inside the SPIRE trust boundary.

The Service does not authorize callers. A caller needs its own SVID and an entry in `allowed_workloads` in `policy.rego`. Do not replace mTLS with an identity header. The TCP readiness probe shows the listener is up. It says nothing about provider credentials or policy.

Run cluster commands only after authorization, with explicit context discovery through `kubie list --json` and then `kubie exec -e CONTEXT pdp ...`. Do not change the global kube context. For several replicas, each accepted revision must be acknowledged by every replica, or stale replicas removed from service, before claiming revocation.

Primary references:

- <https://github.com/spiffe/spiffe-csi>
- <https://github.com/spiffe/spire/blob/main/doc/plugin_agent_workloadattestor_k8s.md>

## Later Jobshop integration

No Jobshop configuration is included. A future integration should expose only the gateway socket or mTLS endpoint to a sandbox, never provider secrets or OAuth state. A Unix integration needs verified distinct UIDs and socket-group access. A SPIFFE integration needs narrowly selected Workload API access and registered workload identities. Do not claim session isolation from PID, systemd unit names, cgroups or environment labels until the attestor verifies those selectors. Confirm that the intended sandbox reaches the gateway and that a neighboring sandbox with another identity gets `403`. Measure daemon and SPIRE resource use separately.
