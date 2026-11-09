# Deployment templates

These files are unapplied templates, not deployment evidence. This change does not create accounts, copy secrets, install units, register SPIFFE identities, create Kubernetes resources, or alter Jobshop.

## Unix isolation

Use a daemon account distinct from every credentialless workload account. Only the daemon account should read mounted provider secrets or writable OAuth token state. Sharing its UID generally exposes those files directly regardless of gateway policy. A private Unix socket alone cannot isolate same-UID processes. `SO_PEERCRED` supplies the kernel UID, not a unit/session identity. A UID shared by several sandboxes is a shared principal and cannot establish per-session isolation.

The socket's parent must exist, be owned by the daemon or root and not be group/world writable. Parent symlinks are rejected. Use `/run/pdp/pdp.sock` or a private administrator-managed directory, never `/tmp/pdp.sock`. Socket access requires both filesystem permissions and an explicit mapped UID. No caller identity header is trusted.

For a non-systemd service, use a trusted parent with a caller-accessible group, set the socket mode to `0660`, and arrange that created socket group through the daemon's primary group or the parent's setgid group. Do not grant workloads write access to the parent directory or secret directories. The `0600` example is appropriate for a same-user transport smoke test, not secret isolation.

## systemd

`examples/systemd/pdp.service` and `.socket` are matching templates. Before installing them, an administrator must create distinct `pdp` and `pdp-clients` accounts/groups, allow only intended caller UIDs into the client group, install the binary and config at their declared paths, and supply `/etc/pdp/secrets/github-token`. Set the real caller UID in `pdp.yaml`, not the daemon UID. No account/group operations have been run here.

The socket unit sets owner `pdp`, group `pdp-clients` and mode `0660`. The service runs as `pdp` with no capabilities, a read-only system, explicit writable runtime/state directories and a mounted systemd credential. The parent is traversable but not writable by clients. Runtime directory preservation prevents stopping the service from unlinking a socket still owned by the socket unit. Review resource limits for your pinned schemas and policy before installing.

For offline validation of the systemd-credential example, provide the credential-directory context without reading its content:

```sh
CREDENTIALS_DIRECTORY=/run/credentials/pdp.service \
  pdp validate --config examples/systemd/pdp.yaml
systemd-analyze verify examples/systemd/pdp.service examples/systemd/pdp.socket
```

Socket activation accepts exactly one Unix stream descriptor, FD 3, with matching `LISTEN_PID` and `LISTEN_FDS=1`. The inherited path must equal the configured socket path. PDP does not unlink the activated socket on exit. Without activation it creates the socket directly and refuses an existing path. A stale daemon-owned socket requires an administrator to verify no process is serving it before removal. No blind unlink occurs.

`ExecReload` sends `SIGHUP`. Its successful signal delivery is not acknowledgement that configuration was accepted. Wait for `reload_applied` and the expected revision-bearing audit records. Rotation of an upstream refresh token is separate from listener or workload certificate rotation.

Primary socket-activation contract: <https://www.freedesktop.org/software/systemd/man/latest/sd_listen_fds.html>.

## Optional SPIFFE mTLS

PDP uses `github.com/spiffe/go-spiffe/v2` with an X.509 Workload API source, not static copied SVID files. The source watches SVID and bundle updates. The TLS listener requires TLS 1.3 and a bundle-verified SPIFFE certificate. The current snapshot's exact SPIFFE-ID-to-principal mapping is checked for every request, including reused connections. An otherwise trusted identity not present in that mapping is unauthorized. TLS session resumption is disabled. The gateway's SVID is workload identity, not a GitHub or Linear credential.

Configure both `transport.unix_socket` and `transport.spiffe` for dual listeners, or only SPIFFE for a network deployment. Restrict the Workload API socket to approved workload processes. Runtime startup waits for the API and fails closed if it cannot obtain identity. Offline `validate` checks syntax/mappings only and cannot establish an installed SPIRE deployment or certificate lifecycle.

Primary library and workload references:

- <https://github.com/spiffe/go-spiffe>
- <https://spiffe.io/docs/latest/deploying/configuring/>

## Kubernetes and service-account attestation

`examples/kubernetes/deployment.yaml` requires an existing `pdp` namespace, installed SPIRE server/agents and SPIFFE CSI driver, a `pdp-config` ConfigMap containing the selected config, and an existing `pdp-provider-credentials` Secret. Replace the deliberately invalid image with an approved immutable digest. The CSI volume mounts the Workload API rather than exposing a hostPath. The Secret is read-only and the container filesystem is read-only. This example uses a static mounted token. A refresh installation additionally needs one private, durable, daemon-writable state volume and serialization ownership, not a shared read-only Secret.

Register separate SPIFFE IDs for the gateway and each authorized caller. Selectors must be based on trusted attestation, including the intended namespace and service account, with the actual agent/cluster parent identity and any needed container constraints. `k8s:ns` and `k8s:sa` are attestor selectors, not caller labels. Do not grant unrelated users permission to create workloads under an authorized service account. A mutable pod label is not sufficient authority by itself. Node/root compromise remains inside the SPIRE trust boundary.

The gateway Service does not make arbitrary callers authorized. Callers require their own SVID and a gateway principal mapping. Do not replace mTLS with an identity HTTP header. The TCP readiness probe proves listener availability only. It is not proof of provider credentials, grant access, or complete end-to-end health.

Run cluster commands only after authorization and explicit context discovery through `kubie list --json`, then `kubie exec -e CONTEXT pdp ...`. Do not mutate the global kube context. Creating credentials, ConfigMaps, registrations and deployments is deliberately not executed in this task. For multiple replicas, each accepted policy revision must be acknowledged or stale replicas removed from service before claiming revocation.

Primary references:

- <https://github.com/spiffe/spiffe-csi>
- <https://github.com/spiffe/spire/blob/main/doc/plugin_agent_workloadattestor_k8s.md>

## Later Jobshop integration

No Jobshop configuration changes are included. A future integration must expose only the gateway socket or mTLS endpoint to a sandbox, never provider secrets or OAuth state. A Unix integration needs verified distinct UIDs and socket-group access. A SPIFFE integration needs narrowly selected Workload API access and registered workload identities. Do not claim session isolation from PID, systemd unit names, cgroups or environment labels until the attestor actually verifies those selectors. Confirm the sandbox can reach the intended gateway and that an unmapped neighboring sandbox cannot. Keep daemon and SPIRE resource measurements separate.
