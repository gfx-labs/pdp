# Deployment

The files under `examples/packs/systemd` and `examples/packs/github-spiffe` are templates. Nothing in this repository creates accounts, copies secrets, installs units, registers SPIFFE identities, issues an interception CA or applies Kubernetes resources. Tests validate the two packs offline and run the Unix transport, socket activation, a local Workload API server, a generated interception CA, a transparent TLS listener and a local DNS server. Separately, the SPIFFE listener and `pdp forward` were run once by hand against a real SPIRE 1.16.0 server and agent as local processes on one machine, with the `unix` workload attestor. See [acceptance.md](acceptance.md#spire-run-on-one-machine). The SPIRE Kubernetes attestor, the SPIFFE CSI driver, a systemd installation, a Kubernetes cluster, cert-manager and trust-manager have not been used.

## What the outer boundary is

Go authenticates and does nothing else with the result:

- **Unix socket.** The kernel peer UID of the connection becomes `input.identity` with `id` `uid:<n>`, `auth_method` `unix` and `uid`.
- **SPIFFE mTLS.** The client certificate is verified against the current Workload API bundle on every request, including reused connections and requests inside an open `CONNECT`. The verified ID becomes `input.identity` with `auth_method` `spiffe` and `spiffe_id`.
- **Transparent listeners.** The source address becomes `input.identity` with `id` `ip:<address>`, `auth_method` `transparent` and `ip`. Nothing else about the caller is known.

PDP does not map these identities to principals and does not hold an allowlist of callers or destinations. Any local UID that can open the socket, any workload in a trusted SPIFFE domain and any address that reaches a transparent listener reaches policy. Default deny in Rego then refuses the ones the policy does not name, with `403`. Earlier versions answered `401` to an unmapped caller. The outer boundary is therefore the socket's file permissions, the trust bundle and the network in front of the transparent listeners. Treat all three as part of the access control, and name exact UIDs, SPIFFE IDs or addresses in `policy.rego`.

PDP only controls traffic sent to it. A workload with a direct route out can bypass it. Block direct egress with a firewall, a network namespace or a Kubernetes `NetworkPolicy` that allows only PDP and DNS.

## Unix isolation

Use a daemon account distinct from every credentialless workload account. Only the daemon account should read mounted provider secrets, writable OAuth token state or the interception CA key. A caller that shares the daemon's UID can usually read those files directly, whatever the policy says. A private socket alone does not separate processes with the same UID. `SO_PEERCRED` supplies the kernel UID, not a unit or session. A UID shared by several sandboxes is one identity and gives no per-session isolation. PID, systemd unit names, cgroups and environment labels are not identities.

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

## Local forwarder for clients without a client certificate

The SPIFFE listener requires a client certificate. Most programs that read `HTTPS_PROXY` (git, the Go toolchain, `gh`, most HTTP libraries) cannot present one to a proxy. `pdp forward` is a process that can. It holds the workload's SVID and gives those programs a plain loopback port.

```sh
pdp forward --listen 127.0.0.1:3128 \
  --workload-api unix:///spiffe-workload-api/spire-agent.sock \
  --gateway pdp.example.svc:8443 \
  --gateway-id spiffe://example.org/ns/x/sa/pdp
```

All four flags are required. There is no configuration file.

- For each accepted connection it opens one TLS 1.3 connection to `--gateway`, presents the current X.509 SVID from the Workload API and accepts the gateway only if its SPIFFE ID equals `--gateway-id`. An SVID rotation applies to the next connection.
- It then copies bytes both ways and reads no HTTP. Absolute-form requests and `CONNECT` reach PDP as the client wrote them, so PDP's policy, interception and audit behave as for any SPIFFE caller. A side that finishes sending is half-closed and still receives the rest.
- `--listen` must be a loopback IP address with a port. Anything else is refused at start. Every process that can connect to the port is forwarded under the workload's SPIFFE ID, and PDP cannot tell them apart.
- At start it waits up to 10 seconds for the Workload API and exits nonzero if no SVID arrives. When ready it prints `{"state": "ready"}`. `SIGINT` and `SIGTERM` close the listener and the open connections.
- A gateway dial and handshake has 10 seconds. On failure the accepted connection is closed and one line goes to stderr. There is no retry and no pool. Successful connections are not logged. PDP's audit log is the record of requests.

Pod shape:

- The **workload container** sets `HTTPS_PROXY=http://127.0.0.1:3128` (and `HTTP_PROXY` if plain HTTP should also go through PDP), and trusts the interception CA root if PDP intercepts `CONNECT`. It does not mount the Workload API socket.
- The **forwarder container** runs the PDP image with `forward` and mounts the Workload API socket, for example from the SPIFFE CSI driver. It needs no configuration, no secrets and no writable filesystem.
- Containers in a pod share the network namespace, so the loopback port is reachable from every container in the pod and from nothing outside it.

Do not mount the Workload API socket into the workload container. With the socket the workload can fetch the SVID and its private key, copy them out and use them from anywhere the gateway is reachable until the SVID expires. Without it, the workload can use the identity only through the forwarder, while the pod runs. The pod's `NetworkPolicy` should allow egress to PDP and DNS only, as for any PDP caller.

`TestForwardPresentsWorkloadSVID` runs the forwarder against a listener built the way `serve` builds it, with a local Workload API server and a generated CA. It checks that a request arrives authenticated as the workload's SPIFFE ID, that a half-closed client gets its response, and that a gateway with another ID is refused before any request is sent. It was also run by hand with real SPIRE on one machine, with curl and `git ls-remote` as the clients. See [acceptance.md](acceptance.md#spire-run-on-one-machine). It has not been run in a pod, with the CSI driver, or with the Go toolchain or `gh` as the client.

A connection through the forwarder ends when the SVID it was opened with expires. PDP answers the next request on it with `401` and closes it, and the client has to reconnect. A new connection uses the renewed SVID.

## Interception CA

An `interception` section is needed for `CONNECT` to anything but a tunnel upstream, and for the transparent HTTPS listener. Absolute-form requests, including `pdp request --url`, do not need it.

- Issue a CA certificate with the certificate-signing key usage. Put it, followed by any intermediates below the root, in `certificate_file`, and its key in `key_file`.
- Make both files readable by the daemon account only. Anyone with the key can impersonate any host the CA permits to every workload that trusts it. Prefer a dedicated CA with name constraints limited to the hosts PDP should intercept, and check that the workloads' TLS libraries enforce name constraints.
- Install the root in the workloads' trust store, or point `SSL_CERT_FILE` or the runtime's equivalent at a bundle that contains it.
- PDP rechecks the files at most once a minute and reloads them when their modification time changes. Replace both files when renewing. A changed path in `interception` needs a restart.

`pdp validate` does not open the CA files. A missing or invalid CA makes `pdp serve` exit at startup.

## DNS steering

For clients that cannot be configured with a proxy, set `transport.transparent` and `dns`. Point the workloads' resolver at `dns.listen`. Only `upstreams` hosts and `dns.intercept` patterns resolve to `dns.address`. Other names are forwarded to `dns.resolver` or refused.

- Binding port 53, 80 or 443 needs the `CAP_NET_BIND_SERVICE` capability or a port above 1024 with a redirect in front. The `systemd` pack does not grant it.
- DNS is UDP only. A client that falls back to TCP for a large answer gets nothing from PDP.
- The transparent listeners identify callers by source address. Run them only on a network where addresses cannot be spoofed by workloads, and name the addresses in policy.
- Whether steering and interception cover every connection a given client makes has not been tested with any real client.

## Kubernetes and service-account attestation

`examples/packs/github-spiffe/deployment.yaml` holds a ServiceAccount, a Deployment and a Service. It requires:

- an existing `pdp` namespace
- installed SPIRE server and agents and the SPIFFE CSI driver
- a `pdp-config` ConfigMap holding `pdp.json`, `policy.rego`, `adapter.star` and `github-rest.json`, because `pdp.json` names all four
- a `pdp-provider-credentials` Secret with the token at the path `pdp.json` names

The manifest has no interception CA, DNS steering or `NetworkPolicy`. For a cluster setup with cert-manager and trust-manager see [forward-proxy.md](forward-proxy.md#kubernetes-and-cert-manager). That setup has not been tried.

Replace the deliberately invalid image with an approved immutable digest. The CSI volume mounts the Workload API without a hostPath. The Secret is read-only and the container filesystem is read-only. The example uses a static mounted token. A refresh installation also needs a private, durable, daemon-writable state volume, not a read-only Secret.

### Image

`containers/pdp/Dockerfile` builds `cmd/pdp` with `CGO_ENABLED=0` and `-trimpath` onto a distroless static base. The image has the public CA roots, no shell, and runs as UID and GID 10001. Both base images are pinned by digest. `scripts/build-image` builds it from a clean checkout and tags it with the first 12 characters of the commit. `.github/workflows/image.yml` pushes `ghcr.io/gfx-labs/pdp:<commit>` from `main` and `p7-deploy` on the `talos-metal-gfx` runners and prints the digest. The image was built locally and the binary copied out and checked. No container was started from it, the workflow has not run, and nothing has been pushed.

### Volumes

PDP writes nothing outside the OAuth state directory and an optional Unix socket, so a read-only root filesystem works. What each kind of file needs:

- **ConfigMap files** (configuration, policy, adapters, schemas) and **Secret files** (static tokens, the interception CA) are symlinks into a versioned directory. PDP follows them. A Secret with `defaultMode: 0440` is readable by a non-root PDP only through the pod's `fsGroup`. A token file that is group or world writable is refused.
- **OAuth state** needs its directory at `0700` and `state.json` at `0600`, on a writable volume. With `fsGroup` set, the kubelet by default adds group read and write to every file and directory of a volume on each mount, and PDP then refuses the state. Set `fsGroupChangePolicy: OnRootMismatch` on the pod and keep the state in a subdirectory of the volume, such as `/var/lib/pdp/<account>/state.json`. The kubelet then changes modes only while the volume root has the wrong group or mode, which is the first mount of an empty volume. Seed the state after that. Whether a given CSI driver applies `fsGroup` at all depends on the driver.
- A **Unix socket** directly in an `emptyDir` is refused. The kubelet creates the directory with mode `0777`, and PDP requires a socket parent that is not group or world writable. PDP does not create a subdirectory itself. The SPIFFE listener does not have this constraint.

The ConfigMap, Secret and state layouts were reproduced with local files against the code that opens them. None was mounted by a kubelet.

Register a SPIFFE ID for the gateway and one for each caller. Selectors must come from trusted attestation, including the intended namespace and service account and the real agent parent. `k8s:ns` and `k8s:sa` are attestor selectors, not caller labels. Do not let unrelated users create workloads under an authorized service account. A mutable pod label is not enough. Node or root compromise is inside the SPIRE trust boundary.

The Service does not authorize callers. A caller needs its own SVID and an entry in `allowed_workloads` in `policy.rego`. Do not replace mTLS with an identity header. The TCP readiness probe shows the listener is up. It says nothing about provider credentials or policy.

Run cluster commands only after authorization, with explicit context discovery through `kubie list --json` and then `kubie exec -e CONTEXT pdp ...`. Do not change the global kube context. For several replicas, each accepted revision must be acknowledged by every replica, or stale replicas removed from service, before claiming revocation.

Primary references:

- <https://github.com/spiffe/spiffe-csi>
- <https://github.com/spiffe/spire/blob/main/doc/plugin_agent_workloadattestor_k8s.md>

## Later Jobshop integration

No Jobshop configuration is included. A future integration should expose only the gateway socket or mTLS endpoint to a sandbox, never provider secrets, OAuth state or the interception CA key. A Unix integration needs verified distinct UIDs and socket-group access. A SPIFFE integration needs narrowly selected Workload API access and registered workload identities. Do not claim session isolation from PID, systemd unit names, cgroups or environment labels until the attestor verifies those selectors. Confirm that the intended sandbox reaches the gateway and that a neighboring sandbox with another identity gets `403`. Measure daemon and SPIRE resource use separately.
