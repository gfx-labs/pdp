# egress

Default-deny egress for named Unix UIDs, with no credentials and no schema. Each rule is a yes or no on host, port, method and protocol. Use this for a destination nobody has written a schema for.

This pack's configuration and explain inputs are YAML, to show the format. The other packs use JSON, and both load the same way.

`pdp.yaml` lists one upstream only because that host is tunnelled. Every other destination a caller asks for still reaches `policy.rego`, which is the only allowlist.

## Edit

- `policy.rego`: `allowed_uids`, `readable_hosts`, `open_hosts` and `tunnels`.
- `pdp.yaml`: `transport.unix_socket`, the `interception` CA paths, and the tunnelled upstream.

## Interception CA

A client that sets `HTTPS_PROXY` sends `CONNECT`. PDP then terminates TLS with a certificate signed by the CA in `interception`, so it can read the method and path. The client must trust that CA or its root. The key lets its holder impersonate any host to those clients, so only the daemon account may read it.

`pdp request` and other clients that send the full `https://` URL in the request line do not need the CA. PDP makes the TLS connection to the destination itself.

The tunnelled upstream is relayed unread. The client sees the real server certificate, and the policy sees only host and port.

## Check

```sh
bin/pdp validate --config examples/packs/egress/pdp.yaml
for input in examples/packs/egress/explain/*.yaml; do
  bin/pdp explain --config examples/packs/egress/pdp.yaml --input "$input"
done
```

| Input | Result |
| --- | --- |
| `read-package.yaml` | allowed, `*.githubusercontent.com` is readable |
| `post-to-read-only-host.yaml` | denied, `pypi.org` is read-only |
| `resolves-to-metadata.yaml` | denied, an allowed name resolved to a link-local address |
| `database-tunnel.yaml` | allowed, the tunnel is listed |

## Serve and call

```sh
bin/pdp serve --config /etc/pdp/pdp.yaml
bin/pdp request --socket /run/pdp/pdp.sock --url https://pypi.org/simple/requests/
```

PDP only controls requests sent to it. Block direct egress from the workload with a firewall or network namespace.
