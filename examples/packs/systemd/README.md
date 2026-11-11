# systemd

The [minimal](../minimal/README.md) policy, run as a socket-activated systemd service with the token supplied as a systemd credential. Callers send absolute-form requests, such as `pdp request --url https://api.github.com/repos/OWNER/REPOSITORY`, to the socket.

- `pdp.socket` creates `/run/pdp/pdp.sock` owned by `pdp`, group `pdp-clients`, mode `0660`.
- `pdp.service` runs as the `pdp` account, loads `/etc/pdp/secrets/github-token` as the credential `github-token`, and reloads on `systemctl reload`.

## Edit

- `policy.rego`: `allowed_uids`.
- Create the `pdp` account and the `pdp-clients` group. Add calling accounts to `pdp-clients`.
- Install `pdp.json`, `policy.rego` and `adapter.star` in `/etc/pdp`, owned by root.
- Put the token in `/etc/pdp/secrets/github-token`, readable by root only. systemd passes it to the service.

## Check

```sh
CREDENTIALS_DIRECTORY=/run/credentials/pdp.service \
  bin/pdp validate --config examples/packs/systemd/pdp.json
```

The variable only tells validation where the credential would be. No secret is read.

## Install

Installing units needs root and is not done by anything in this repository:

```sh
install -m 0644 examples/packs/systemd/pdp.service examples/packs/systemd/pdp.socket /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now pdp.socket
```

After changing `policy.rego`, set a new `revision` in `pdp.json` and run `systemctl reload pdp.service`.

## Status

Validated offline only. The units have not been installed as part of testing. Socket activation itself is covered by a test that passes an inherited socket to the real CLI. The units do not grant `CAP_NET_BIND_SERVICE`, so this pack cannot serve the transparent listeners or DNS on ports below 1024 as shipped.
