# deploy/

Reference files for operators. The reasoning behind them is in
[ARCHITECTURE.md](../docs/ARCHITECTURE.md).

| File | Purpose |
|---|---|
| `jailhub.service` | systemd unit for the hub. Deliberately no `ExecReload`: `--takeover` needs the old process to stay alive through the hand-off, which `Type=simple` will not do. Upgrades are `systemctl restart` |
| `Dockerfile.hub` | Hub container: the native binary on a distroless base, about 35 MB. Packaging only -- build the binary first, `./mvnw -DskipTests -Pnative -pl hub -am package` |
| `Dockerfile.node` | Node container, same shape, `-pl node -am` |
| `nginx-stream.conf` | For a server where nginx already owns 443. SNI routing with `ssl_preread`, plus a PROXY header |
| `haproxy.cfg` | The same with HAProxy, using `send-proxy-v2` |

Registering the node as a service is a command rather than a file:
`jailscale service install` (launchd on macOS, `systemctl --user` on Linux, a
logon task on Windows).

Behind a proxy, the hub must either listen on loopback with `--proxy-protocol`
or be given `--trusted-proxy <cidr>`. Otherwise anyone could forge a visitor
address, so the hub refuses to start.

Published images, built by the `images` workflow with the same toolchain and options as the
release, so §14's numbers describe them:

```
ghcr.io/eth219/jailhub:latest
ghcr.io/eth219/jailscale:latest
```
