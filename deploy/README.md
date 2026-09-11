# deploy/

Reference files for operators. The reasoning behind them is in
[ARCHITECTURE.md](../docs/ARCHITECTURE.md).

| File | Purpose |
|---|---|
| `jailhub.service` | systemd unit for the hub. `systemctl reload jailhub` is wired to `jailhub serve --takeover`, which replaces the process without dropping nodes |
| `Dockerfile.hub` | Hub container: GraalVM native build on a distroless base, about 30 MB |
| `Dockerfile.node` | Node container, same shape |
| `nginx-stream.conf` | For a server where nginx already owns 443. SNI routing with `ssl_preread`, plus a PROXY header |
| `haproxy.cfg` | The same with HAProxy, using `send-proxy-v2` |
| `homebrew/jailscale.rb` | Formula template for a tap |

Registering the node as a service is a command rather than a file:
`jailscale service install` (launchd on macOS, `systemctl --user` on Linux, a
logon task on Windows).

Behind a proxy, the hub must either listen on loopback with `--proxy-protocol`
or be given `--trusted-proxy <cidr>`. Otherwise anyone could forge a visitor
address, so the hub refuses to start.

Published images:

```
ghcr.io/eth219/jailhub:latest
ghcr.io/eth219/jailscale:latest
```
