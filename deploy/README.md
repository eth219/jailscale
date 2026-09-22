# deploy/

Reference files for operators. The reasoning behind them is in
[ARCHITECTURE.md](../docs/ARCHITECTURE.md).

| File | Purpose |
|---|---|
| `jailscale.service` | systemd user unit for the node daemon. The node's own answer to "keep it running": `jailscale service install` wrote three of these for three platforms and was removed with the rest of the maintenance cut |
| `jailhub.service` | systemd unit for the hub. Deliberately no `ExecReload`: upgrades are `systemctl restart`, and the nodes' backoff covers the few seconds |
| `Dockerfile.hub` | Hub container: the native binary on a distroless base, about 35 MB. Packaging only -- build the binary first, `./mvnw -DskipTests -Pnative -pl hub -am package` |
| `Dockerfile.node` | Node container, same shape, `-pl node -am` |

On macOS the equivalent of `jailscale.service` is a launchd agent in
`~/Library/LaunchAgents` running the same command with `RunAtLoad` and
`KeepAlive`; on Windows, a logon scheduled task. The command to put in either
is the one the CLI itself spawns: `jailscale daemon --home <dir> --socket <path>`.

The hub takes 443 itself: it no longer reads PROXY headers, so it cannot sit
behind nginx or HAProxy on that port
([ARCHITECTURE.md §8.5](../docs/ARCHITECTURE.md)). The configs that documented
that deployment went with the feature.

## Published images

Built by the `images` workflow for linux/amd64 and linux/arm64, with the same
toolchain and options as the release binaries, so §14's numbers describe them
too:

```
ghcr.io/eth219/jailhub:v0.1.10
ghcr.io/eth219/jailscale:v0.1.10
```

`:vX.Y.Z` pins that release. `:latest` follows releases: it moves when one is
published and its signature has been checked, not when a tag is pushed. `:edge`
follows main. The images tagged `:v0.1.0` are not worth pulling: they were
built before the runtime base carried a libc, so they answer `exec /jailscale:
no such file or directory` instead of starting, and `:latest` pointed at one of
them until v0.1.1.

Both images are distroless and run as a non-root user: the binary, glibc and
zlib, no shell, no package manager, no JVM. That is worth most on the hub,
which holds the wildcard private key and is the one part of this with a public
address. On the node it adds a filesystem boundary around a program that needed
no root to begin with: what reaches the process does not reach your home
directory. macOS and Windows nodes run the binary; these images are Linux only.

## Running the node in a container

The container runs the daemon, and the CLI is `exec`ed into it:

```sh
docker network create demo   # the app joins this too, see below
docker run -d --name jailscale --network demo \
    -v jailscale-state:/var/lib/jailscale ghcr.io/eth219/jailscale:v0.1.10
docker exec jailscale /jailscale up --hub jailscale.sinabro.io
docker exec jailscale /jailscale open 3000 --host myapp --name myapp
```

The one thing to know first: `127.0.0.1` inside a container is the container's
own loopback, and reaching a local service is the node's whole job. There are
two ways out and they are not equally isolated. Put the app on the same
container network and name it with `--host`, as above, which needs no published
port on the app either and keeps both boundaries. Or run the node with
`--network host` and keep `127.0.0.1`, which hands back the network namespace
and leaves only the filesystem one.

The state volume holds the machine key, which is the node's identity: lose it
and you rejoin as a new node.
