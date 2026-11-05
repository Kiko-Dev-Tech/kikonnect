# Kikonnect

LAN games over the internet **without port forwarding**.

Components:
- Relay server (Your Server, runs in Docker)
- Player App (The host and players need this)

One player (the **host**) shares a locally running game server (e.g. Minecraft on
`localhost:25565`). Friends (the **players**) run the same app, enter the host's name and connect
their game to `localhost`. Both sides only make *outbound* connections to a small relay server, so
NAT and firewalls are not a problem.

```
Game client → Player app (localhost) → Relay server → Host app → Game server (localhost)
```

TCP games (Minecraft Java) and UDP games (Minecraft Bedrock, 19132) are supported.

## Using the client

Download `kikonnect-client` for your OS from the
[CI artifacts / releases](https://github.com/kiko-dev-tech/kikonnect/actions) or build it with
`cargo build --release -p kikonnect-client`.

1. **Settings** – enter the relay server address (default `tunnel.example.com:7000`). The
   insecure-certificate option is for development servers only. Settings are stored in your OS
   config directory (`…/kikonnect/config.toml`); passwords are never stored.
2. **Host tab** – choose a name, optionally a password, and list the services to share (label,
   TCP/UDP, local port). *Start* connects to the relay. Once *Online*, tell your friends the
   *Join name*. The list shows connected players. If the connection drops the app reconnects with
   backoff and reclaims the name.
3. **Join tab** – enter the host's name (and password), press *Connect*. For each service the app
   shows where to point your game, e.g. *Connect your game to `localhost:25565`*. If the host's
   port is busy on your machine the next free port is used and shown; you can change the port
   there. Latency to the relay is displayed.
4. The collapsible **Log** panel at the bottom shows the last ~500 log lines.

## Deploying the server with Docker

The server is shipped as a Docker image (`ghcr.io/kiko-dev-tech/kikonnect-server`, `linux/amd64` and
`linux/arm64`). It listens on **UDP** (QUIC), not TCP, and runs as a non-root user.

You need a DNS name for the server and a TLS certificate for it (e.g. from Let's Encrypt).

```sh
docker compose -f docker/docker-compose.yml up -d
docker compose -f docker/docker-compose.yml ps    # STATUS shows (healthy)
```

or without compose:

```sh
docker run -d --name kikonnect --restart unless-stopped \
  -p 7000:7000/udp \
  -v /etc/letsencrypt/live/tunnel.example.com:/certs:ro \
  ghcr.io/kiko-dev-tech/kikonnect-server:latest
```

Open **UDP port 7000** in your firewall. Clients then use `tunnel.example.com:7000`.

- **Configuration** is done through `KIKONNECT_*` environment variables only. the `environment:` block in `docker/docker-compose.yml` (or `docker/.env.example`)
  documents every one of them. Defaults make `docker run` work with just the certificates mounted
  at `/certs/fullchain.pem` and `/certs/privkey.pem`.
- **Certificate renewal:** the server reloads the certificate on `SIGHUP` and whenever the files
  change (checked every 30 s). No restart is needed after a renewal. A failed reload keeps the old
  certificate. With Let's Encrypt, `live/` contains symlinks into `archive/`; mount
  `/etc/letsencrypt` and point `KIKONNECT_CERT`/`KIKONNECT_KEY` at `/certs/live/<domain>/…`.
- **Health check:** `kikonnect-server healthcheck` does a local QUIC handshake and `Hello`
  exchange; the image uses it as `HEALTHCHECK`.
- **Shutdown:** `docker stop` sends `SIGTERM`; the server notifies clients and closes connections.
- **Logs** go to stdout as JSON (`KIKONNECT_LOG_FORMAT=text` for humans).
- **Self-signed certificate inside the container** (local testing). The container user is
  `nonroot` (uid 65532), so the mounted directory must be writable by it:

  ```sh
  mkdir -p certs
  docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/certs:/out" \
    ghcr.io/kiko-dev-tech/kikonnect-server:latest gen-cert --hostname localhost --out /out
  ```

Build the image yourself from the repository root:

```sh
docker build -f docker/Dockerfile -t kikonnect-server .
docker buildx build --platform linux/amd64,linux/arm64 -f docker/Dockerfile .
```

### Releases

CI (`.github/workflows/ci.yml`) runs `cargo fmt --check`, `clippy -D warnings` and all tests on
every push, builds client/server binaries for Linux, Windows and macOS, and builds the multi-arch
image. Pushing a tag `v*` additionally publishes the image to GitHub Container Registry.

## Is this ✨vibecoded✨?

**Yes, but...** I'm a software developer with over 10 years of experience. The idea, the
architecture and the concept are mine; AI was used to write the code in a timely manner.

## Not in v1

Accounts or persistent storage, web dashboard, DNS/subdomains and deep links, multiple relays,
P2P/hole punching, TCP fallback for networks that block UDP, LAN discovery emulation, Minecraft
hostname sniffing.

## Quick start (local development setup)

Requires a stable Rust toolchain.

```sh
# 1. Self-signed certificate (valid for localhost, 127.0.0.1, ::1)
cargo run -p kikonnect-server -- gen-cert --hostname localhost --out ./dev-certs

# 2. Relay server on UDP 7000
cargo run -p kikonnect-server -- serve \
  --listen 127.0.0.1:7000 --cert ./dev-certs/fullchain.pem --key ./dev-certs/privkey.pem

# 3. Two clients (separate terminals; give the second one its own config dir if you like)
cargo run -p kikonnect-client
cargo run -p kikonnect-client
```

In **both** clients, open the **Settings** tab, set the server address to `localhost:7000` and tick
*Allow insecure / self-signed certificates* (development only).

- Client A, **Host** tab: name `kilian`, keep the default service (`Minecraft, TCP, 25565`) and
  press *Start*. Run something on that port, e.g. `python -m http.server 25565`.
- Client B, **Join** tab: host name `kilian`, press *Connect*. Open `http://localhost:25565`
  (or the port shown in the app if 25565 was busy).

Useful for debugging: `KIKONNECT_LOG=debug`.

## Architecture

| Crate | Purpose |
|---|---|
| `crates/protocol` | Shared wire types: control messages, length-prefixed `postcard` framing, name rules, UDP datagram header, constants |
| `crates/client-core` | All client networking (host and join mode), no UI. Fully testable |
| `crates/client` | The egui desktop app, a thin layer over `client-core` |
| `crates/server` | The relay: CLI (`kikonnect-server`) plus a library used by the tests |
| `tests` | End-to-end tests: in-process server + `client-core` |

**Transport.** Every client opens one QUIC connection (`quinn`, TLS 1.3 via `rustls`, ALPN
`kikonnect/1`, keep-alive 10 s, idle timeout 30 s) to the server. The first bidirectional stream is
the *control stream* (`Hello`, `Register`/`Join`, `Ping`, notifications).

- **TCP:** each game connection becomes a new bidirectional QUIC stream: player → server → host,
  and the server pipes the bytes (including half-close).
- **UDP:** packets travel as QUIC datagrams `[service_id u8][session_id u32][payload]`. The server
  rewrites per-player session ids to tunnel-unique ids. Sessions expire after 60 s idle. Packets
  larger than the QUIC datagram limit are dropped and counted (no fragmentation in v1).
- **Names and passwords.** Names match `^[a-z0-9-]{3,32}$`. A name is reserved for 60 s after the
  host disconnects, and the host reclaims it with a `reconnect_secret`. Join passwords are kept in
  memory only, hashed with Argon2. There are no accounts and no database.
- **Safety limits.** Rate limiting of `Register`/`Join` per source IP, and limits for tunnels,
  players per tunnel, streams per connection and UDP sessions per tunnel.

## Development

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The end-to-end tests in `tests/` start a relay in-process with a self-signed certificate and cover
TCP (concurrent connections, 10 MB transfer), UDP sessions, password/name errors, host
disconnects, reconnect within the grace period, version mismatch, health check and certificate
reload.

## License

Kikonnect is **source-available** under the
[PolyForm Noncommercial License 1.0.0](LICENSE). You may use, modify and share it for any
noncommercial purpose (personal use, hobby projects, education, non-profits, ...). **Commercial
use is not permitted** without a separate agreement. Contact the author for commercial licensing.

Note: because of the noncommercial restriction this is not an OSI-approved "open source" license.
Third-party dependencies keep their own (permissive) licenses.
