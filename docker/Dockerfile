# syntax=docker/dockerfile:1.7
#
# Kikonnect relay server image.  Build context: the repository root.
#
#   docker build -f docker/Dockerfile -t kikonnect-server .
#   docker buildx build --platform linux/amd64,linux/arm64 -f docker/Dockerfile .
#
# The server speaks QUIC, i.e. it listens on UDP (default 7000/udp).

ARG RUST_VERSION=1

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-bookworm AS build
WORKDIR /src

# 1) Dependency layer: only manifests plus stub sources, so that code changes
#    do not invalidate the (slow) compilation of all dependencies. The whole
#    workspace has to be present for cargo to resolve it, but only the server
#    crate and its dependencies are built.
COPY Cargo.toml Cargo.lock ./
COPY crates/protocol/Cargo.toml    crates/protocol/Cargo.toml
COPY crates/client-core/Cargo.toml crates/client-core/Cargo.toml
COPY crates/client/Cargo.toml      crates/client/Cargo.toml
COPY crates/server/Cargo.toml      crates/server/Cargo.toml
COPY tests/Cargo.toml              tests/Cargo.toml
RUN set -eux; \
    for lib in crates/protocol crates/client-core crates/server tests; do \
        mkdir -p "$lib/src"; : > "$lib/src/lib.rs"; \
    done; \
    mkdir -p crates/client/src crates/server/src; \
    echo 'fn main() {}' > crates/client/src/main.rs; \
    echo 'fn main() {}' > crates/server/src/main.rs
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p kikonnect-server

# 2) Real sources. Touch them so cargo does not mistake the stubs for up to date.
COPY crates/protocol    crates/protocol
COPY crates/server      crates/server
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    set -eux; \
    find crates/protocol/src crates/server/src -name '*.rs' -exec touch {} +; \
    cargo build --release --locked -p kikonnect-server; \
    install -D target/release/kikonnect-server /out/kikonnect-server

# ---------------------------------------------------------------------------
# Runtime stage: distroless (glibc, CA certificates, no shell), non-root user
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=build /out/kikonnect-server /usr/local/bin/kikonnect-server

# All configuration happens through environment variables (see docker/.env.example).
ENV KIKONNECT_LISTEN=0.0.0.0:7000 \
    KIKONNECT_CERT=/certs/fullchain.pem \
    KIKONNECT_KEY=/certs/privkey.pem \
    KIKONNECT_LOG_FORMAT=json

# QUIC runs over UDP, not TCP.
EXPOSE 7000/udp

USER nonroot:nonroot

# Does a local QUIC handshake + Hello against the running server.
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/kikonnect-server", "healthcheck"]

ENTRYPOINT ["kikonnect-server"]
CMD ["serve"]
