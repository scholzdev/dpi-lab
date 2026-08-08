# Multi-stage: build with the full Rust toolchain, ship just the binary +
# config defaults. Linux-only concern either way - --inline (NFQUEUE) is
# Linux-native, and this is the first environment this session's Linux-only
# code (inline.rs, Ipv6RstSender/Ipv6DnsSender) actually gets to compile at
# all (built on macOS all session, no Linux toolchain available there).
FROM rust:1-slim-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY ui ./ui
RUN cargo build --release

# nftables is only needed for --inline (inline.rs shells out to `nft`,
# same as lockdown.rs/throttle.rs shell out to pfctl/dnctl on macOS) -
# harmless to have installed and unused in passive mode. No libpcap: pnet's
# pcap backend is an opt-in Cargo feature this project doesn't enable, the
# default Linux backend is raw AF_PACKET sockets.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends nftables && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /build/target/release/dpi-lab /app/dpi-lab
COPY --from=build /build/target/release/dpi-lab-ui /app/dpi-lab-ui
COPY config ./config
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

# No USER drop to non-root: raw sockets, NFQUEUE, and nftables all need root
# or capabilities that don't survive a non-root user cleanly here - same
# trust model as running this natively with sudo. See README.md's Docker
# section for the capability flags this expects at `docker run` time.
ENTRYPOINT ["/app/docker-entrypoint.sh"]
