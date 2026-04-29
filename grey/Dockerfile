# Grey — JAM blockchain node
# Multi-stage Docker build: Rust builder + minimal Debian runtime.
#
# Build:  docker build -t grey -f grey/Dockerfile .
# Run:    docker run -p 9000:9000 -p 9933:9933 -v grey-data:/data grey
# Info:   docker run grey --info

# ── Builder stage ────────────────────────────────────────────────────────
FROM rust:1.94-bookworm AS builder

WORKDIR /build

# Copy workspace manifests first for dependency caching
# Build context is the repo root (docker build -f grey/Dockerfile .)
COPY Cargo.toml Cargo.lock ./
COPY grey/ ./grey/
COPY tools/ ./tools/
COPY spec/crypto-ffi/ ./spec/crypto-ffi/

# Build the grey binary in release mode
RUN cargo build --release --locked -p grey \
    && strip target/release/grey

# ── Runtime stage ────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# Build metadata labels (populated by CI or docker build --build-arg)
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.source="https://github.com/jarchain/jar"
LABEL org.opencontainers.image.revision="${GIT_COMMIT}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.title="grey"
LABEL org.opencontainers.image.description="Grey — JAM blockchain node"

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash grey

# Copy binary from builder
COPY --from=builder /build/target/release/grey /usr/local/bin/grey

# Data and config volumes
RUN mkdir -p /data /config && chown grey:grey /data /config
VOLUME ["/data", "/config"]

# Switch to non-root
USER grey
WORKDIR /home/grey

# Ports: P2P, RPC, Metrics
EXPOSE 9000 9933 9615

# Health check via RPC /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:9933/health || exit 1

# Default: run grey with data in /data, listening on all interfaces
ENTRYPOINT ["grey"]
CMD ["--listen-addr", "0.0.0.0", "--db-path", "/data", "--rpc-port", "9933", "--rpc-host", "0.0.0.0", "--rpc-cors"]
