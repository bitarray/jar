# Multi-stage build for Grey node
# Stage 1: Build
FROM rust:1.83-bookworm AS builder

WORKDIR /jar

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
COPY grey/Cargo.toml grey/Cargo.toml
COPY grey/crates/grey/Cargo.toml grey/crates/grey/Cargo.toml
COPY grey/crates/grey-rpc/Cargo.toml grey/crates/grey-rpc/Cargo.toml
COPY grey/crates/grey-network/Cargo.toml grey/crates/grey-network/Cargo.toml
COPY grey/crates/grey-consensus/Cargo.toml grey/crates/grey-consensus/Cargo.toml
COPY grey/crates/grey-state/Cargo.toml grey/crates/grey-state/Cargo.toml
COPY grey/crates/grey-store/Cargo.toml grey/crates/grey-store/Cargo.toml
COPY grey/crates/grey-types/Cargo.toml grey/crates/grey-types/Cargo.toml
COPY grey/crates/grey-crypto/Cargo.toml grey/crates/grey-crypto/Cargo.toml
COPY grey/crates/grey-codec/Cargo.toml grey/crates/grey-codec/Cargo.toml
COPY grey/crates/grey-erasure/Cargo.toml grey/crates/grey-erasure/Cargo.toml
COPY grey/crates/grey-merkle/Cargo.toml grey/crates/grey-merkle/Cargo.toml
COPY grey/crates/grey-services/Cargo.toml grey/crates/grey-services/Cargo.toml
COPY grey/crates/grey-transpiler/Cargo.toml grey/crates/grey-transpiler/Cargo.toml
COPY grey/crates/javm/Cargo.toml grey/crates/javm/Cargo.toml

# Create dummy main.rs to cache deps
RUN mkdir -p grey/crates/grey/src && echo "fn main(){}" > grey/crates/grey/src/main.rs
RUN mkdir -p grey/crates/grey-rpc/src && touch grey/crates/grey-rpc/src/lib.rs
RUN mkdir -p grey/crates/grey-network/src && touch grey/crates/grey-network/src/lib.rs
RUN mkdir -p grey/crates/grey-consensus/src && touch grey/crates/grey-consensus/src/lib.rs
RUN mkdir -p grey/crates/grey-state/src && touch grey/crates/grey-state/src/lib.rs
RUN mkdir -p grey/crates/grey-store/src && touch grey/crates/grey-store/src/lib.rs
RUN mkdir -p grey/crates/grey-types/src && touch grey/crates/grey-types/src/lib.rs
RUN mkdir -p grey/crates/grey-crypto/src && touch grey/crates/grey-crypto/src/lib.rs
RUN mkdir -p grey/crates/grey-codec/src && touch grey/crates/grey-codec/src/lib.rs
RUN mkdir -p grey/crates/grey-erasure/src && touch grey/crates/grey-erasure/src/lib.rs
RUN mkdir -p grey/crates/grey-merkle/src && touch grey/crates/grey-merkle/src/lib.rs
RUN mkdir -p grey/crates/grey-services/src && touch grey/crates/grey-services/src/lib.rs
RUN mkdir -p grey/crates/grey-transpiler/src && touch grey/crates/grey-transpiler/src/lib.rs
RUN mkdir -p grey/crates/javm/src && touch grey/crates/javm/src/lib.rs

RUN cargo build --release -p grey 2>/dev/null || true

# Copy actual source
COPY . .

RUN cargo build --release -p grey

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /jar/target/release/grey /usr/local/bin/grey

# P2P, RPC, Metrics
EXPOSE 9000 9933 9615

# Database, Config
VOLUME ["/data", "/config"]

ENTRYPOINT ["grey"]
CMD ["--help"]
