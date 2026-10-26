
# -------- Builder stage --------
FROM rust:1.89-slim-bookworm AS builder

# Avoid prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install minimal build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config ca-certificates git && \
    rm -rf /var/lib/apt/lists/*

# Create app dir
WORKDIR /app

# Cache deps first
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples
COPY benches ./benches
COPY vectors ./vectors
COPY README.md .

# Build with features used in runbook
RUN cargo build --locked --release --examples --features crypto-ed25519,hash-blake3

# -------- Runtime stage --------
FROM debian:bookworm-slim AS runtime

# Minimal runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy artifacts
COPY --from=builder /app/target/release /usr/local/bin
COPY --from=builder /app /app

# Default mode and env
ENV MODE=aaip_scenario

# Entry
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
