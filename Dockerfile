# ======================
# 1) Build stage
# ======================
FROM rust:1.81 AS builder

# Set workdir
WORKDIR /usr/src/trax

# Copy all project files
COPY . .

# Build release binary for an example (aaip_scenario)
RUN cargo build --release --features crypto-ed25519,hash-blake3 --example aaip_scenario

# ======================
# 2) Runtime stage
# ======================
FROM debian:12-slim

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy built binary from builder stage
COPY --from=builder /usr/src/trax/target/release/examples/aaip_scenario /app/aaip_scenario

# Set default command to run scenario
CMD ["./aaip_scenario"]
