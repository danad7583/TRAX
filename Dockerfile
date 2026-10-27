FROM rust:1.89-bookworm AS build
WORKDIR /usr/src/trax
COPY . .
RUN cargo build --locked --release --example session

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /usr/src/trax/target/release/examples/session /usr/local/bin/trax-session
ENTRYPOINT ["/usr/local/bin/trax-session"]
