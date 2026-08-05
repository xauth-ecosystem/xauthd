FROM rust:1.94-slim AS builder

WORKDIR /usr/src/xauthd
COPY . .

# Install dependencies if needed (e.g. for SQLite/OpenSSL)
RUN apt-get update && apt-get install -y pkg-config libssl-dev protobuf-compiler

# Build the release binary
RUN cargo build --release

# Create a minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/src/xauthd/target/release/xauth-core /app/xauth-core
COPY --from=builder /usr/src/xauthd/xauthd.example.toml /app/xauthd.toml

EXPOSE 50051 8080

CMD ["./xauth-core", "start"]
