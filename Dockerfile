FROM rust:1.88 AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY opaque-core ./opaque-core
COPY opaque-ffi ./opaque-ffi
COPY sync-axum-api ./sync-axum-api

WORKDIR /app/sync-axum-api
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/sync-axum-api /usr/local/bin/sync-axum-api

ENV TSUPASSWD_SYNC_BIND=0.0.0.0:8080
EXPOSE 8080

CMD ["sync-axum-api"]