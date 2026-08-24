FROM rust:1.80-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/baton-gateway-engine /usr/local/bin/baton-adapter
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /bin/false baton
USER baton
EXPOSE 8080 8082
CMD ["baton-adapter"]
