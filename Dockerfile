FROM rust:1.93-slim AS builder
WORKDIR /build
COPY . .
ARG BUILD_PROFILE=release

RUN apt update && apt install -y make libssl-dev pkg-config libpq-dev \
    && cargo build --profile $BUILD_PROFILE --locked \
    && cp /build/target/$BUILD_PROFILE/bridge-api /build/bridge-api

FROM ubuntu:22.04 AS run
WORKDIR /app

COPY --from=builder /build/bridge-api /usr/local/bin

RUN adduser --disabled-password --gecos "" --no-create-home --uid 1000 bridge \
    && apt-get update && apt-get install -y ca-certificates libpq-dev \
    && apt clean \
    && chown -R bridge:bridge /usr/local/bin/bridge-api

USER bridge

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/bridge-api"]
