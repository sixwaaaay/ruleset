# syntax=docker/dockerfile:1

# ===================== Stage 1: build the frontend =====================
FROM node:22-alpine AS frontend-build
WORKDIR /app/frontend
# Copy manifests first so npm layer stays cached
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ===================== Stage 2: cross-compile the backend (static musl) =====================
# Per-platform build args:  ZIG_ARCH=x86_64 TARGET_TRIPLE=x86_64-unknown-linux-musl (amd64)
#                           ZIG_ARCH=aarch64 TARGET_TRIPLE=aarch64-unknown-linux-musl (arm64)
FROM rust:1-slim AS backend-build
ARG ZIG_ARCH
ARG TARGET_TRIPLE
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl xz-utils \
    && curl -fsSL "https://ziglang.org/download/0.16.0/zig-${ZIG_ARCH}-linux-0.16.0.tar.xz" -o /tmp/zig.tar.xz \
    && mkdir -p /opt/zig \
    && tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 \
    && rm /tmp/zig.tar.xz \
    && ln -s /opt/zig/zig /usr/local/bin/zig \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-zigbuild
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
RUN rustup target add ${TARGET_TRIPLE} \
    && cargo zigbuild --release --target ${TARGET_TRIPLE} --bin ruleset
# Bundle the frontend output into the image so no mount is needed at runtime
COPY --from=frontend-build /app/frontend/dist ./dist

# ===================== Stage 3: runtime (Alpine) =====================
FROM alpine:3.21 AS runtime
ARG TARGET_TRIPLE
RUN apk add --no-cache ca-certificates \
    && adduser -D -u 10001 ruleset
WORKDIR /app
COPY --chown=ruleset:ruleset --from=backend-build /app/target/${TARGET_TRIPLE}/release/ruleset /usr/local/bin/ruleset
COPY --chown=ruleset:ruleset --from=frontend-build /app/frontend/dist ./dist
RUN mkdir -p /app/data && chown ruleset:ruleset /app/data

ENV BIND_ADDR=0.0.0.0:3500 \
    DATA_FILE=/app/data/rulesets.json \
    FE_DIR=/app/dist

VOLUME ["/app/data"]
USER ruleset
EXPOSE 3500
ENTRYPOINT ["/usr/local/bin/ruleset"]