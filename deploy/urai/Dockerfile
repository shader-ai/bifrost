# Build from the submodule source so all local patches (e.g. passthrough-key
# account changes) are compiled in.  Build context must be the bifrost repo root
# (set in .github/workflows/build-bifrost.yml: context: ./bifrost).

# --- UI Build Stage ---
FROM node:25-alpine3.23 AS ui-builder
WORKDIR /app

RUN apk upgrade --no-cache

COPY ui/package*.json ./
RUN npm ci

COPY ui/ ./
RUN npm run build-enterprise

# --- Go Build Stage ---
FROM golang:1.26.2-alpine3.23 AS builder
WORKDIR /app

RUN apk upgrade --no-cache && \
    apk add --no-cache gcc musl-dev sqlite-dev binutils binutils-gold

ENV CGO_ENABLED=1 GOOS=linux

# Build bifrost-http from local source so the urai patches in core/,
# framework/, and plugins/ are compiled in, instead of the published proxy
# versions pinned in transports/go.mod (which predate the patches).
COPY . .
COPY --from=ui-builder /app/out ./transports/bifrost-http/ui

# The dev go.work is gitignored and excluded by .dockerignore (local-only), so
# recreate an equivalent Go workspace here: core, framework, transports, cli
# and every plugin. go.work.sum is unnecessary -- each module's own go.sum
# covers external dependency checksums; go build fetches them on demand.
RUN go work init && \
    go work use ./core ./framework ./transports ./cli ./plugins/*

ARG VERSION=urai
RUN go build \
    -ldflags="-w -s -X main.Version=v${VERSION} -extldflags '-static'" \
    -a -trimpath \
    -tags "sqlite_static" \
    -o /app/main \
    ./transports/bifrost-http

RUN test -f /app/main || (echo "Build failed" && exit 1)

# --- Runtime Stage ---
FROM alpine:3.23.4
WORKDIR /app

RUN apk upgrade --no-cache && \
    apk add --no-cache musl libgcc ca-certificates wget zlib

COPY --from=builder /app/main .
COPY --from=builder /app/transports/docker-entrypoint.sh .

# Bake in the urai-specific config (no providers declared; all keys are
# supplied per-request via x-bf-provider-key by the URAI backend).
COPY deploy/urai/config.json /app/data/config.json

ARG ARG_APP_PORT=8080
ARG ARG_APP_HOST=0.0.0.0
ARG ARG_LOG_LEVEL=info
ARG ARG_LOG_STYLE=json
ARG ARG_APP_DIR=/app/data

ENV APP_PORT=$ARG_APP_PORT \
    APP_HOST=$ARG_APP_HOST \
    LOG_LEVEL=$ARG_LOG_LEVEL \
    LOG_STYLE=$ARG_LOG_STYLE \
    APP_DIR=$ARG_APP_DIR

ENV GOGC="" \
    GOMEMLIMIT=""

RUN mkdir -p "$ARG_APP_DIR/logs" && \
    adduser -D -s /bin/sh appuser && \
    chown -R appuser:appuser /app && \
    chmod +x /app/docker-entrypoint.sh
USER appuser

VOLUME ["${APP_DIR}"]
EXPOSE $APP_PORT

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 -O /dev/null http://127.0.0.1:${APP_PORT}/health || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["/app/main"]
