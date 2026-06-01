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

# Build the whole bifrost workspace from source so local patches in core/,
# framework/, and plugins/ are compiled in. transports/go.mod pins published
# proxy versions of those modules (which predate the patches); the repo-root
# go.work redirects them to the local source, so the workspace must stay on
# (do NOT set GOWORK=off here). go build fetches modules on demand; a
# standalone `go mod download` errors at the workspace root (no main module).
COPY . .
COPY --from=ui-builder /app/out ./transports/bifrost-http/ui

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
