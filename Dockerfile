# ============================================================
#  MekongTunnel — Dockerfile
#  Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
#  Open Source by KhmerStack
#
#  Multi-stage build:
#    Stage 1 (builder)  — compiles Go binary with full SDK
#    Stage 2 (runtime)  — scratch image + CA certs + binary only
#
#  Final image: ~6 MB
# ============================================================

# ── Stage 1: Build ──────────────────────────────────────────
FROM golang:1.24-alpine AS builder

WORKDIR /app

# git + ca-certificates needed for go mod download over HTTPS
RUN apk add --no-cache git ca-certificates

# Download dependencies first (cached layer — only re-runs when go.mod/go.sum change)
COPY go.mod go.sum ./
RUN go mod download

# Copy source and compile
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -trimpath \
    -o mekongtunnel \
    ./cmd/mekongtunnel


# ── Stage 2: Runtime ────────────────────────────────────────
# Use scratch (empty base) for the smallest possible image.
# Only what we need: CA certs (for outbound TLS) + the binary.
FROM scratch

# CA certificates let the binary verify TLS when making outbound requests
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the compiled binary
COPY --from=builder /app/mekongtunnel /mekongtunnel

# Ports:
#   22  — SSH tunnel connections  (ssh -t -R 80:localhost:PORT domain.com)
#   80  — HTTP redirect → HTTPS
#   443 — HTTPS TLS termination + reverse proxy
EXPOSE 22 80 443

# Run as nobody (UID 65534) — non-root for security
USER 65534:65534

LABEL maintainer="Ing Muyleang <Ing_Muyleang>" \
      org.opencontainers.image.title="MekongTunnel" \
      org.opencontainers.image.description="Minimal SSH tunnel service — Open Source by KhmerStack" \
      org.opencontainers.image.source="https://github.com/Ing-Muyleang/mekongtunnel"

ENTRYPOINT ["/mekongtunnel"]
