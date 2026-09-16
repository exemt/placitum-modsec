FROM golang:1.25-alpine AS build

WORKDIR /src

ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ENV CGO_ENABLED=0

ARG VERSION=dev
ARG REVISION=unknown
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/modsec ./cmd/modsec && \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/modsec-probe ./cmd/probe

FROM alpine:3.22

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="placitum/modsec" \
      org.opencontainers.image.description="Placitum modsec inspector: OWASP CRS on Coraza, request and response phases" \
      org.opencontainers.image.source="https://github.com/exemt/placitum-modsec" \
      org.opencontainers.image.licenses="LicenseRef-Placitum" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

WORKDIR /app

COPY --from=build /out/modsec /out/modsec-probe /usr/local/bin/
COPY profiles ./profiles
COPY status_map.yaml ./status_map.yaml
COPY inspector.conf ./inspector.conf

RUN adduser -D -H -u 10001 modsec && \
    mkdir -p /var/lib/waf/modsec && \
    chown -R modsec:modsec /var/lib/waf
USER modsec

ENV NATS_URL=nats://nats:4222 \
    WAF_MODSEC_SUBJECT=waf.req.modsec \
    WAF_MODSEC_NAME=modsec \
    WAF_MODSEC_PROFILES=/app/profiles \
    WAF_MODSEC_DATA=/var/lib/waf/modsec \
    WAF_MODSEC_STATUS_MAP=/app/status_map.yaml \
    WAF_MODSEC_LOG=info

HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
    CMD ["modsec-probe", "--quiet", "--timeout", "1s", "--uri", "/healthcheck"]

CMD ["modsec"]
