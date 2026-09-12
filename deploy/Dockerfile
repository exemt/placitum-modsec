# Контекст сборки -- корень инспектора, не корень платформы: модуль Go
# самостоятелен и ничего оттуда не берёт. Отсюда же сборка прямо из git.
#
#     docker build -f deploy/Dockerfile -t placitum/modsec .
#     docker buildx build -f deploy/Dockerfile -t placitum/modsec \
#         "https://github.com/exemt/placitum-modsec.git#develop"

FROM golang:1.25-alpine AS build

WORKDIR /src

# Прокси модулей -- аргументом: в изолированном контуре подставляют своё зеркало.
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

# Зависимости отдельным слоем: они меняются на порядок реже кода, а тянуть CRS и
# Coraza заново на каждую правку правила -- минута на ровном месте.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

# CGO не нужен: Coraza -- чистый Go, включая движок регулярных выражений (RE2).
# Отсюда и статический бинарник, и возможность собрать образ без libc.
ENV CGO_ENABLED=0

# Профили из образа обязаны компилироваться: опечатка в SecLang иначе ловится
# только стартом контейнера, потому что движок собирает набор целиком.
COPY profiles ./profiles

# Тесты целиком. Сверки с платформой здесь пропускаются сами: схема провода
# (docs/messages/inspector.schema.json) и канон профилей лежат в платформе, а
# не в контексте сборки, и тесты, которые их ищут, отвечают Skip, а не Fail.
RUN go test ./...

RUN go build -trimpath -ldflags="-s -w" -o /out/modsec ./cmd/modsec && \
    go build -trimpath -ldflags="-s -w" -o /out/modsec-probe ./cmd/probe

FROM alpine:3.22

# Версия и ревизия приходят снаружи: .git в контекст сборки не попадает.
ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="placitum/modsec" \
      org.opencontainers.image.description="Placitum modsec inspector: OWASP CRS on Coraza, request and response phases" \
      org.opencontainers.image.source="https://github.com/exemt/placitum-modsec" \
      org.opencontainers.image.licenses="LicenseRef-Placitum" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

# Правила CRS встроены в бинарник (coraza-coreruleset), с диска читаются только
# профили: то, что отличает эту установку от поставки.
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

# Проба идёт тем же путём, что и реальная инспекция: вердикт в ответ означает,
# что живы соединение с шиной, подписка, набор правил и пул воркеров. TCP-пинг до
# NATS не сказал бы ни про одно из этого.
#
# start-period с запасом: набор правил CRS компилируется при старте, и до конца
# компиляции подписки нет.
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
    CMD ["modsec-probe", "--quiet", "--timeout", "1s", "--uri", "/healthcheck"]

CMD ["modsec"]
