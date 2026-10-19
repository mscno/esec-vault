# Builds the esec vault server with Litestream for continuous SQLite backup.
# Build from the repository root:
#   docker build -f deploy/Dockerfile -t esec-vault-server .
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/esec-vault-server ./cmd/esec-vault-server

FROM litestream/litestream:0.5.17 AS litestream

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -H -u 10001 esec \
 && mkdir -p /data && chown esec /data
COPY --from=build /out/esec-vault-server /usr/local/bin/esec-vault-server
COPY --from=litestream /usr/local/bin/litestream /usr/local/bin/litestream
COPY deploy/litestream.yml /etc/litestream.yml
COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY deploy/server.toml /etc/esec-vault/server.toml
USER esec
ENV ESEC_SERVER_CONFIG=/etc/esec-vault/server.toml
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
