FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/probing-agent ./cmd/probing-agent \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/probing-file-adapter ./cmd/probing-file-adapter \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/probing-uploader ./cmd/probing-uploader \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/probing-journal-adapter ./cmd/probing-journal-adapter

FROM gcr.io/distroless/static-debian12:nonroot AS probing-uploader
COPY --from=build /out/probing-uploader /usr/local/bin/probing-uploader
ENTRYPOINT ["/usr/local/bin/probing-uploader"]

FROM gcr.io/distroless/static-debian12:nonroot AS probing-file-adapter
COPY --from=build /out/probing-file-adapter /usr/local/bin/probing-file-adapter
ENTRYPOINT ["/usr/local/bin/probing-file-adapter"]

# The journal adapter shells out to journalctl, so it needs systemd's reader
# rather than a distroless base. Trixie's journalctl reads journal files
# written by older hosts (bookworm) as well as current ones.
FROM debian:trixie-slim AS probing-journal-adapter
RUN apt-get update \
    && apt-get install -y --no-install-recommends systemd \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/probing-journal-adapter /usr/local/bin/probing-journal-adapter
ENTRYPOINT ["/usr/local/bin/probing-journal-adapter"]

FROM gcr.io/distroless/static-debian12:nonroot AS probing-collector
COPY --from=build /out/probing-agent /usr/local/bin/probing-agent
ENTRYPOINT ["/usr/local/bin/probing-agent"]
