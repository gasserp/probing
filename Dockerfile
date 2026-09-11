FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/probing-agent ./cmd/probing-agent \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/probing-file-adapter ./cmd/probing-file-adapter \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/probing-uploader ./cmd/probing-uploader

FROM gcr.io/distroless/static-debian12:nonroot AS probing-uploader
COPY --from=build /out/probing-uploader /usr/local/bin/probing-uploader
ENTRYPOINT ["/usr/local/bin/probing-uploader"]

FROM gcr.io/distroless/static-debian12:nonroot AS probing-collector
COPY --from=build /out/probing-agent /usr/local/bin/probing-agent
COPY --from=build /out/probing-file-adapter /usr/local/bin/probing-file-adapter
ENTRYPOINT ["/usr/local/bin/probing-agent"]
