# Pinned to an exact patch release: the Go standard library ships security
# fixes in patch versions, and the module's `toolchain` directive pins the same
# one, so an image rebuild cannot silently pick up an older, vulnerable
# toolchain (independent security assessment, 2026-10-29).
FROM golang:1.27.3-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/iamd ./cmd/iamd

# Distroless static, running as the built-in nonroot user: no shell, no package
# manager, no writable filesystem outside /tmp.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/iamd /iamd
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/iamd"]
