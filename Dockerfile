# Build the fully static binary (default, zero-cgo profile).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/cephalote ./cmd/cephalote

# Minimal runtime image: just the static binary.
FROM scratch
COPY --from=build /out/cephalote /cephalote
# Source trees are mounted at /src and scanned read-only.
WORKDIR /src
ENTRYPOINT ["/cephalote"]
CMD ["--help"]
