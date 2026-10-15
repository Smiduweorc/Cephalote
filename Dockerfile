# Build the static binary: cgo for Tree-sitter, linked statically against
# Alpine's musl so it still runs from scratch.
FROM golang:1.27-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=1 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -linkmode external -extldflags -static" \
      -o /out/cephalote ./cmd/cephalote \
 && /out/cephalote --version | grep -q '(tree-sitter)'

# Minimal runtime image: just the static binary.
FROM scratch
COPY --from=build /out/cephalote /cephalote
# Source trees are mounted at /src and scanned read-only.
WORKDIR /src
ENTRYPOINT ["/cephalote"]
CMD ["--help"]
