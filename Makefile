BINARY      := cephalote
PKG         := ./cmd/cephalote
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION)

# Tree-sitter is C, so a binary that has it needs cgo. Linking that statically
# against musl, with zig as the C toolchain, keeps it a single file with no
# runtime dependencies on any Linux.
ZIG_ARCH    := $(subst arm64,aarch64,$(subst amd64,x86_64,$(shell go env GOARCH)))
STATIC_LD   := -linkmode external -extldflags '-static -s'
zigcc        = CC="zig cc -target $(1)-linux-musl" CXX="zig c++ -target $(1)-linux-musl"

.DEFAULT_GOAL := build

## build: static Linux binary with Tree-sitter (needs zig)
.PHONY: build
build:
	CGO_ENABLED=1 $(call zigcc,$(ZIG_ARCH)) go build -trimpath \
		-ldflags "$(LDFLAGS) $(STATIC_LD)" -o $(BINARY) $(PKG)

## build-dev: host-toolchain build with Tree-sitter, dynamically linked
.PHONY: build-dev
build-dev:
	CGO_ENABLED=1 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

## test: run the test suite (race + coverage), Tree-sitter included
.PHONY: test
test:
	CGO_ENABLED=1 go test -race -coverprofile=coverage.out ./...

## test-nocgo: run tests with cgo off, which compiles the Tree-sitter stub
.PHONY: test-nocgo
test-nocgo:
	CGO_ENABLED=0 go test ./...

## test-all: both
.PHONY: test-all
test-all: test test-nocgo

## fmt: format and report non-compliant files
.PHONY: fmt
fmt:
	gofmt -w .
	@test -z "$$(gofmt -l .)" || (echo "unformatted files remain" && exit 1)

## vet: go vet
.PHONY: vet
vet:
	go vet ./...

## cross: static Tree-sitter binaries for the primary server targets (needs zig)
.PHONY: cross
cross:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 $(call zigcc,x86_64) go build -trimpath -ldflags "$(LDFLAGS) $(STATIC_LD)" -o dist/$(BINARY)_linux_amd64 $(PKG)
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 $(call zigcc,aarch64) go build -trimpath -ldflags "$(LDFLAGS) $(STATIC_LD)" -o dist/$(BINARY)_linux_arm64 $(PKG)

## snapshot: build a local goreleaser snapshot (no publish)
.PHONY: snapshot
snapshot:
	goreleaser release --snapshot --clean

## changelog: regenerate CHANGELOG.md from conventional commits (git-cliff)
.PHONY: changelog
changelog:
	git-cliff -o CHANGELOG.md

## release: cut a release (usage: make release V=v1.2.3  or  V=patch|minor|major)
.PHONY: release
release:
	@test -n "$(V)" || (echo "set V=<version|major|minor|patch>, e.g. make release V=patch" && exit 1)
	scripts/release.sh $(V)

## docker: build the scratch container image
.PHONY: docker
docker:
	docker build --build-arg VERSION=$(VERSION) -t cephalote:$(VERSION) .

## clean: remove build artifacts
.PHONY: clean
clean:
	rm -rf $(BINARY) dist coverage.out

## help: list targets
.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
