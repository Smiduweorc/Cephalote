BINARY      := cephalote
PKG         := ./cmd/cephalote
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION)

.DEFAULT_GOAL := build

## build: static, zero-cgo binary (default ship profile)
.PHONY: build
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

## build-treesitter: cgo binary with the tier-2 Tree-sitter analyzer
.PHONY: build-treesitter
build-treesitter:
	CGO_ENABLED=1 go build -tags treesitter -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-ts $(PKG)

## test: run the default test suite (race + coverage)
.PHONY: test
test:
	go test -race -coverprofile=coverage.out ./...

## test-treesitter: run tests with the Tree-sitter tier enabled
.PHONY: test-treesitter
test-treesitter:
	CGO_ENABLED=1 go test -tags treesitter ./...

## test-all: both profiles
.PHONY: test-all
test-all: test test-treesitter

## fmt: format and report non-compliant files
.PHONY: fmt
fmt:
	gofmt -w .
	@test -z "$$(gofmt -l .)" || (echo "unformatted files remain" && exit 1)

## vet: go vet
.PHONY: vet
vet:
	go vet ./...

## cross: static binaries for the primary server targets
.PHONY: cross
cross:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)_linux_amd64 $(PKG)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)_linux_arm64 $(PKG)

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
	rm -rf $(BINARY) $(BINARY)-ts dist coverage.out

## help: list targets
.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
