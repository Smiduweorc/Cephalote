# Cephalote

![logo](./assets/logo.png)

Cephalote scans a source tree for weak and broken cryptography (MD5, DES, RC4,
undersized RSA keys, hardcoded keys, and so on) and tells you where it found
them. It's a single static binary with no runtime dependencies, meant to drop
onto a server or into CI without fuss.

## Install

```sh
# Go toolchain
go install github.com/Smiduweorc/Cephalote/cmd/cephalote@latest

# Released binary (Linux/macOS, amd64/arm64)
curl -sSfL https://raw.githubusercontent.com/Smiduweorc/Cephalote/main/install.sh | sh

# Container (scratch image, ~static binary)
docker run --rm -v "$PWD:/src:ro" ghcr.io/smiduweorc/cephalote scan /src
```

`.deb`/`.rpm` packages and checksummed archives are attached to each
[GitHub Release](https://github.com/Smiduweorc/Cephalote/releases). Or build
locally with `make build` (static, zero-cgo).

To run Cephalote continuously (on an interval or as a managed daemon) see
[docs/SCHEDULING.md](docs/SCHEDULING.md) for copy-pasteable Docker, Compose,
Kubernetes `CronJob`, and systemd examples.

## Usage

```sh
cephalote scan <dir> [flags]

  --format {text|json|sarif}   output format (default: text)
  --exit-code                  exit non-zero (1) when findings are present (CI gate)
  --include-unknown            run the regex fallback on unrecognized languages
  --min-confidence {low|high}  minimum confidence to report (default: low)
  --scheme <names|classes>     search for specific algorithms (see below)
  --config <file>              YAML config: excludes, overrides, custom schemes

cephalote schemes              list the algorithm catalog
```

Examples:

```sh
# Human-readable scan of the current tree
cephalote scan .

# SARIF for GitHub/GitLab code scanning, only high-confidence findings
cephalote scan . --format sarif --min-confidence high > results.sarif

# Gate a CI pipeline on any findings
cephalote scan . --exit-code
```

### Searching for specific algorithms

Beyond the default weak-crypto scan, `--scheme` turns Cephalote into a
crypto-aware search, useful for inventory and migration (e.g. "where do we
still use SHA-256?"). It accepts canonical names, aliases, or class selectors,
and reports matches of *any* strength, tagged with their security class.

```sh
cephalote schemes                          # list every known algorithm + class
cephalote scan . --scheme sha256           # find a specific algorithm
cephalote scan . --scheme sha-256,des3     # aliases + multiple, comma-separated
cephalote scan . --scheme weak             # all broken+weak schemes (broad net)
cephalote scan . --scheme all              # full crypto inventory
```

Class selectors: `all`, `weak` (broken+weak), `broken`, `legacy`, `contextual`,
`strong`. Search matches are regex-based and therefore low confidence.

## How it works

Cephalote detects the language of each file, then hands it to the most precise
analyzer it has for that language:

| Analyzer | Languages | Availability | Confidence |
|----------|-----------|--------------|------------|
| Go `go/ast` | Go | built-in | `high` |
| Tree-sitter | Python | `treesitter` build | `high` |
| Regex over the scheme catalog | everything else | built-in | `low` |

The Go analyzer reads the actual syntax tree, so it is import-aware and looks at
values and structure: it flags `rsa.GenerateKey(rand.Reader, 1024)` but not
`4096`, follows renamed imports, and spots hardcoded keys and static or zero
IVs. The regex analyzer scans every other language line by line against the
[algorithm catalog](internal/scheme/scheme.go), which is why those matches are
reported at low confidence.

### Build profiles (Tree-sitter)

Tree-sitter grammars require cgo, which pulls against the goal of shipping a
single static `CGO_ENABLED=0` binary. There are two build profiles to cover
both cases:

- **Default** (`make build`, `go install`): pure-Go, fully static. There is no
  Tree-sitter analyzer, so Python, JavaScript, and the rest fall back to the
  regex scan.
- **Tree-sitter** (`make build-treesitter`, i.e. `CGO_ENABLED=1 go build -tags
  treesitter`): adds real Python AST analysis at high confidence, at the cost of
  cgo. More grammars plug in behind the same entry point.

```sh
# High-confidence Python analysis
CGO_ENABLED=1 go build -tags treesitter -o cephalote-ts ./cmd/cephalote
```

### Configuration & suppression

A YAML config (`--config`) adds excludes, rule overrides, and project-specific
detections, see [`cephalote.example.yaml`](cephalote.example.yaml):

```yaml
exclude: ["testdata/**", "**/*.min.js"]
rules:
  disable: [weak-hash-sha1, "scheme:cbc"]
  severity: { insecure-random: low }
custom_schemes:
  - id: internal-xor
    class: broken
    pattern: "(?i)\\bxor_encrypt\\b"
    remediation: "Use a vetted AEAD cipher."
```

Individual findings can be silenced inline (any language) with a comment:

```go
h := md5.New() // cephalote:ignore weak-hash-md5
secret := sha1.Sum(x) // cephalote:ignore       (bare form silences the line)
```

### Detections

Go (high confidence): weak hashes (MD5, SHA-1, MD4), weak/broken ciphers
(DES, 3DES, RC4, Blowfish), undersized RSA keys (<2048), insecure randomness
(`math/rand`), deprecated TLS versions, hardcoded keys, and static/zero IVs.

Every other language (low confidence): the full
[scheme catalog](internal/scheme/scheme.go): 50+ algorithms spanning hashes,
ciphers, modes, asymmetric schemes, KDFs, RNGs, and TLS versions. Run
`cephalote schemes` to list them.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (no findings, or findings without `--exit-code`) |
| 1 | `--exit-code` set and findings were present |
| 2 | Operational error (bad flag, unreadable path, etc.) |

## Development

```sh
make build             # static, zero-cgo binary
make build-treesitter  # cgo binary with the Tree-sitter analyzer
make test              # race + coverage (default profile)
make test-all          # both profiles
make fmt vet           # formatting + go vet
make snapshot          # local goreleaser build (no publish)
make help              # list all targets
```

CI runs gofmt, vet, race tests with coverage, and static cross-compilation for
`linux/amd64` + `linux/arm64` (Go 1.25/1.26), plus separate jobs for the
Tree-sitter profile, a GoReleaser config check, and `govulncheck`, on every
push and PR. Tagging `vX.Y.Z` triggers a GoReleaser release (binaries,
checksums, `.deb`/`.rpm`).
