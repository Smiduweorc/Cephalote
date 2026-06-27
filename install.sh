#!/bin/sh
# Cephalote installer: downloads the latest release binary for this platform.
#
#   curl -sSfL https://raw.githubusercontent.com/Smiduweorc/Cephalote/master/install.sh | sh
#
# Environment:
#   CEPHALOTE_VERSION  release tag to install (default: latest)
#   BINDIR             install directory (default: /usr/local/bin)
set -eu

REPO="Smiduweorc/Cephalote"
BINDIR="${BINDIR:-/usr/local/bin}"
VERSION="${CEPHALOTE_VERSION:-latest}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
case "$os" in
  linux|darwin) ;;
  *) echo "unsupported OS: $os" >&2; exit 1 ;;
esac

if [ "$VERSION" = "latest" ]; then
  VERSION=$(curl -sSfL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | cut -d'"' -f4)
  [ -n "$VERSION" ] || { echo "could not determine latest version" >&2; exit 1; }
fi

num="${VERSION#v}"
tarball="cephalote_${num}_${os}_${arch}.tar.gz"
url="https://github.com/${REPO}/releases/download/${VERSION}/${tarball}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $url"
curl -sSfL "$url" -o "$tmp/c.tar.gz"

# Verify checksum when available.
if curl -sSfL "https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt" -o "$tmp/sums.txt" 2>/dev/null; then
  (cd "$tmp" && grep " ${tarball}\$" sums.txt | sha256sum -c -) || {
    echo "checksum verification failed" >&2; exit 1; }
fi

tar -xzf "$tmp/c.tar.gz" -C "$tmp"
if [ -w "$BINDIR" ]; then
  install -m 0755 "$tmp/cephalote" "$BINDIR/cephalote"
else
  sudo install -m 0755 "$tmp/cephalote" "$BINDIR/cephalote"
fi

echo "Installed cephalote ${VERSION} to ${BINDIR}/cephalote"
