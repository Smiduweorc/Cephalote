#!/usr/bin/env bash
#
# release.sh — cut a new release for Cephalote.
#
# Flow:
#   1. sanity-check the working tree and branch
#   2. run the full test suite
#   3. regenerate CHANGELOG.md with git-cliff (including the new tag)
#   4. commit the changelog as `chore(release): prepare for <version>`
#   5. create an annotated git tag
#   6. optionally push branch + tag, which triggers the GoReleaser workflow
#
# Usage:
#   scripts/release.sh v1.2.3      # explicit version
#   scripts/release.sh patch       # bump patch from the latest tag
#   scripts/release.sh minor
#   scripts/release.sh major
#
# Env:
#   PUSH=1            push the branch and tag when done (default: 0, dry local)
#   RELEASE_BRANCH    branch releases must be cut from (default: master)
set -euo pipefail

RELEASE_BRANCH="${RELEASE_BRANCH:-master}"
PUSH="${PUSH:-0}"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v git-cliff >/dev/null 2>&1 || die "git-cliff not found (run 'npm install')"

arg="${1:-}"
[ -n "$arg" ] || die "usage: scripts/release.sh <version|major|minor|patch>"

# Resolve the target version.
latest="$(git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0)"
case "$arg" in
  major|minor|patch)
    ver="${latest#v}"
    IFS='.' read -r major minor patch <<<"$ver"
    case "$arg" in
      major) major=$((major + 1)); minor=0; patch=0 ;;
      minor) minor=$((minor + 1)); patch=0 ;;
      patch) patch=$((patch + 1)) ;;
    esac
    version="v${major}.${minor}.${patch}"
    ;;
  v[0-9]*)
    version="$arg"
    ;;
  *)
    die "version must be vX.Y.Z or one of: major, minor, patch"
    ;;
esac

echo "==> Releasing $version (previous: $latest)"

# Sanity checks.
branch="$(git rev-parse --abbrev-ref HEAD)"
[ "$branch" = "$RELEASE_BRANCH" ] || die "must release from '$RELEASE_BRANCH' (on '$branch')"
[ -z "$(git status --porcelain)" ] || die "working tree is dirty; commit or stash first"
git rev-parse "$version" >/dev/null 2>&1 && die "tag $version already exists"

# Tests.
echo "==> Running tests"
go test -race ./...

# Changelog for the upcoming tag.
echo "==> Updating CHANGELOG.md"
git-cliff --tag "$version" -o CHANGELOG.md
git add CHANGELOG.md
git commit -m "chore(release): prepare for $version"

# Annotated tag.
echo "==> Tagging $version"
git tag -a "$version" -m "$version"

if [ "$PUSH" = "1" ]; then
  echo "==> Pushing $branch and $version"
  git push origin "$branch"
  git push origin "$version"
  echo "==> Done. GoReleaser will run from the tag push."
else
  echo "==> Done (local only). Review, then push with:"
  echo "      git push origin $branch && git push origin $version"
fi
