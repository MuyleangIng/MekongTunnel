#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/release-cli.sh <tag> [--publish] [--remote <name>]

Builds Mekong CLI release assets exactly like the GitHub release workflow:
- 6 cross-compiled CLI binaries
- SHA256SUMS-<tag>.txt
- release-notes.md extracted from CHANGELOG.md

Options:
  --publish         create annotated git tag and push only that tag
  --remote <name>   git remote for tag push (default: origin)
EOF
}

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 1
fi

tag="$1"
shift

publish=0
remote="origin"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --publish)
      publish=1
      shift
      ;;
    --remote)
      [[ $# -ge 2 ]] || { echo "missing value for --remote" >&2; exit 1; }
      remote="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

case "$tag" in
  v*.*.*) ;;
  *)
    echo "tag must look like v1.5.7" >&2
    exit 1
    ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="${repo_root}/dist/${tag}"

cd "$repo_root"

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "tracked changes are not committed; commit the release content before building/publishing ${tag}" >&2
  exit 1
fi

if ! bash scripts/extract_changelog_section.sh "$tag" CHANGELOG.md >/dev/null 2>&1; then
  echo "CHANGELOG.md does not have a section for ${tag}" >&2
  exit 1
fi

mkdir -p "$out_dir"

ldflags="-s -w -X main.version=${tag}"

echo "▶ Building CLI release assets for ${tag} ..."
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="${ldflags}" -trimpath -o "${out_dir}/mekong-darwin-amd64" ./cmd/mekong
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="${ldflags}" -trimpath -o "${out_dir}/mekong-darwin-arm64" ./cmd/mekong
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="${ldflags}" -trimpath -o "${out_dir}/mekong-linux-amd64" ./cmd/mekong
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="${ldflags}" -trimpath -o "${out_dir}/mekong-linux-arm64" ./cmd/mekong
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="${ldflags}" -trimpath -o "${out_dir}/mekong-windows-amd64.exe" ./cmd/mekong
CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -ldflags="${ldflags}" -trimpath -o "${out_dir}/mekong-windows-arm64.exe" ./cmd/mekong

checksum_write() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}

checksum_verify() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$1"
  else
    shasum -a 256 -c "$1"
  fi
}

(
  cd "$out_dir"
  checksum_write mekong-* > "SHA256SUMS-${tag}.txt"
)

if [[ "$(wc -l < "${out_dir}/SHA256SUMS-${tag}.txt" | tr -d ' ')" != "6" ]]; then
  echo "expected 6 checksums in SHA256SUMS-${tag}.txt" >&2
  exit 1
fi

echo "▶ Verifying checksum file ..."
(
  cd "$out_dir"
  checksum_verify "SHA256SUMS-${tag}.txt"
)

echo "▶ Building release notes from CHANGELOG.md ..."
bash scripts/extract_changelog_section.sh "$tag" CHANGELOG.md > "${out_dir}/release-notes.md"
{
  echo
  echo "## Release Assets"
  echo
  echo "| Asset | SHA-256 |"
  echo "| --- | --- |"
  while read -r sum file; do
    asset="$(basename "$file")"
    echo "| \`${asset}\` | \`${sum}\` |"
  done < "${out_dir}/SHA256SUMS-${tag}.txt"
} >> "${out_dir}/release-notes.md"

echo "✓ Assets ready in ${out_dir}"
echo "✓ Checksum file: ${out_dir}/SHA256SUMS-${tag}.txt"
echo "✓ Release notes: ${out_dir}/release-notes.md"

if [[ "$publish" -ne 1 ]]; then
  exit 0
fi

echo "▶ Publishing tag ${tag} to ${remote} ..."
if git rev-parse "${tag}^{tag}" >/dev/null 2>&1 || git rev-parse "${tag}^{commit}" >/dev/null 2>&1; then
  echo "local tag ${tag} already exists" >&2
  exit 1
fi

if git ls-remote --exit-code --tags "$remote" "$tag" >/dev/null 2>&1; then
  echo "remote tag ${tag} already exists on ${remote}" >&2
  exit 1
fi

git tag -a "$tag" -m "release: ${tag}"
git push "$remote" "$tag"

echo "✅ Tag pushed: ${tag}"
echo "   GitHub Actions release.yml can now build the same assets and create the GitHub release."
echo "   Local verified assets remain in ${out_dir}"
