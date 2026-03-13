#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <tag> [changelog-file]" >&2
  exit 1
fi

tag="$1"
changelog_file="${2:-CHANGELOG.md}"

if [[ ! -f "$changelog_file" ]]; then
  echo "changelog file not found: $changelog_file" >&2
  exit 1
fi

awk -v tag="$tag" '
  BEGIN {
    in_section = 0
    found = 0
  }

  $0 == "## " tag || $0 ~ "^## " tag " - " {
    in_section = 1
    found = 1
    print
    next
  }

  in_section && /^## / {
    exit
  }

  in_section {
    print
  }

  END {
    if (!found) {
      exit 1
    }
  }
' "$changelog_file"
