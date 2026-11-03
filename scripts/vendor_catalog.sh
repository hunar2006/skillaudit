#!/usr/bin/env bash
# Re-pin the catalog: scripts/vendor_catalog.sh <anthropics/skills commit sha> [skill ...]
set -euo pipefail
sha=${1:?usage: scripts/vendor_catalog.sh <sha> [skill ...]}; shift
skills=("${@:-webapp-testing brand-guidelines web-artifacts-builder}")
read -ra skills <<< "${skills[*]}"
dest="$(cd "$(dirname "$0")/.." && pwd)/skillaudit/catalog"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
git clone -q https://github.com/anthropics/skills.git "$tmp/repo"
git -C "$tmp/repo" checkout -q "$sha"
full=$(git -C "$tmp/repo" rev-parse HEAD)
rm -rf "$dest"; mkdir -p "$dest"
for s in "${skills[@]}"; do cp -r "$tmp/repo/skills/$s" "$dest/"; done
python3 - "$dest" "$full" "${skills[@]}" <<'PY'
import json, sys
dest, sha, *skills = sys.argv[1:]
json.dump({"repo": "https://github.com/anthropics/skills", "sha": sha, "skills": skills},
          open(f"{dest}/manifest.json", "w"), indent=2)
PY
echo "catalog pinned to $full: ${skills[*]}"
