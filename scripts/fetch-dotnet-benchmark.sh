#!/usr/bin/env bash
set -euo pipefail

repo_url="https://github.com/AlexGoOn/the-most-vulnerable-dotnet-app.git"
revision="60d060faf08079887e71a98498fe9a9d623e8ffc"
destination="${1:-benchmarks/the-most-vulnerable-dotnet-app}"

if [[ -e "$destination" ]]; then
  if [[ ! -d "$destination/.git" ]]; then
    echo "refusing to overwrite non-git path: $destination" >&2
    exit 2
  fi
  current="$(git -C "$destination" rev-parse HEAD)"
  if [[ "$current" != "$revision" ]]; then
    echo "refusing mismatched checkout at $destination" >&2
    echo "expected $revision, found $current" >&2
    exit 2
  fi
  echo "$destination already pinned at $revision"
  exit 0
fi

mkdir -p "$(dirname "$destination")"
git clone --filter=blob:none --no-checkout "$repo_url" "$destination"
git -C "$destination" fetch --depth 1 origin "$revision"
git -C "$destination" checkout --detach "$revision"

current="$(git -C "$destination" rev-parse HEAD)"
if [[ "$current" != "$revision" ]]; then
  echo "checkout verification failed: expected $revision, found $current" >&2
  exit 1
fi
echo "$destination pinned at $revision"
