#!/bin/bash
set -euo pipefail
export NODE_OPTIONS="--max-old-space-size=8192"

# Build the pinned frontend for the upstream GoReleaser hook.
cd "$(dirname "$0")/.."
version="${1:?Release version required}"
cd assets
pnpm install --frozen-lockfile --ignore-scripts
pnpm version "$version" --no-git-tag-version --allow-same-version
pnpm run build

cd ..
zip -r - assets/build > application/statics/assets.zip.pending
mv application/statics/assets.zip.pending application/statics/assets.zip
