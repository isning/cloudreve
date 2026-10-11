#!/bin/bash
set -euo pipefail
export NODE_OPTIONS="--max-old-space-size=8192"

# Keep local releases and GoReleaser on the same verified build path.
cd "$(dirname "$0")/.."
python3 scripts/build-frontend.py --stage all --version "${1:?Release version required}"
