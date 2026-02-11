#!/bin/bash
set -ex

EVERPARSE_TAG="v2026.02.04"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EVERPARSE_DIR="$SCRIPT_DIR/../.patched/everparse"

if [ -d "$EVERPARSE_DIR" ]; then
    echo "Directory $EVERPARSE_DIR already exists, checking out $EVERPARSE_TAG"
    cd "$EVERPARSE_DIR"
    git fetch --tags
    git checkout "$EVERPARSE_TAG"
else
    git clone --depth 1 --branch "$EVERPARSE_TAG" \
        https://github.com/project-everest/everparse \
        "$EVERPARSE_DIR"
fi
