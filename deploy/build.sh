#!/usr/bin/env bash
# Build .spl package for Splunk deployment
# Usage: bash deploy/build.sh [version]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Read version from argument or VERSION file
VERSION="${1:-$(cat "$PROJECT_DIR/VERSION")}"
APP_NAME="splunk_es_ai_rba"
BUILD_DIR="$PROJECT_DIR/build"
STAGE_DIR="$BUILD_DIR/$APP_NAME"

echo "Building $APP_NAME version $VERSION ..."

# Clean previous build
rm -rf "$BUILD_DIR"
mkdir -p "$STAGE_DIR"

# Copy app contents
cp -r "$PROJECT_DIR/default" "$STAGE_DIR/"
cp -r "$PROJECT_DIR/lookups" "$STAGE_DIR/"
cp -r "$PROJECT_DIR/metadata" "$STAGE_DIR/"
if [ -f "$PROJECT_DIR/README.md" ]; then
  cp "$PROJECT_DIR/README.md" "$STAGE_DIR/"
fi

# Patch version in app.conf
sed -i.bak "s/^version = .*/version = $VERSION/" "$STAGE_DIR/default/app.conf"
sed -i.bak "s/^build = .*/build = $(date +%s)/" "$STAGE_DIR/default/app.conf"
rm -f "$STAGE_DIR/default/app.conf.bak"

# Create .spl (tar.gz) package
ARTIFACT="$BUILD_DIR/${APP_NAME}-${VERSION}.spl"
tar -czf "$ARTIFACT" -C "$BUILD_DIR" "$APP_NAME"

# Clean up staging directory
rm -rf "$STAGE_DIR"

echo "Built: $ARTIFACT"
echo "$ARTIFACT"
