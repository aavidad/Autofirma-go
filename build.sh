#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Diputacion de Granada
# Autor: Alberto Avidad Fernandez (Oficina de Software Libre de la Diputacion de Granada)

set -e

# Directory definitions
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$BASE_DIR/dist"
OUTPUT_ZIP="$BASE_DIR/autofirma-desktop-linux.zip"

echo "Cleaning dist directory..."
rm -rf "$DIST_DIR"
rm -f "$OUTPUT_ZIP"
mkdir -p "$DIST_DIR"

echo "Building Go binary..."
go build -mod=readonly -o "$DIST_DIR/autofirma-desktop" ./cmd/gui

echo "Copying dependencies..."
# Copy signers folder
if [ -d "$BASE_DIR/signers" ]; then
    cp -r "$BASE_DIR/signers" "$DIST_DIR/"
else
    echo "Warning: local 'signers' directory not found. Code assumes it expects it relative to binary."
    echo "Please copy 'signers' from native-host root if it exists elsewhere."
    # Try to find it in common locations just in case (e.g. if script run from wrong place)
    if [ -d "$BASE_DIR/../signers" ]; then
         cp -r "$BASE_DIR/../signers" "$DIST_DIR/"
    fi
fi

# npm install in signers if needed (production deps only)
if [ -d "$DIST_DIR/signers" ]; then
    echo "Installing Node.js dependencies..."
    cd "$DIST_DIR/signers"
    npm install --production
    cd "$BASE_DIR"
fi

echo "Creating Zip package..."
cd "$DIST_DIR"
zip -r "$OUTPUT_ZIP" .

echo "Done!"
echo "Package created at: $OUTPUT_ZIP"
echo "To install: Unzip and run ./autofirma-desktop"
