#!/bin/bash
# build.sh — macOS APT Detector v15.0
set -e

BINARY="macos_apt_detector_v15"
SOURCE="macos_apt_detector_v15.c"

echo "[*] Building ${BINARY}..."

clang \
    -o "${BINARY}" \
    "${SOURCE}" \
    -framework Security \
    -framework CoreFoundation \
    -framework CoreGraphics \
    -I. \
    -O2 \
    -Wall \
    -Wextra \
    -Wno-unused-parameter

chmod +x "${BINARY}"
echo "[+] Build complete. Run with: sudo ./${BINARY}"
