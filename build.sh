#!/bin/bash
# build.sh — macOS APT Detector v11.0
set -e

BINARY="macos_apt_detector_v11"
SOURCE="macos_apt_detector_v11.c"

echo "[*] Building ${BINARY}..."

clang \
    -o "${BINARY}" \
    "${SOURCE}" \
    -framework Security \
    -framework CoreFoundation \
    -framework CoreGraphics \
    -I. -O3

if [ $? -eq 0 ]; then
    chmod +x "${BINARY}"
    echo "[+] Build complete: sudo ./${BINARY}"
fi
