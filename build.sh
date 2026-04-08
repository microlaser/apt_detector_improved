#!/bin/bash
# build.sh — macOS APT Detector v12.0
set -e

BINARY="macos_apt_detector_v12"
SOURCE="macos_apt_detector_v12.c"

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

if [ $? -eq 0 ]; then
    chmod +x "${BINARY}"
    echo "[+] Build complete."
    echo "[+] Run with: sudo ./${BINARY}"
fi
