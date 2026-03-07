#!/bin/bash
# build.sh — Configure and build the JIT tracer agent for Android arm64
#
# Usage: ./scripts/build.sh
#   Set ANDROID_NDK_HOME before running, or edit the fallback below.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    echo "ERROR: ANDROID_NDK_HOME is not set."
    echo "  export ANDROID_NDK_HOME=/path/to/android-ndk-r26d"
    exit 1
fi

TOOLCHAIN="${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake"
if [ ! -f "$TOOLCHAIN" ]; then
    echo "ERROR: Toolchain file not found: ${TOOLCHAIN}"
    exit 1
fi

echo "[*] Configuring (arm64-v8a, API 34)..."
cmake -B "$BUILD_DIR" -S "$PROJECT_DIR" \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-34 \
    -DANDROID_STL=c++_static

echo "[*] Building..."
cmake --build "$BUILD_DIR"

echo "[+] Built: ${BUILD_DIR}/libart_jit_tracer.so"
