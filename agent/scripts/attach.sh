#!/bin/bash
# attach.sh — Attach the dexbgd agent to a target app
#
# Usage:
#   ./scripts/attach.sh <package_name>              # normal attach (app must be running)
#   ./scripts/attach.sh <package_name> --suspended  # start frozen, attach, wait for resume.sh

set -euo pipefail

TARGET_PKG="${1:-com.test.profiletest}"
AGENT_NAME="libart_jit_tracer.so"

# Derive the agent path from the installed APK location
APK_PATH=$(adb shell pm path "$TARGET_PKG" 2>/dev/null | head -1 | sed 's/package://' | tr -d '\r')
if [ -z "$APK_PATH" ]; then
    echo "ERROR: Package $TARGET_PKG not found on device"
    exit 1
fi
BASE_DIR=$(dirname "$APK_PATH")
AGENT_PATH="${BASE_DIR}/lib/arm64/${AGENT_NAME}"

if ! adb shell "[ -f '$AGENT_PATH' ]" 2>/dev/null; then
    echo "ERROR: Agent not found at: $AGENT_PATH"
    echo "Make sure the .so is bundled in jniLibs/arm64-v8a/ and the APK is installed."
    exit 1
fi

echo "[*] Package path: $BASE_DIR"
echo "[*] Agent path:   $AGENT_PATH"

# --suspended: start the app frozen (waiting for JDWP), attach agent, then wait.
if [ "${2:-}" = "--suspended" ]; then
    echo "[*] Starting $TARGET_PKG suspended (am start -D)..."
    adb shell am start -D -n "${TARGET_PKG}/.MainActivity"

    echo "[*] Waiting for process to appear..."
    PID=""
    for i in $(seq 1 50); do
        PID=$(adb shell pidof "$TARGET_PKG" 2>/dev/null | tr -d '\r')
        [ -n "$PID" ] && break
        sleep 0.2
    done
    if [ -z "$PID" ]; then
        echo "ERROR: Process did not appear after 10s"
        exit 1
    fi
    echo "[*] PID: $PID"

    echo "[*] Attaching agent..."
    adb shell cmd activity attach-agent "$TARGET_PKG" "$AGENT_NAME"

    echo "[*] Waiting for agent socket..."
    sleep 2
    adb forward tcp:12345 localabstract:dexbgd

    echo ""
    echo "[*] Agent attached. App is frozen."
    echo "[*] In the TUI, type:  connect"
    echo "[*] Set your breakpoints, then run:"
    echo "    ./scripts/resume.sh $TARGET_PKG"
    exit 0
fi

# Normal path: ensure app is running, then attach
PID=$(adb shell pidof "$TARGET_PKG" 2>/dev/null | tr -d '\r')
if [ -z "$PID" ]; then
    echo "[*] App not running, starting it..."
    adb shell am start -n "${TARGET_PKG}/.MainActivity"
    sleep 2
    PID=$(adb shell pidof "$TARGET_PKG" 2>/dev/null | tr -d '\r')
    if [ -z "$PID" ]; then
        echo "ERROR: Failed to start $TARGET_PKG"
        exit 1
    fi
fi
echo "[*] PID: $PID"

echo "[*] Attaching agent..."
adb shell cmd activity attach-agent "$TARGET_PKG" "$AGENT_NAME"
echo "[*] Agent attached."
