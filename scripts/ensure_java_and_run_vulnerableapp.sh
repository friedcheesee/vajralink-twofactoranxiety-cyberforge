#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VAJRA_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOLS_DIR="$VAJRA_ROOT/.tools"
JDK_DIR="$TOOLS_DIR/jdk-17"
TARGET_DIR="$VAJRA_ROOT/../targets/VulnerableApp"

mkdir -p "$TOOLS_DIR"

# 1. Download OpenJDK 17 if not present
if [ ! -f "$JDK_DIR/Contents/Home/bin/java" ]; then
    echo "[Vajra] OpenJDK 17 not found. Downloading Eclipse Temurin 17 for macOS arm64..."
    JDK_URL="https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.21%2B9/OpenJDK17U-jdk_aarch64_mac_hotspot_17.0.21_9.tar.gz"
    TAR_FILE="$TOOLS_DIR/temurin17.tar.gz"
    curl -L -o "$TAR_FILE" "$JDK_URL"
    mkdir -p "$JDK_DIR"
    tar -xzf "$TAR_FILE" -C "$JDK_DIR" --strip-components 1
    rm -f "$TAR_FILE"
    echo "[Vajra] OpenJDK 17 installed successfully into $JDK_DIR"
fi

export JAVA_HOME="$JDK_DIR/Contents/Home"
export PATH="$JAVA_HOME/bin:$PATH"

echo "[Vajra] Using Java Runtime:"
"$JAVA_HOME/bin/java" -version

# 2. Check if VulnerableApp is already running on port 9090
if curl -s -m 2 http://127.0.0.1:9090 >/dev/null; then
    echo "[Vajra] VulnerableApp is already running on http://127.0.0.1:9090"
    exit 0
fi

if [ "$1" = "--start" ]; then
    echo "[Vajra] Starting VulnerableApp in background on port 9090..."
    cd "$TARGET_DIR"
    nohup ./gradlew bootRun > "$VAJRA_ROOT/vulnerableapp.log" 2>&1 &
    APP_PID=$!
    echo "[Vajra] VulnerableApp launching with PID $APP_PID. Waiting for port 9090..."
    for i in {1..60}; do
        if curl -s -m 1 http://127.0.0.1:9090 >/dev/null; then
            echo "[Vajra] VulnerableApp is UP and READY on http://127.0.0.1:9090!"
            exit 0
        fi
        sleep 2
    done
    echo "[Vajra] Warning: VulnerableApp did not become ready within 120 seconds. Check vulnerableapp.log."
fi
