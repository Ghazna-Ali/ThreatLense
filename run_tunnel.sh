```bash
#!/usr/bin/env bash
# ------------------------------------------------------------------
# run_tunnel.sh
#
# Starts ThreatLens locally with Streamlit, then exposes it to the
# public internet with a Cloudflare Quick Tunnel.
#
# Supports:
#   - Linux
#   - macOS
#   - Windows + Git Bash
#
# Usage:
#   chmod +x run_tunnel.sh
#   ./run_tunnel.sh
#
# Press Ctrl+C to stop both Streamlit and Cloudflare Tunnel.
# ------------------------------------------------------------------

set -euo pipefail

PORT=8501

# ---- 1. Locate cloudflared ---------------------------------------

CLOUDFLARED=""

# Windows + Git Bash:
# Look for cloudflared.exe in the current project directory first.
if [ -f "./cloudflared.exe" ]; then
    CLOUDFLARED="./cloudflared.exe"

# Normal Linux/macOS installation:
elif command -v cloudflared >/dev/null 2>&1; then
    CLOUDFLARED="$(command -v cloudflared)"

# Windows cloudflared available somewhere in PATH:
elif command -v cloudflared.exe >/dev/null 2>&1; then
    CLOUDFLARED="$(command -v cloudflared.exe)"

else
    echo "cloudflared not found."
    echo ""
    echo "Please download cloudflared from:"
    echo "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
    echo ""
    echo "On Windows, place cloudflared.exe in this ThreatLens folder:"
    echo "$(pwd)"
    exit 1
fi

echo "Using cloudflared: $CLOUDFLARED"

# ---- 2. Check Python / Streamlit ---------------------------------

if ! command -v python >/dev/null 2>&1; then
    echo "Python was not found."
    exit 1
fi

if ! python -m streamlit --version >/dev/null 2>&1; then
    echo "Streamlit is not installed in this Python environment."
    echo ""
    echo "Install it with:"
    echo "python -m pip install streamlit"
    exit 1
fi

echo "Using:"
python --version
python -m streamlit --version

# ---- 3. Start Streamlit in the background ------------------------

echo ""
echo "Starting ThreatLens on http://127.0.0.1:${PORT} ..."

python -m streamlit run app.py \
    --server.port "${PORT}" \
    --server.address "127.0.0.1" \
    --server.headless true &

STREAMLIT_PID=$!

# ---- 4. Cleanup function -----------------------------------------

TUNNEL_PID=""

cleanup() {
    echo ""
    echo "Shutting down..."

    if [ -n "${TUNNEL_PID}" ]; then
        kill "${TUNNEL_PID}" 2>/dev/null || true
    fi

    if [ -n "${STREAMLIT_PID}" ]; then
        kill "${STREAMLIT_PID}" 2>/dev/null || true
    fi
}

trap cleanup EXIT INT TERM

# ---- 5. Give Streamlit time to start ------------------------------

sleep 3

# ---- 6. Start Cloudflare Quick Tunnel ----------------------------

echo ""
echo "Starting Cloudflare quick tunnel..."
echo ""

# --chrome-ip-version 4 is required for reliable connectivity
# on this Windows/Git Bash setup.

"$CLOUDFLARED" tunnel \
    --url "http://127.0.0.1:${PORT}" \
    --chrome-ip-version 4 &

TUNNEL_PID=$!

# ---- 7. Wait for either process ----------------------------------

wait "$STREAMLIT_PID" "$TUNNEL_PID"
```
