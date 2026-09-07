# ------------------------------------------------------------------
# run_tunnel.ps1
#
# Starts ThreatLens locally with Streamlit, then exposes it via a
# Cloudflare quick tunnel - forcing IPv4 (--chrome-ip-version 4), since
# some networks have a broken/flaky IPv6 path that makes cloudflared's
# initial tunnel request hang and time out. Retries automatically if
# that initial request fails.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\run_tunnel.ps1
#
# Requires cloudflared.exe to be in this same folder (or on PATH).
# Press Ctrl+C to stop the tunnel; then close the Streamlit window too.
# ------------------------------------------------------------------

$Port = 8501
$MaxAttempts = 5
$RetryDelaySeconds = 3

# Resolve cloudflared.exe: prefer one sitting next to this script.
$cloudflaredPath = Join-Path $PSScriptRoot "cloudflared.exe"
if (-not (Test-Path $cloudflaredPath)) {
    $cloudflaredPath = "cloudflared.exe"  # fall back to PATH
}

Write-Host "Starting ThreatLens on http://localhost:$Port ..."
$streamlitProcess = Start-Process -PassThru -FilePath "streamlit" `
    -ArgumentList "run app.py --server.port $Port --server.headless true"

Start-Sleep -Seconds 3

try {
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        Write-Host ""
        Write-Host "Starting Cloudflare quick tunnel (attempt $attempt of $MaxAttempts, forcing IPv4)..."

        & $cloudflaredPath tunnel --url "http://127.0.0.1:$Port" --chrome-ip-version 4

        # cloudflared exits immediately (non-zero) if the initial quick
        # tunnel request fails; if it actually connects, it stays
        # running until Ctrl+C and we never reach this retry logic.
        if ($LASTEXITCODE -eq 0) {
            break
        }

        Write-Host "Tunnel request failed (exit code $LASTEXITCODE)."
        if ($attempt -lt $MaxAttempts) {
            Write-Host "Retrying in $RetryDelaySeconds seconds..."
            Start-Sleep -Seconds $RetryDelaySeconds
        } else {
            Write-Host "Gave up after $MaxAttempts attempts. Check your network connection and try again."
        }
    }
}
finally {
    Write-Host ""
    Write-Host "Shutting down Streamlit..."
    Stop-Process -Id $streamlitProcess.Id -ErrorAction SilentlyContinue
}
