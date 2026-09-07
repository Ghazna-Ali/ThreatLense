# ThreatLens

ThreatLens is a Streamlit app that checks whether an IP address, domain, or URL looks safe or risky. It pulls data from **VirusTotal** and **WHOIS**, then sends the combined findings to **Google Gemini** for a plain-language, level-appropriate interpretation (Beginner / Intermediate / Expert).

> ThreatLens provides an automated risk assessment based on available intelligence. A "Safe" result does not guarantee that an indicator is completely harmless.

---

## How it works

```
                 USER
                   │
                   ▼
                app.py            (Streamlit UI, validation,
                   │               orchestration, Gemini prompt/parse)
          ┌────────┴─────────┐
          │                  │
          ▼                  ▼
     sources.py           Gemini
          │
     ┌────┴─────┐
     ▼          ▼
VirusTotal    WHOIS
```

- **`sources.py`** owns all IOC logic (type detection, validation, domain extraction) and every intelligence source (`get_virustotal`, `get_who_is`), ending in a `SOURCES` registry dict. It has no Streamlit UI and no Gemini logic.
- **`app.py`** owns the UI, the validation flow, looping over `SOURCES` generically (no per-source `if/else`), the Gemini prompt/JSON parsing, and results display.
- Adding a new intelligence source only ever requires: write `get_x(ioc, ioc_type) -> dict` in `sources.py`, add it to `SOURCES`. Nothing in `app.py` changes.

## Project structure

```
ThreatLens/
├── app.py
├── sources.py
├── requirements.txt
├── run_tunnel.sh          # Cloudflare tunnel launcher (macOS/Linux)
├── run_tunnel.ps1         # Cloudflare tunnel launcher (Windows)
├── cloudflared.exe        # (Windows only - not committed, see below)
└── .streamlit/
    └── secrets.toml.example
```

---

## Prerequisites

- Python 3.9+
- A free [VirusTotal](https://www.virustotal.com/) account and API key
- A free [Google AI Studio](https://aistudio.google.com/apikey) Gemini API key
- (Optional, for public sharing) `cloudflared` - [download here](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/). No Cloudflare account is required for the quick-tunnel flow this project uses.

## Setup

1. Clone this repo and `cd` into it.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Copy the secrets template and fill in your real keys:
   ```bash
   cp .streamlit/secrets.toml.example .streamlit/secrets.toml
   ```
   ```toml
   VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
   GEMINI_API_KEY = "your_gemini_api_key"
   ```
   `.streamlit/secrets.toml` is git-ignored - never commit real keys.

## Running locally

```bash
python -m streamlit run app.py
```

This opens the app in your default browser at `http://localhost:8501`. Using `python -m streamlit` (rather than the bare `streamlit` command) avoids PATH-resolution issues some setups hit, and works identically on Windows/macOS/Linux.

Test it with a known-safe indicator first, e.g. `8.8.8.8`, to confirm both API keys are working before trying anything else.

---

## Sharing it publicly with Cloudflare Tunnel

ThreatLens can be exposed to the internet with a Cloudflare **quick tunnel** - no ngrok, no Cloudflare account, no API key, no domain. It works by opening an outbound connection from your machine to Cloudflare's edge, so it bypasses your router/firewall (no port forwarding needed) and is reachable from any network, not just your own.

### Recommended: run it in two separate steps

This has proven the most reliable approach in practice - keep Streamlit and the tunnel as two independent processes rather than one script managing both:

**Terminal 1 - start the app:**
```bash
python -m streamlit run app.py
```
Confirm it loads at `http://localhost:8501` in a browser before moving on.

**Terminal 2 - start the tunnel, forcing IPv4:**
```powershell
./cloudflared.exe tunnel --url http://127.0.0.1:8501 --edge-ip-version 4
```
(macOS/Linux: `cloudflared tunnel --url http://127.0.0.1:8501 --edge-ip-version 4`)

Cloudflare will print a public URL that looks like `https://random-words.trycloudflare.com`. Share that link. Closing either terminal - or your machine sleeping - takes the link down; restarting the tunnel generates a brand-new random URL each time.

### Convenience scripts

`run_tunnel.sh` (macOS/Linux) and `run_tunnel.ps1` (Windows) automate the above - starting Streamlit, then the tunnel with `--edge-ip-version 4` and a retry-with-backoff loop if the initial tunnel request times out.

```powershell
powershell -ExecutionPolicy Bypass -File .\run_tunnel.ps1
```

These are convenient, but the two-terminal manual flow above is the more battle-tested option if the script gives you trouble - it's easier to see exactly which piece failed.

---

## Troubleshooting

**`failed to request quick Tunnel: ... context deadline exceeded`**
The initial request to Cloudflare's tunnel API timed out. Always include `--edge-ip-version 4` - on networks with a partially broken IPv6 path, cloudflared can otherwise stall trying IPv6 first. If it still fails on every attempt, you may be hitting Cloudflare's account-less quick-tunnel rate limiting from repeated rapid requests; wait a few minutes between attempts rather than retrying immediately.

**Tunnel connects, but the public URL doesn't load**
Make sure Streamlit is actually running and reachable at `http://localhost:8501` *before* starting the tunnel - the tunnel just forwards to that local address, so if nothing's listening there, the public URL will fail too.

**The public URL loads in one browser but not another**
If it fails to load in your default browser (e.g. Edge) but works in a different one (e.g. Chrome), that's typically a browser-level quirk (extensions, cached state, or corporate browser policy) rather than an actual tunnel or app problem. Try a different browser, or an incognito/private window, before assuming the tunnel itself is broken.

**`Start-Process` can't find `streamlit` when using `run_tunnel.ps1`**
Run Streamlit manually with `python -m streamlit run app.py` in its own terminal instead (see "Recommended" above) - it's more robust across different install setups than relying on `streamlit` being resolvable via `Start-Process`.

**A source shows an "Error" verdict**
Check `.streamlit/secrets.toml` first - a missing or invalid API key is the most common cause. One source failing never blocks the other; VirusTotal and WHOIS run and report independently.

**Gemini returns a 404 for a model name**
Google periodically retires older Gemini model versions. This project uses the `gemini-flash-latest` alias, which Google keeps pointed at whatever the current flash model is, specifically to avoid this.

---

## Security notes

- Never commit `.streamlit/secrets.toml` (only `secrets.toml.example` should be tracked).
- A running quick tunnel is public and unauthenticated - anyone with the URL can use the app and consume your API quota while it's active. Don't leave it running unattended, and don't share the link more widely than necessary.
- Quick tunnels have no uptime guarantee and are intended for testing/demos, not production hosting. For a stable, permanent URL on your own domain, use a [named Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps) tied to a real Cloudflare account instead.
