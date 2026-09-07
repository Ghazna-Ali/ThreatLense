"""
sources.py
------------------------------------------------------------------
All IOC helper functions and external intelligence source functions
live here. This module has NO Streamlit UI, NO Gemini logic, and NO
per-source orchestration outside of the SOURCES registry at the
bottom of the file.

To add a new intelligence source:
    1. Write a function `get_my_source(ioc: str, ioc_type: str) -> dict`
       that returns the standard result dict (see STANDARD RESULT
       FORMAT below).
    2. Add it to the SOURCES dict at the bottom of this file.
No changes to app.py are required.
------------------------------------------------------------------
"""

import base64
import ipaddress
import re
from datetime import date, datetime
from urllib.parse import urlparse

import requests
import streamlit as st
import whois  # python-whois


# ------------------------------------------------------------------
# STANDARD RESULT FORMAT
# ------------------------------------------------------------------
# Every source function returns exactly this shape:
#
# {
#     "source": "VirusTotal" | "WHOIS" | ...,
#     "verdict": "Safe" | "Suspicious" | "Malicious" | "Unknown" | "Error",
#     "risk_score": int (0-100),
#     "raw_data": dict,
#     "error": None | str,
# }
# ------------------------------------------------------------------


# Domain labels can be alphanumeric, but the final label (the TLD)
# must be purely alphabetic. This mirrors real-world domain naming
# and, importantly, keeps a malformed IP like "999.999.999.999" from
# being misclassified as a valid domain (its "TLD" is all digits).
_DOMAIN_PATTERN = (
    r"^(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+"
    r"[A-Za-z]{2,63}$"
)


# ==================================================================
# IOC HELPERS
# ==================================================================

def detect_ioc_type(ioc: str) -> str:
    """Detect whether `ioc` is an ip, domain, url, or unknown."""
    if not ioc:
        return "unknown"

    candidate = ioc.strip()
    if not candidate:
        return "unknown"

    # URL: has a scheme like http:// or https://
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", candidate):
        return "url"

    # IP address (v4 or v6)
    try:
        ipaddress.ip_address(candidate)
        return "ip"
    except ValueError:
        pass

    # Domain: simple structural check (labels separated by dots, no
    # spaces/slashes, plausible-looking TLD)
    if re.match(_DOMAIN_PATTERN, candidate):
        return "domain"

    return "unknown"


def is_valid_ioc(ioc: str, ioc_type: str) -> bool:
    """Validate `ioc` against the given type. Never makes network calls."""
    if not ioc or not isinstance(ioc, str):
        return False

    candidate = ioc.strip()
    if not candidate:
        return False

    try:
        if ioc_type == "ip":
            ipaddress.ip_address(candidate)
            return True

        if ioc_type == "domain":
            return bool(re.match(_DOMAIN_PATTERN, candidate))

        if ioc_type == "url":
            parsed = urlparse(candidate)
            if parsed.scheme not in ("http", "https"):
                return False
            hostname = parsed.hostname
            if not hostname:
                return False
            # Host can be a valid domain OR a raw IP address
            try:
                ipaddress.ip_address(hostname)
                return True
            except ValueError:
                return bool(re.match(_DOMAIN_PATTERN, hostname))

        return False
    except Exception:
        # Any unexpected parsing error means "not valid", never crash.
        return False


def extract_domain(ioc: str) -> str:
    """Extract the bare hostname/domain from a URL or domain string."""
    if not ioc:
        return ""

    candidate = ioc.strip()

    # If it has a scheme, let urlparse pull the hostname out for us.
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", candidate):
        try:
            hostname = urlparse(candidate).hostname
            return hostname or ""
        except Exception:
            return ""

    # Otherwise treat it as a bare domain, stripping any accidental
    # path/query/fragment the user typed after it.
    stripped = re.split(r"[/?#]", candidate, maxsplit=1)[0]
    return stripped


# ==================================================================
# VIRUSTOTAL
# ==================================================================

def get_virustotal(ioc: str, ioc_type: str) -> dict:
    """
    Query VirusTotal for the given IOC and normalize the response.

    Scoring logic (documented, deterministic):
        risk_score = round(100 * (malicious + 0.5 * suspicious) / total_engines)
        - "malicious" detections count fully
        - "suspicious" detections count at half weight
        - if there are no usable engine stats, we cannot compute a
          ratio at all -> verdict "Unknown", risk_score 0

    Verdict thresholds (derived from the same ratio):
        no engine stats available -> Unknown
        malicious == 0 and suspicious == 0 -> Safe
        risk_score < 20 (but some detections exist) -> Suspicious
        risk_score >= 20 -> Malicious

    This intentionally does NOT treat any single non-zero detection as
    automatic proof of malicious activity - it weighs it against the
    total number of engines that returned an opinion.
    """
    source = "VirusTotal"

    try:
        api_key = st.secrets["VIRUSTOTAL_API_KEY"]
    except Exception:
        return {
            "source": source,
            "verdict": "Error",
            "risk_score": 0,
            "raw_data": {},
            "error": "VirusTotal API key not configured in st.secrets.",
        }

    headers = {"x-apikey": api_key}

    try:
        if ioc_type == "ip":
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        elif ioc_type == "domain":
            endpoint = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        elif ioc_type == "url":
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            return {
                "source": source,
                "verdict": "Unknown",
                "risk_score": 0,
                "raw_data": {},
                "error": f"Unsupported IOC type for VirusTotal: {ioc_type}",
            }

        response = requests.get(endpoint, headers=headers, timeout=15)

        # VT returns 404 when it simply has no data yet for this
        # indicator - that's "Unknown", not a failure.
        if response.status_code == 404:
            return {
                "source": source,
                "verdict": "Unknown",
                "risk_score": 0,
                "raw_data": {"message": "No VirusTotal data found for this indicator."},
                "error": None,
            }

        response.raise_for_status()
        payload = response.json()

        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {}) or {}

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        timeout_count = stats.get("timeout", 0)

        total_engines = malicious + suspicious + harmless + undetected + timeout_count

        if total_engines == 0:
            verdict = "Unknown"
            risk_score = 0
        else:
            ratio = (malicious + 0.5 * suspicious) / total_engines
            risk_score = round(ratio * 100)
            if malicious == 0 and suspicious == 0:
                verdict = "Safe"
            elif risk_score < 20:
                verdict = "Suspicious"
            else:
                verdict = "Malicious"

        raw_data = {
            "last_analysis_stats": stats,
            "reputation": attributes.get("reputation"),
            "total_votes": attributes.get("total_votes"),
            "categories": attributes.get("categories"),
        }
        raw_data = {k: v for k, v in raw_data.items() if v is not None}

        return {
            "source": source,
            "verdict": verdict,
            "risk_score": risk_score,
            "raw_data": raw_data,
            "error": None,
        }

    except requests.exceptions.RequestException as exc:
        return {
            "source": source,
            "verdict": "Error",
            "risk_score": 0,
            "raw_data": {},
            "error": f"VirusTotal request failed: {exc}",
        }
    except Exception as exc:
        return {
            "source": source,
            "verdict": "Error",
            "risk_score": 0,
            "raw_data": {},
            "error": f"Unexpected VirusTotal error: {exc}",
        }


# ==================================================================
# WHOIS
# ==================================================================

def get_who_is(ioc: str, ioc_type: str) -> dict:
    """
    Query WHOIS for the given IOC's domain and normalize the response.

    WHOIS is treated as CONTEXTUAL evidence only and never produces a
    "Malicious" verdict on its own:
        - IP addresses: WHOIS isn't queried -> "Unknown"
        - No usable registration data returned -> "Unknown"
        - Domain registered in the last 30 days -> "Suspicious"
          (new-domain risk signal only, not proof of anything)
        - Otherwise, having registration data at all -> "Safe"
    Missing fields (e.g. privacy-protected WHOIS) never imply
    malicious behavior by themselves.
    """
    source = "WHOIS"

    if ioc_type == "ip":
        return {
            "source": source,
            "verdict": "Unknown",
            "risk_score": 0,
            "raw_data": {"message": "WHOIS lookups are only performed for domains/URLs."},
            "error": None,
        }

    domain = extract_domain(ioc) if ioc_type == "url" else ioc.strip()

    if not domain:
        return {
            "source": source,
            "verdict": "Error",
            "risk_score": 0,
            "raw_data": {},
            "error": "Could not extract a domain to look up.",
        }

    try:
        record = whois.whois(domain)

        def _first(value):
            # python-whois sometimes returns a list of dates/strings.
            if isinstance(value, list):
                return value[0] if value else None
            return value

        creation_date = _first(record.creation_date)
        expiration_date = _first(record.expiration_date)
        updated_date = _first(record.updated_date)
        registrar = _first(record.registrar)
        domain_name = _first(record.domain_name)

        raw_data = {
            "domain": domain_name or domain,
            "registrar": registrar,
            "creation_date": str(creation_date) if creation_date else None,
            "expiration_date": str(expiration_date) if expiration_date else None,
            "updated_date": str(updated_date) if updated_date else None,
            "name_servers": record.name_servers,
            "status": record.status,
        }
        raw_data = {k: v for k, v in raw_data.items() if v is not None}

        if not registrar and not creation_date:
            # WHOIS gave us essentially nothing usable.
            return {
                "source": source,
                "verdict": "Unknown",
                "risk_score": 0,
                "raw_data": raw_data,
                "error": None,
            }

        verdict = "Safe"
        risk_score = 0

        age_days = None
        if isinstance(creation_date, datetime):
            age_days = (datetime.now() - creation_date).days
        elif isinstance(creation_date, date):
            age_days = (date.today() - creation_date).days

        if age_days is not None and age_days < 30:
            verdict = "Suspicious"
            risk_score = 40

        return {
            "source": source,
            "verdict": verdict,
            "risk_score": risk_score,
            "raw_data": raw_data,
            "error": None,
        }

    except Exception as exc:
        return {
            "source": source,
            "verdict": "Error",
            "risk_score": 0,
            "raw_data": {},
            "error": f"WHOIS lookup failed: {exc}",
        }


# ==================================================================
# SOURCE REGISTRY
# ------------------------------------------------------------------
# To add a new source: write a `get_x(ioc, ioc_type) -> dict` function
# above following the standard result format, then register it below.
# app.py loops over this dict generically - no other file changes.
# ==================================================================
SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_who_is,
}
