"""
app.py
------------------------------------------------------------------
ThreatLens - Streamlit UI, orchestration, and Gemini integration.

This file owns:
    - Streamlit UI
    - user input & validation flow
    - looping over sources.SOURCES (NO per-source logic here)
    - building the Gemini prompt & safely parsing its JSON response
    - results display

All IOC/VirusTotal/WHOIS logic lives in sources.py. This file never
imports or hardcodes anything specific to a single source - it only
knows the SOURCES registry.
------------------------------------------------------------------
"""

import json
import re
from typing import Optional, Tuple

import streamlit as st
import google.generativeai as genai

from sources import detect_ioc_type, is_valid_ioc, SOURCES


# ==================================================================
# PAGE SETUP
# ==================================================================
st.set_page_config(page_title="ThreatLens", page_icon="🔎", layout="centered")

st.title("ThreatLens")
st.caption("Analyze an IP address, domain, or URL using trusted threat intelligence sources.")

st.info(
    "ThreatLens provides an automated risk assessment based on available "
    "intelligence. A \"Safe\" result does not guarantee that an indicator "
    "is completely harmless.",
    icon="ℹ️",
)


# ==================================================================
# CACHED SOURCE CALL
# ------------------------------------------------------------------
# A single generic cache wrapper. It looks the function up in the
# registry by name and calls it - it has no idea which source it's
# actually calling, so adding a new source never touches this code.
# ==================================================================
@st.cache_data(show_spinner=False, ttl=3600)
def run_source(source_name: str, ioc: str, ioc_type: str) -> dict:
    source_function = SOURCES[source_name]
    try:
        return source_function(ioc, ioc_type)
    except Exception as exc:
        # Belt-and-suspenders: even if a source function forgot to
        # catch its own exceptions, one failing source can never take
        # down the others.
        return {
            "source": source_name,
            "verdict": "Error",
            "risk_score": 0,
            "raw_data": {},
            "error": f"Unexpected error in {source_name}: {exc}",
        }


# ==================================================================
# GEMINI
# ==================================================================
VERDICT_ICONS = {
    "Safe": "🟢",
    "Suspicious": "🟡",
    "Malicious": "🔴",
    "Unknown": "⚪",
    "Error": "⚪",
}

FALLBACK_AI_RESULT = {
    "verdict": "Unknown",
    "risk_score": 0,
    "summary": "AI analysis could not be completed.",
    "key_findings": [],
    "recommendations": [],
}

LEVEL_GUIDANCE = {
    "Beginner": (
        "Explain your reasoning in simple, non-technical language. Briefly "
        "explain any necessary terms (e.g. WHOIS, DNS, registrar, malicious "
        "detection) the first time you use them. Avoid unnecessary jargon."
    ),
    "Intermediate": (
        "Use moderate technical detail: detection ratios, domain age, "
        "registration information, and how the sources differ. Assume the "
        "reader understands basic cybersecurity terminology."
    ),
    "Expert": (
        "Provide a technically detailed analysis: detection ratios, "
        "conflicting intelligence between sources, registration metadata, "
        "source reliability, limitations, uncertainty, possible false "
        "positives, and evidence strength. Do not oversimplify."
    ),
}


def build_gemini_prompt(ioc: str, ioc_type: str, level: str, results: list) -> str:
    """Build a level-specific prompt containing only the collected source data."""
    source_summaries = [
        {
            "source": result.get("source"),
            "verdict": result.get("verdict"),
            "risk_score": result.get("risk_score"),
            "raw_data": result.get("raw_data"),
            "error": result.get("error"),
        }
        for result in results
    ]

    prompt = f"""You are a cybersecurity analysis assistant. Analyze the indicator below
using ONLY the source data provided. Do not invent facts or assume
information that is not present in the data.

Indicator: {ioc}
Indicator type: {ioc_type}
Reader knowledge level: {level}

Source data (JSON):
{json.dumps(source_summaries, indent=2, default=str)}

Rules:
- Use only the supplied source data. Do not claim the indicator is
  malicious without supporting evidence in the data above.
- Treat WHOIS data as contextual information only, never as proof of
  malicious activity on its own.
- Treat VirusTotal detections as evidence, not absolute proof.
- Clearly separate factual source findings from your own interpretation.
- If the evidence is insufficient or conflicting, use "Unknown" rather
  than guessing.
- {LEVEL_GUIDANCE.get(level, "")}

Respond with ONLY valid JSON (no markdown fences, no commentary)
matching exactly this structure:
{{
  "verdict": "Safe" | "Suspicious" | "Malicious" | "Unknown",
  "risk_score": <integer 0-100>,
  "summary": "<a few sentences>",
  "key_findings": ["<finding 1>", "<finding 2>", "..."],
  "recommendations": ["<recommendation 1>", "<recommendation 2>", "..."]
}}
"""
    return prompt


def parse_gemini_response(raw_text: str) -> dict:
    """Safely parse Gemini's response into the expected dict shape."""
    if not raw_text:
        return dict(FALLBACK_AI_RESULT)

    text = raw_text.strip()

    # Strip markdown code fences if present, e.g. ```json ... ``` or ``` ... ```
    fence_match = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1)

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return dict(FALLBACK_AI_RESULT)

    if not isinstance(data, dict):
        return dict(FALLBACK_AI_RESULT)

    result = dict(FALLBACK_AI_RESULT)
    result["verdict"] = data.get("verdict") or result["verdict"]

    try:
        result["risk_score"] = int(data.get("risk_score", result["risk_score"]))
    except (TypeError, ValueError):
        pass

    result["summary"] = data.get("summary") or result["summary"]

    if isinstance(data.get("key_findings"), list):
        result["key_findings"] = data["key_findings"]
    if isinstance(data.get("recommendations"), list):
        result["recommendations"] = data["recommendations"]

    return result


def call_gemini(prompt: str) -> Tuple[dict, Optional[str]]:
    """Call Gemini and return (parsed_result, error_message_or_None)."""
    try:
        api_key = st.secrets["GEMINI_API_KEY"]
    except Exception:
        return dict(FALLBACK_AI_RESULT), "Gemini API key not configured in st.secrets."

    try:
        genai.configure(api_key=api_key)
        # "gemini-flash-latest" is a Google-maintained alias that always
        # points at the current flash model, so this doesn't need to be
        # updated by hand every time a model version is retired.
        model = genai.GenerativeModel("gemini-flash-latest")
        response = model.generate_content(prompt)
        raw_text = getattr(response, "text", None) or ""
        return parse_gemini_response(raw_text), None
    except Exception as exc:
        return dict(FALLBACK_AI_RESULT), f"Gemini request failed: {exc}"


# ==================================================================
# UI - INPUT FORM
# ==================================================================
st.subheader("1. Select IOC type")
ioc_type_label = st.radio(
    "IOC Type",
    options=["IP Address", "Domain", "URL"],
    horizontal=True,
    label_visibility="collapsed",
)
LABEL_TO_TYPE = {"IP Address": "ip", "Domain": "domain", "URL": "url"}

st.subheader("2. Knowledge level")
level = st.radio(
    "Knowledge Level",
    options=["Beginner", "Intermediate", "Expert"],
    horizontal=True,
    label_visibility="collapsed",
)

st.subheader("3. Enter the indicator")
ioc_input = st.text_input(
    "Enter IP, domain, or URL",
    placeholder="8.8.8.8, example.com, or https://example.com/login",
    label_visibility="collapsed",
)

analyze_clicked = st.button("Analyze", type="primary")


# ==================================================================
# VALIDATION + ORCHESTRATION
# ==================================================================
if analyze_clicked:
    ioc = (ioc_input or "").strip()
    selected_type = LABEL_TO_TYPE[ioc_type_label]

    if not ioc:
        st.error("✗ Please enter an IP address, domain, or URL.")
        st.stop()

    detected_type = detect_ioc_type(ioc)
    ioc_type = selected_type

    if not is_valid_ioc(ioc, ioc_type):
        # Give the auto-detected type a chance in case the wrong radio
        # option was selected, before rejecting the input outright.
        if detected_type != ioc_type and is_valid_ioc(ioc, detected_type):
            ioc_type = detected_type
        else:
            st.error(f"✗ Invalid {ioc_type_label.lower()}: \"{ioc}\"")
            st.stop()

    st.success(f"✓ Valid {ioc_type}")

    # ---- Source orchestration: loop over the registry only ----
    with st.spinner("Querying threat intelligence sources..."):
        results = [run_source(name, ioc, ioc_type) for name in SOURCES]

    # ---- Gemini interpretation ----
    with st.spinner("Getting AI interpretation..."):
        prompt = build_gemini_prompt(ioc, ioc_type, level, results)
        ai_result, gemini_error = call_gemini(prompt)

    if gemini_error:
        st.warning(f"AI analysis unavailable: {gemini_error}")

    # ==============================================================
    # AI ASSESSMENT CARD
    # ==============================================================
    st.divider()
    st.subheader("AI Assessment")

    verdict = ai_result.get("verdict", "Unknown")
    icon = VERDICT_ICONS.get(verdict, "⚪")

    with st.container(border=True):
        st.markdown(f"### {icon} {verdict.upper()}")

        risk_score = ai_result.get("risk_score", 0)
        st.metric("Risk Score", f"{risk_score} / 100")
        st.caption(
            "0 = Low risk · 100 = High risk. This score reflects available "
            "evidence, not certainty."
        )

        st.markdown("**Summary**")
        st.write(ai_result.get("summary", ""))

        findings = ai_result.get("key_findings") or []
        if findings:
            st.markdown("**Key Findings**")
            for item in findings:
                st.markdown(f"- {item}")

        recommendations = ai_result.get("recommendations") or []
        if recommendations:
            st.markdown("**Recommendations**")
            for item in recommendations:
                st.markdown(f"- {item}")

    # ==============================================================
    # SOURCE RESULTS
    # ==============================================================
    st.divider()
    st.subheader("Source Results")

    for result in results:
        source_name = result.get("source", "Unknown source")
        source_verdict = result.get("verdict", "Unknown")
        source_icon = VERDICT_ICONS.get(source_verdict, "⚪")
        source_risk = result.get("risk_score", 0)
        error = result.get("error")

        with st.container(border=True):
            st.markdown(f"**{source_name}**")
            st.write(f"{source_icon} Verdict: {source_verdict}")
            st.write(f"Risk Score: {source_risk}/100")

            if error:
                st.error(f"Unable to retrieve {source_name} information: {error}")

            with st.expander("Raw Data"):
                st.json(result.get("raw_data") or {})