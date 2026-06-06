"""
Triage Agent — rapid Tier-1 LLM analysis of every incoming alert.

Responsibilities:
  - Classify each alert as likely FP or likely TP using LLM reasoning
  - Assign a triage_confidence score (0.0 – 1.0)
  - Recommend an action: "close_fp" | "monitor" | "escalate"
  - Produce a 2–3 sentence triage_summary
  - Apply the supervisor's escalation rule and set routing_decision:
      escalate_to_investigation  if  likely_classification == TP  AND  severity == HIGH
      close                      otherwise

LLM prompt design rationale
─────────────────────────────
The system prompt instructs the model to behave as a Tier-1 SOC analyst
performing a rapid first-pass review.  The human prompt presents every alert
field that a real analyst would see: severity, category, source IP, rule name,
and the raw log line.  The model is told to return a strict JSON schema with no
markdown wrapping so that JsonOutputParser can parse it reliably.  A fallback
dict is returned on any parse error so the pipeline never halts.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnableSerializable

from soc_agents.state import SOCState

# ─── Prompt templates ────────────────────────────────────────────────────────

_SYSTEM = """You are an expert SOC Tier-1 analyst performing rapid alert triage.
Your job is to classify each security alert as likely False Positive (FP) or
True Positive (TP) and recommend an action.

Respond ONLY with a valid JSON object — no markdown fences, no text outside the JSON.

Heuristics to apply:
- Rule names containing "Authorised", "IT", "Scheduled", "Backup", "Migration",
  "HRIS", "SCCM", "MECM", "ticketID", "Override" → strong FP signal
- Raw logs from known scanning tools (Nessus, SCCM, MECM, Tenable) → FP signal
- External source IPs combined with credential categories → TP signal
- After-hours timestamps + bulk data transfers → TP signal
- Known attack tool names (cobalt, mimikatz, vssadmin, psexec without ticket) → TP signal
- Ransomware keywords (shadow, encrypt, LockBit) → strong TP/severe signal
"""

_HUMAN = """Analyse this security alert and return a triage decision as JSON.

Alert Fields:
  severity        : {severity}
  category        : {category}
  source_ip       : {source_ip}
  destination_ip  : {destination_ip}
  hostname        : {hostname}
  user            : {user}
  rule_name       : {rule_name}
  raw_log         : {raw_log}

Return EXACTLY this JSON structure (no extra keys, no markdown):
{{
  "likely_classification": "FP" or "TP",
  "triage_confidence": <float between 0.0 and 1.0>,
  "triage_recommendation": "close_fp" or "monitor" or "escalate",
  "triage_summary": "<2–3 sentence analyst reasoning>",
  "key_indicators": ["<indicator that drove the decision>", ...],
  "risk_factors": ["<risk factor or mitigating factor>", ...]
}}"""


# ─── Chain builder ────────────────────────────────────────────────────────────

def _build_chain(llm: Any) -> RunnableSerializable:
    """Construct the LCEL triage chain: prompt | llm | json_parser."""
    prompt = ChatPromptTemplate.from_messages([
        ("system", _SYSTEM),
        ("human", _HUMAN),
    ])
    return prompt | llm | JsonOutputParser()


# ─── Fallback ────────────────────────────────────────────────────────────────

def _fallback(reason: str) -> dict:
    return {
        "likely_classification": "FP",
        "triage_confidence": 0.50,
        "triage_recommendation": "monitor",
        "triage_summary": f"Automated triage unavailable ({reason}). Manual review required.",
        "key_indicators": [],
        "risk_factors": ["triage_error"],
    }


# ─── Node function ────────────────────────────────────────────────────────────

def run_triage(state: SOCState, llm: Any) -> dict:
    """
    LangGraph node — execute triage analysis and apply escalation routing.

    The supervisor's escalation rule is implemented here because it requires
    the triage result which does not exist when the supervisor_node ran:

        escalate_to_investigation  ←  likely_classification == TP  AND  severity == HIGH
        close                      ←  everything else

    Returns partial SOCState updates: triage_result, routing_decision,
    and one processing_log entry.
    """
    alert = state["alert"]
    chain = _build_chain(llm)

    try:
        triage_result: dict = chain.invoke({
            "severity": alert.get("severity", "UNKNOWN"),
            "category": alert.get("category", "unknown"),
            "source_ip": alert.get("source_ip", "0.0.0.0"),
            "destination_ip": alert.get("destination_ip", "0.0.0.0"),
            "hostname": alert.get("hostname", "unknown"),
            "user": alert.get("user", "unknown"),
            "rule_name": alert.get("rule_name", "Unknown Rule"),
            "raw_log": alert.get("raw_log", ""),
        })
    except Exception as exc:  # noqa: BLE001
        triage_result = _fallback(str(exc))

    # Supervisor escalation rule
    is_tp = triage_result.get("likely_classification") == "TP"
    is_high = alert.get("severity") == "HIGH"

    if is_tp and is_high:
        routing_decision = "escalate_to_investigation"
        triage_result["triage_recommendation"] = "escalate"
    elif is_tp:
        routing_decision = "close"
        triage_result["triage_recommendation"] = "monitor"
    else:
        routing_decision = "close"
        triage_result["triage_recommendation"] = "close_fp"

    conf = triage_result.get("triage_confidence", 0.0)
    log = (
        f"[TRIAGE] classification={triage_result['likely_classification']} "
        f"confidence={conf:.2f} recommendation={triage_result['triage_recommendation']} "
        f"routing={routing_decision}"
    )

    return {
        "triage_result": triage_result,
        "routing_decision": routing_decision,
        "processing_log": [log],
    }
