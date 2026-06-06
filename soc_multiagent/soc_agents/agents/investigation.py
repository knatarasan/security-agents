"""
Investigation Agent — deep Tier-3 forensic analysis for escalated alerts.

Only called when the supervisor routes an alert as "escalate_to_investigation"
(i.e., triage classified it as likely TP AND severity is HIGH).

Responsibilities:
  - Map the attack to a MITRE ATT&CK tactic and technique ID
  - Identify the attack stage in the kill-chain
  - Extract a structured IOC list (IP, hostname, user, malware artefacts)
  - Recommend a concrete incident response action
  - Assess overall severity: critical | high | medium
  - Produce analyst notes, threat actor profile, and containment steps
  - Estimate time_to_investigate (simulated)

LLM prompt design rationale
─────────────────────────────
The system prompt establishes the analyst persona at Tier-3 depth.  The human
prompt supplies BOTH the original alert fields AND the triage context (summary,
key indicators, confidence) so the investigation can build on prior reasoning
rather than starting cold.  The model is instructed to produce a strict JSON
schema to enable downstream parsing and display.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnableSerializable

from soc_agents.state import SOCState

# ─── Prompt templates ────────────────────────────────────────────────────────

_SYSTEM = """You are a senior SOC Tier-3 threat analyst and incident responder.
You receive escalated HIGH-severity alerts that Tier-1 triage has classified as
likely True Positives.

Your investigation must:
1. Map to the most precise MITRE ATT&CK technique (Txxxx.xxx if applicable)
2. Name the ATT&CK tactic (attack stage): Initial Access | Execution | Persistence |
   Privilege Escalation | Defense Evasion | Credential Access | Discovery |
   Lateral Movement | Collection | Command and Control | Exfiltration | Impact
3. List concrete IOCs (IPs, hashes, process names, hostnames, user accounts)
4. Recommend a specific, actionable incident response step
5. Assess severity: critical (active breach / data loss) | high (imminent risk) | medium
6. Identify threat actor profile if signatures match known APT/ransomware groups
7. Provide 3 containment steps in order of urgency

Respond ONLY with valid JSON — no markdown, no preamble, no explanation outside JSON.
Be precise: use real MITRE technique IDs, real tool names, real CVE numbers where applicable.
"""

_HUMAN = """Perform a deep forensic investigation on this escalated alert.

=== Original Alert ===
alert_id       : {alert_id}
severity       : {severity}
category       : {category}
source_ip      : {source_ip}
destination_ip : {destination_ip}
hostname       : {hostname}
user           : {user}
rule_name      : {rule_name}
raw_log        : {raw_log}

=== Triage Context ===
classification : {triage_classification}
confidence     : {triage_confidence}
summary        : {triage_summary}
key_indicators : {key_indicators}

Return EXACTLY this JSON structure (no extra keys):
{{
  "attack_stage": "<MITRE ATT&CK tactic>",
  "mitre_technique": "<Txxxx[.xxx] – Technique Name>",
  "ioc_summary": ["<ioc1>", "<ioc2>", "<ioc3>"],
  "recommended_response": "<single most important IR action>",
  "severity_assessment": "critical" or "high" or "medium",
  "analyst_notes": "<3–4 sentence forensic analysis>",
  "threat_actor_profile": "<APT group, ransomware family, or 'Unknown'>",
  "containment_steps": ["<urgent step 1>", "<step 2>", "<step 3>"],
  "time_to_investigate": "<realistic estimate e.g. '4 minutes'>"
}}"""


# ─── Chain builder ────────────────────────────────────────────────────────────

def _build_chain(llm: Any) -> RunnableSerializable:
    """Construct the LCEL investigation chain: prompt | llm | json_parser."""
    prompt = ChatPromptTemplate.from_messages([
        ("system", _SYSTEM),
        ("human", _HUMAN),
    ])
    return prompt | llm | JsonOutputParser()


# ─── Fallback ────────────────────────────────────────────────────────────────

def _fallback(alert: dict, reason: str) -> dict:
    return {
        "attack_stage": "Unknown",
        "mitre_technique": "T0000 – Investigation Unavailable",
        "ioc_summary": [
            alert.get("source_ip", "unknown"),
            alert.get("hostname", "unknown"),
            alert.get("user", "unknown"),
        ],
        "recommended_response": "Manual investigation required — automated analysis failed.",
        "severity_assessment": "high",
        "analyst_notes": (
            f"Automated investigation failed: {reason}. "
            "Alert meets escalation criteria (HIGH severity + TP classification). "
            "Escalate to senior analyst immediately."
        ),
        "threat_actor_profile": "Unknown",
        "containment_steps": [
            "Isolate affected host from network",
            "Preserve memory dump and disk image",
            "Escalate to senior analyst / IR team",
        ],
        "time_to_investigate": "manual",
    }


# ─── Node function ────────────────────────────────────────────────────────────

def run_investigation(state: SOCState, llm: Any) -> dict:
    """
    LangGraph node — execute deep forensic investigation.

    Invoked only for alerts where routing_decision == "escalate_to_investigation".
    Reads both the original alert and the triage context to produce a rich
    investigation_report with MITRE ATT&CK mapping.

    Returns partial SOCState updates: investigation_report, final_disposition,
    and one processing_log entry.
    """
    alert = state["alert"]
    triage = state.get("triage_result", {})
    chain = _build_chain(llm)

    try:
        report: dict = chain.invoke({
            "alert_id": alert.get("alert_id", "unknown"),
            "severity": alert.get("severity", "UNKNOWN"),
            "category": alert.get("category", "unknown"),
            "source_ip": alert.get("source_ip", "0.0.0.0"),
            "destination_ip": alert.get("destination_ip", "0.0.0.0"),
            "hostname": alert.get("hostname", "unknown"),
            "user": alert.get("user", "unknown"),
            "rule_name": alert.get("rule_name", "Unknown Rule"),
            "raw_log": alert.get("raw_log", ""),
            "triage_classification": triage.get("likely_classification", "TP"),
            "triage_confidence": f"{triage.get('triage_confidence', 0.8):.2f}",
            "triage_summary": triage.get("triage_summary", "No summary available."),
            "key_indicators": json.dumps(triage.get("key_indicators", []), indent=0),
        })
    except Exception as exc:  # noqa: BLE001
        report = _fallback(alert, str(exc))

    sev = report.get("severity_assessment", "unknown")
    stage = report.get("attack_stage", "Unknown")
    mitre = report.get("mitre_technique", "N/A")

    log = (
        f"[INVESTIGATION] attack_stage={stage} mitre={mitre} "
        f"severity_assessment={sev} "
        f"threat_actor={report.get('threat_actor_profile', 'Unknown')}"
    )

    return {
        "investigation_report": report,
        "final_disposition": f"ESCALATED-INVESTIGATED | severity={sev.upper()} | stage={stage} | mitre={mitre}",
        "processing_log": [log],
    }
