"""
Supervisor Agent — alert intake, validation, and final output formatting.

The supervisor appears twice in the pipeline lifecycle:
  1. supervisor_node (graph entry): validates the incoming alert, initialises
     state fields, and writes the first processing log entry.
  2. output_node (graph exit): reads the final triage/investigation results
     and writes a human-readable final_disposition string.

The supervisor's *escalation decision* is embedded in triage_node because
that decision depends on triage_result which does not exist yet when the
supervisor first runs.  The routing logic is documented in triage.py.
"""

from __future__ import annotations

from datetime import datetime, timezone

from soc_agents.state import SOCState

# Fields that every valid SIEM alert must contain
_REQUIRED_FIELDS = [
    "alert_id", "severity", "category",
    "source_ip", "destination_ip", "hostname", "user",
    "rule_name", "raw_log",
]


def run_supervisor_init(state: SOCState) -> dict:
    """
    Entry node — validate alert and initialise processing state.

    Returns partial state updates: routing_decision, final_disposition,
    investigation_report, triage_result, and the first processing_log entry.
    """
    alert = state["alert"]

    missing = [f for f in _REQUIRED_FIELDS if not alert.get(f)]
    warn = f" | WARNING missing fields: {missing}" if missing else ""

    init_log = (
        f"[SUPERVISOR-INIT] alert_id={alert.get('alert_id', 'unknown')[:8]} "
        f"severity={alert.get('severity')} category={alert.get('category')} "
        f"received_at={datetime.now(timezone.utc).isoformat()}{warn}"
    )

    return {
        "routing_decision": "pending",
        "final_disposition": "pending",
        "investigation_report": None,
        "triage_result": {},
        "processing_log": [init_log],  # operator.add reducer appends this
    }


def run_output_node(state: SOCState) -> dict:
    """
    Exit node — compute the human-readable final_disposition string.

    Examines triage_result and (optionally) investigation_report to produce
    a one-line summary of how the alert was handled.
    """
    triage = state.get("triage_result", {})
    investigation = state.get("investigation_report")
    routing = state.get("routing_decision", "close")

    if investigation:
        sev = investigation.get("severity_assessment", "unknown").upper()
        stage = investigation.get("attack_stage", "Unknown")
        mitre = investigation.get("mitre_technique", "N/A")
        final_disposition = (
            f"ESCALATED-INVESTIGATED | severity={sev} | stage={stage} | mitre={mitre}"
        )
    elif triage.get("likely_classification") == "TP":
        conf = triage.get("triage_confidence", 0)
        sev = state["alert"].get("severity", "?")
        final_disposition = (
            f"CLOSED-MONITORED | TP below escalation threshold "
            f"(severity={sev}, confidence={conf:.0%})"
        )
    else:
        conf = triage.get("triage_confidence", 0)
        final_disposition = f"CLOSED-FP | false positive (confidence={conf:.0%})"

    close_log = f"[OUTPUT] final_disposition={final_disposition}"

    return {
        "final_disposition": final_disposition,
        "processing_log": [close_log],
    }
