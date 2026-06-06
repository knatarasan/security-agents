"""
LangGraph shared state for the SOC multi-agent pipeline.

SOCState is the single TypedDict that flows through every node in the graph.
Each node receives the full current state and returns a partial dict of
fields to update.

The `processing_log` field uses an operator.add reducer so that each node
appends its own log entry rather than overwriting the list.
"""

from __future__ import annotations

import operator
from typing import Annotated, Optional, TypedDict


class SOCState(TypedDict):
    """Shared state passed between all SOC pipeline nodes."""

    # The raw alert dict as received from the SIEM
    alert: dict

    # Populated by triage_node — classification, confidence, recommendation
    triage_result: dict

    # Populated by investigation_node — only present for escalated alerts
    investigation_report: Optional[dict]

    # "escalate_to_investigation" | "close" | "pending"
    routing_decision: str

    # Human-readable summary of how the alert was ultimately handled
    final_disposition: str

    # Accumulated audit trail — each node appends its own entry
    processing_log: Annotated[list[str], operator.add]
