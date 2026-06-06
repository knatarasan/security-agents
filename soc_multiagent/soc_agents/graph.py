"""
LangGraph StateGraph definition for the SOC multi-agent pipeline.

Graph topology
──────────────
  START
    │
    ▼
  supervisor_node   ← validates alert, initialises state
    │
    ▼
  triage_node       ← LLM first-pass: FP/TP classification + confidence
    │
    ▼ (conditional edge — supervisor escalation rule)
    ├─── HIGH + likely TP ──▶  investigation_node  ← deep forensic + MITRE mapping
    │                                │
    └─── otherwise ──────────────────┤
                                     ▼
                               output_node   ← final_disposition string
                                     │
                                     ▼
                                    END

LLM selection
─────────────
Set MODEL_PROVIDER env var to "openai" (default) or "anthropic".
Credentials are read from OPENAI_API_KEY / ANTHROPIC_API_KEY.
"""

from __future__ import annotations

import os
from functools import partial
from typing import Any

from langgraph.graph import END, START, StateGraph

from soc_agents.agents.investigation import run_investigation
from soc_agents.agents.supervisor import run_output_node, run_supervisor_init
from soc_agents.agents.triage import run_triage
from soc_agents.state import SOCState


# ─── LLM factory ─────────────────────────────────────────────────────────────

def _build_llm() -> Any:
    """
    Instantiate the LLM based on MODEL_PROVIDER environment variable.

    Defaults to OpenAI gpt-4o-mini for low latency and cost.
    Set MODEL_PROVIDER=anthropic to use Claude 3.5 Haiku instead.
    """
    provider = os.getenv("MODEL_PROVIDER", "openai").strip().lower()

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic  # noqa: PLC0415

        return ChatAnthropic(
            model="claude-haiku-4-5-20251001",
            temperature=0.1,
            max_tokens=2048,
        )

    # Default: OpenAI
    from langchain_openai import ChatOpenAI  # noqa: PLC0415

    return ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0.1,
        max_tokens=2048,
    )


# ─── Routing function ─────────────────────────────────────────────────────────

def _route_after_triage(state: SOCState) -> str:
    """
    Conditional edge function evaluated after triage_node completes.

    Implements the supervisor escalation rule:
      - Route to investigation if triage flagged HIGH + likely TP
      - Otherwise route directly to output
    """
    if state.get("routing_decision") == "escalate_to_investigation":
        return "investigation_node"
    return "output_node"


# ─── Graph builder ────────────────────────────────────────────────────────────

def build_soc_graph() -> Any:
    """
    Construct and compile the LangGraph StateGraph.

    Nodes are registered with their LLM dependency injected via functools.partial
    so the graph itself stays stateless and can be safely reused across requests.

    Returns a compiled graph ready for .invoke() / .ainvoke() calls.
    """
    llm = _build_llm()

    # Bind LLM to agent node functions (LangGraph passes state as first arg)
    triage_with_llm = partial(run_triage, llm=llm)
    investigation_with_llm = partial(run_investigation, llm=llm)

    graph = StateGraph(SOCState)

    # ── Register nodes ──────────────────────────────────────────────────────
    graph.add_node("supervisor_node", run_supervisor_init)
    graph.add_node("triage_node", triage_with_llm)
    graph.add_node("investigation_node", investigation_with_llm)
    graph.add_node("output_node", run_output_node)

    # ── Define edges ────────────────────────────────────────────────────────
    graph.add_edge(START, "supervisor_node")
    graph.add_edge("supervisor_node", "triage_node")

    # Conditional edge: triage → (investigation | output)
    graph.add_conditional_edges(
        "triage_node",
        _route_after_triage,
        {
            "investigation_node": "investigation_node",
            "output_node": "output_node",
        },
    )

    graph.add_edge("investigation_node", "output_node")
    graph.add_edge("output_node", END)

    return graph.compile()


# ─── Mermaid diagram ──────────────────────────────────────────────────────────

def get_mermaid_diagram() -> str:
    """Return a Mermaid flowchart string describing the SOC pipeline graph."""
    return """\
graph TD
    A([START]) --> B

    B["🔵 supervisor_node<br/>Alert intake &amp; validation<br/><i>initialises state fields</i>"]
    B --> C

    C["🟡 triage_node<br/>LLM Tier-1 fast-pass analysis<br/><i>FP/TP classification + confidence</i>"]
    C --> D{Routing Decision<br/><i>supervisor escalation rule</i>}

    D -->|"HIGH severity<br/>+ likely TP<br/>→ escalate_to_investigation"| E
    D -->|"FP or non-HIGH TP<br/>→ close"| F

    E["🔴 investigation_node<br/>LLM deep forensic analysis<br/><i>MITRE ATT&CK mapping<br/>IOC extraction<br/>IR recommendations</i>"]
    E --> F

    F["🟢 output_node<br/>Final disposition<br/><i>human-readable summary</i>"]
    F --> G([END])

    style A fill:#6b7280,color:#fff,stroke:none
    style B fill:#3b82f6,color:#fff,stroke:none
    style C fill:#f59e0b,color:#fff,stroke:none
    style D fill:#8b5cf6,color:#fff,stroke:none
    style E fill:#ef4444,color:#fff,stroke:none
    style F fill:#10b981,color:#fff,stroke:none
    style G fill:#6b7280,color:#fff,stroke:none"""
