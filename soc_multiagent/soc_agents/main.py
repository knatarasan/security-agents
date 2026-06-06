"""
SOC Multi-Agent System — FastAPI server on port 8082.

Exposes the LangGraph SOC pipeline as a REST API.  The compiled graph is
built once at startup and reused across all requests.

Start with:
    uvicorn soc_agents.main:app --port 8082 --reload
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from soc_agents.graph import build_soc_graph, get_mermaid_diagram
from soc_agents.state import SOCState

# ─── Startup / shutdown ───────────────────────────────────────────────────────

_graph: Any = None
_stats: dict = {
    "total_processed": 0,
    "escalated": 0,
    "closed": 0,
    "critical_findings": 0,
}


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    """Build the LangGraph pipeline on startup."""
    global _graph
    _graph = build_soc_graph()
    yield
    # Nothing to clean up on shutdown


app = FastAPI(
    title="SOC Multi-Agent System",
    description=(
        "LangGraph-powered multi-agent SOC pipeline: "
        "Supervisor → Triage → (conditional) Investigation → Output"
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ─── Request / response models ────────────────────────────────────────────────

class AlertRequest(BaseModel):
    alert: dict


class BatchRequest(BaseModel):
    alerts: list[dict]


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _initial_state(alert: dict) -> SOCState:
    """Create a clean initial SOCState for a new alert."""
    return SOCState(
        alert=alert,
        triage_result={},
        investigation_report=None,
        routing_decision="pending",
        final_disposition="pending",
        processing_log=[],
    )


def _update_stats(result: dict) -> None:
    """Increment global counters based on pipeline outcome."""
    _stats["total_processed"] += 1
    if result.get("routing_decision") == "escalate_to_investigation":
        _stats["escalated"] += 1
    else:
        _stats["closed"] += 1
    inv = result.get("investigation_report") or {}
    if inv.get("severity_assessment") == "critical":
        _stats["critical_findings"] += 1


def _run_graph(alert: dict) -> dict:
    """Synchronous graph execution — called inside a thread via asyncio.to_thread."""
    result = _graph.invoke(_initial_state(alert))
    _update_stats(result)
    return dict(result)


# ─── Endpoints ───────────────────────────────────────────────────────────────

@app.post(
    "/process-alert",
    summary="Run a single alert through the full SOC pipeline",
    response_description="Completed SOCState with triage, routing, and optional investigation",
)
async def process_alert(request: AlertRequest) -> dict:
    """
    Process one alert through the LangGraph pipeline.

    The graph is invoked in a thread pool so the FastAPI event loop is not
    blocked by synchronous LLM calls.
    """
    if _graph is None:
        raise HTTPException(status_code=503, detail="Pipeline not yet initialised.")
    try:
        result = await asyncio.to_thread(_run_graph, request.alert)
        return result
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Pipeline error: {exc}") from exc


@app.post(
    "/process-batch",
    summary="Process a list of alerts sequentially",
    response_description="List of completed SOCState dicts plus error list",
)
async def process_batch(request: BatchRequest) -> dict:
    """
    Process multiple alerts.  Alerts are run sequentially to avoid
    overwhelming the upstream LLM API with concurrent requests.
    Failed alerts are collected in 'errors' rather than aborting the batch.
    """
    if _graph is None:
        raise HTTPException(status_code=503, detail="Pipeline not yet initialised.")

    results: list[dict] = []
    errors: list[dict] = []

    for alert in request.alerts:
        try:
            result = await asyncio.to_thread(_run_graph, alert)
            results.append(result)
        except Exception as exc:  # noqa: BLE001
            errors.append({"alert_id": alert.get("alert_id"), "error": str(exc)})

    return {
        "results": results,
        "errors": errors,
        "processed": len(results),
        "failed": len(errors),
    }


@app.get("/pipeline/status", summary="Pipeline health and processing statistics")
def pipeline_status() -> dict:
    """Return current pipeline health and running counters."""
    return {
        "status": "healthy" if _graph is not None else "initialising",
        "graph_initialised": _graph is not None,
        "stats": _stats,
    }


@app.get("/pipeline/visualize", summary="Return Mermaid diagram of the LangGraph")
def pipeline_visualize() -> dict:
    """Return a Mermaid flowchart string that can be pasted into mermaid.live."""
    return {"mermaid": get_mermaid_diagram()}
