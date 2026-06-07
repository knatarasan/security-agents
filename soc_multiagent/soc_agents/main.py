"""
SOC Multi-Agent System — FastAPI server on port 8082.

Enhanced with CopilotKit for live streaming dashboard support.
Exposes the LangGraph SOC pipeline as a REST API.

The compiled graph and CopilotKit endpoint are registered at module load so
there is no startup race between lifespan and route registration.

Start with:
    uvicorn soc_agents.main:app --port 8082 --reload
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from soc_agents.graph import build_soc_graph, get_mermaid_diagram
from soc_agents.state import SOCState

# ─── CopilotKit — correct class names for v0.1.94+ ───────────────────────────
# v0.1.31+: CopilotKitSDK → CopilotKitRemoteEndpoint
# v0.1.94+: LangGraphAgent → LangGraphAGUIAgent

COPILOT_AGENT_NAME = "soc_pipeline"

_COPILOTKIT_AVAILABLE = False
try:
    from copilotkit import CopilotKitRemoteEndpoint, LangGraphAGUIAgent  # noqa: PLC0415
    from copilotkit.integrations.fastapi import add_fastapi_endpoint  # noqa: PLC0415
    from langgraph.checkpoint.memory import MemorySaver  # noqa: PLC0415

    _COPILOTKIT_AVAILABLE = True
except ImportError:
    pass

# ─── Build graph at module level ──────────────────────────────────────────────
# Building here (not in lifespan) ensures the CopilotKit endpoint is registered
# before any request arrives and avoids the lifespan/route-registration race.

_checkpointer = MemorySaver() if _COPILOTKIT_AVAILABLE else None  # type: ignore[name-defined]
_graph: Any = build_soc_graph(checkpointer=_checkpointer)

_stats: dict = {
    "total_processed": 0,
    "escalated": 0,
    "closed": 0,
    "critical_findings": 0,
}

# ─── Persistent data files ────────────────────────────────────────────────────

_DATA_DIR = Path(__file__).parent.parent / "data"
_DATA_DIR.mkdir(exist_ok=True)

_CORRECTIONS_FILE = _DATA_DIR / "corrections.json"
_ACTIONS_LOG_FILE = _DATA_DIR / "actions_log.json"
_TICKETS_FILE = _DATA_DIR / "tickets.json"
_BLOCKED_IPS_FILE = _DATA_DIR / "blocked_ips.json"


def _read_json(path: Path) -> list:
    if not path.exists():
        return []
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _append_json(path: Path, item: dict) -> None:
    data = _read_json(path)
    data.append(item)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def _calculate_triage_weight(corrections: list) -> float:
    """Derive triage confidence weight from analyst correction history."""
    if not corrections:
        return 1.0
    fp_count = sum(1 for c in corrections if c.get("analyst_classification") == "FP")
    tp_count = sum(1 for c in corrections if c.get("analyst_classification") == "TP")
    total = len(corrections)
    bias = (tp_count - fp_count) / total
    adj_avg = sum(float(c.get("confidence_adjustment", 0)) for c in corrections) / total
    weight = 1.0 + bias * 0.1 + adj_avg * 0.05
    return round(max(0.5, min(2.0, weight)), 4)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SOC Multi-Agent System",
    description=(
        "LangGraph-powered multi-agent SOC pipeline: "
        "Supervisor → Triage → (conditional) Investigation → Output"
    ),
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── CopilotKit endpoint (registered at module level, not in lifespan) ────────

if _COPILOTKIT_AVAILABLE:
    _sdk = CopilotKitRemoteEndpoint(  # type: ignore[name-defined]
        agents=[
            LangGraphAGUIAgent(  # type: ignore[name-defined]
                name=COPILOT_AGENT_NAME,
                description=(
                    "SOC multi-agent security alert triage and investigation pipeline. "
                    "Processes alerts through Supervisor → Triage → Investigation nodes."
                ),
                graph=_graph,
            )
        ]
    )
    add_fastapi_endpoint(app, _sdk, "/copilotkit")  # type: ignore[name-defined]


@app.middleware("http")
async def normalise_copilotkit_info_response(request: Request, call_next):
    """Key CopilotKit info agents by name for the React runtime client."""
    response = await call_next(request)
    if request.url.path.rstrip("/") != "/copilotkit" or response.status_code != 200:
        return response

    content_type = response.headers.get("content-type", "")
    if "application/json" not in content_type:
        return response

    body = b"".join([chunk async for chunk in response.body_iterator])
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        headers = dict(response.headers)
        headers.pop("content-length", None)
        return Response(
            content=body,
            status_code=response.status_code,
            headers=headers,
            media_type=content_type,
            background=response.background,
        )

    agents = payload.get("agents") if isinstance(payload, dict) else None
    if isinstance(agents, list):
        keyed_agents = {}
        for index, agent in enumerate(agents):
            if not isinstance(agent, dict):
                continue
            agent_id = str(agent.get("name") or agent.get("agentId") or index)
            keyed_agents[agent_id] = {**agent, "agentId": agent_id}
        payload = {**payload, "agents": keyed_agents}
        body = json.dumps(payload).encode("utf-8")

    headers = dict(response.headers)
    headers.pop("content-length", None)
    return Response(
        content=body,
        status_code=response.status_code,
        headers=headers,
        media_type="application/json",
        background=response.background,
    )


# ─── Request / response models ────────────────────────────────────────────────

class AlertRequest(BaseModel):
    alert: dict


class BatchRequest(BaseModel):
    alerts: list[dict]


class IsolateRequest(BaseModel):
    hostname: str
    alert_id: str


class TicketRequest(BaseModel):
    priority: str  # P1 | P2 | P3
    summary: str
    alert_id: str


class BlockIPRequest(BaseModel):
    ip: str
    reason: str
    alert_id: str


class OverrideRequest(BaseModel):
    alert_id: str
    original_classification: str
    analyst_classification: str  # FP | TP
    analyst_reasoning: str
    confidence_adjustment: float = 0.0


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


# ─── Existing pipeline endpoints ──────────────────────────────────────────────

@app.post(
    "/process-alert",
    summary="Run a single alert through the full SOC pipeline",
    response_description="Completed SOCState with triage, routing, and optional investigation",
)
async def process_alert(request: AlertRequest) -> dict:
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
    return {
        "status": "healthy",
        "graph_initialised": True,
        "copilotkit_enabled": _COPILOTKIT_AVAILABLE,
        "stats": _stats,
    }


@app.get("/pipeline/visualize", summary="Return Mermaid diagram of the LangGraph")
def pipeline_visualize() -> dict:
    return {"mermaid": get_mermaid_diagram()}


# ─── Response action endpoints ────────────────────────────────────────────────

@app.post("/response/isolate", summary="Request host isolation and create P1 ticket")
async def isolate_host(body: IsolateRequest) -> dict:
    ticket_id = f"INC-{uuid.uuid4().hex[:6].upper()}"
    entry = {
        "action": "isolate",
        "hostname": body.hostname,
        "alert_id": body.alert_id,
        "ticket_id": ticket_id,
        "timestamp": _now(),
        "status": "queued",
    }
    _append_json(_ACTIONS_LOG_FILE, entry)
    _append_json(_TICKETS_FILE, {
        **entry,
        "priority": "P1",
        "summary": f"Host isolation request: {body.hostname}",
    })
    return {
        "status": "queued",
        "ticket_id": ticket_id,
        "message": f"Isolation request for {body.hostname} queued as {ticket_id}.",
    }


@app.post("/response/ticket", summary="Create an incident ticket")
async def create_ticket(body: TicketRequest) -> dict:
    ticket_id = f"INC-{uuid.uuid4().hex[:6].upper()}"
    entry = {
        "action": "ticket",
        "ticket_id": ticket_id,
        "priority": body.priority,
        "summary": body.summary,
        "alert_id": body.alert_id,
        "timestamp": _now(),
        "status": "open",
    }
    _append_json(_ACTIONS_LOG_FILE, entry)
    _append_json(_TICKETS_FILE, entry)
    return {"status": "created", "ticket_id": ticket_id, "priority": body.priority}


@app.post("/response/block-ip", summary="Block an IP address at perimeter firewall")
async def block_ip(body: BlockIPRequest) -> dict:
    blocked = _read_json(_BLOCKED_IPS_FILE)
    if any(b["ip"] == body.ip for b in blocked):
        return {"status": "already_blocked", "ip": body.ip}
    ticket_id = f"BLK-{uuid.uuid4().hex[:6].upper()}"
    entry = {
        "action": "block_ip",
        "ip": body.ip,
        "reason": body.reason,
        "alert_id": body.alert_id,
        "ticket_id": ticket_id,
        "timestamp": _now(),
    }
    _append_json(_ACTIONS_LOG_FILE, entry)
    _append_json(_BLOCKED_IPS_FILE, entry)
    return {"status": "blocked", "ip": body.ip, "ticket_id": ticket_id}


@app.get("/response/actions-log", summary="Return all recorded response actions")
async def get_actions_log() -> dict:
    return {
        "actions": _read_json(_ACTIONS_LOG_FILE),
        "blocked_ips": _read_json(_BLOCKED_IPS_FILE),
        "tickets": _read_json(_TICKETS_FILE),
    }


# ─── Analyst feedback endpoints ───────────────────────────────────────────────

@app.post("/analyst/override", summary="Record analyst classification override")
async def analyst_override(body: OverrideRequest) -> dict:
    corrections = _read_json(_CORRECTIONS_FILE)
    entry = {
        "alert_id": body.alert_id,
        "original_classification": body.original_classification,
        "analyst_classification": body.analyst_classification,
        "analyst_reasoning": body.analyst_reasoning,
        "confidence_adjustment": body.confidence_adjustment,
        "timestamp": _now(),
    }
    _append_json(_CORRECTIONS_FILE, entry)
    corrections.append(entry)
    return {
        "status": "recorded",
        "correction_id": f"COR-{uuid.uuid4().hex[:6].upper()}",
        "new_triage_weight": _calculate_triage_weight(corrections),
        "total_corrections": len(corrections),
    }


@app.get("/analyst/corrections", summary="Return all analyst correction history")
async def get_corrections() -> dict:
    corrections = _read_json(_CORRECTIONS_FILE)
    return {
        "corrections": corrections,
        "total": len(corrections),
        "triage_weight": _calculate_triage_weight(corrections),
    }
