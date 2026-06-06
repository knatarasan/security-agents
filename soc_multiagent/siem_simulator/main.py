"""
SIEM Alert Simulator — FastAPI server on port 8081.

Simulates a Security Information and Event Management system emitting
security alerts with realistic statistical distributions.

Start with:
    uvicorn siem_simulator.main:app --port 8081 --reload
"""

from __future__ import annotations

import asyncio
import json
from typing import Annotated

from fastapi import FastAPI, Query
from fastapi.responses import StreamingResponse

from siem_simulator.alert_generator import generate_alert

# ─── App ─────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SIEM Alert Simulator",
    description="Simulated SIEM that emits security alerts with configurable distributions.",
    version="1.0.0",
)

MAX_ALERTS = 100

# In-memory counters — reset with POST /alerts/reset
_state: dict = {
    "alert_counter": 0,
    "total_emitted": 0,
    "severity": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
    "ground_truth": {"FP": 0, "TP": 0},
    "severity_class": {"routine": 0, "severe": 0},
}


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _record(alert: dict) -> None:
    """Update running counters after generating an alert."""
    _state["total_emitted"] += 1
    _state["alert_counter"] += 1
    _state["severity"][alert["severity"]] += 1
    _state["ground_truth"][alert["ground_truth"]] += 1
    if sc := alert.get("severity_class"):
        _state["severity_class"][sc] += 1


def _make_alert() -> dict | None:
    """Generate one alert if quota allows, else return None."""
    if _state["alert_counter"] >= MAX_ALERTS:
        return None
    a = generate_alert()
    _record(a)
    return a


# ─── Endpoints ───────────────────────────────────────────────────────────────

@app.get(
    "/alerts",
    summary="Return N random alerts",
    response_description="List of alert objects",
)
def get_alerts(
    count: Annotated[int, Query(ge=1, le=MAX_ALERTS, description="Number of alerts to generate")] = 10,
) -> dict:
    """
    Return up to *count* randomly generated alerts (hard-capped at 100 total
    since the last reset).  Alerts remaining to the cap may be fewer than
    requested.
    """
    alerts: list[dict] = []
    for _ in range(count):
        a = _make_alert()
        if a is None:
            break
        alerts.append(a)
    return {"alerts": alerts, "count": len(alerts), "remaining_quota": MAX_ALERTS - _state["alert_counter"]}


@app.get(
    "/alerts/stream",
    summary="SSE stream — one alert every 2 seconds",
    response_class=StreamingResponse,
)
async def stream_alerts() -> StreamingResponse:
    """
    Server-Sent Events endpoint.  Emits one alert every 2 seconds until the
    100-alert quota is exhausted, then sends a completion event.
    """

    async def _gen():
        while _state["alert_counter"] < MAX_ALERTS:
            a = _make_alert()
            if a is None:
                break
            yield f"data: {json.dumps(a)}\n\n"
            await asyncio.sleep(2)
        yield (
            f"data: {json.dumps({'event': 'stream_complete', 'total_emitted': _state['total_emitted']})}\n\n"
        )

    return StreamingResponse(_gen(), media_type="text/event-stream")


@app.get("/alerts/stats", summary="Return distribution summary")
def get_stats() -> dict:
    """Return current emission counts and percentage distributions."""
    total = max(_state["total_emitted"], 1)
    tp_total = max(_state["ground_truth"]["TP"], 1)

    return {
        "total_emitted": _state["total_emitted"],
        "alert_counter": _state["alert_counter"],
        "max_alerts": MAX_ALERTS,
        "severity_distribution": {
            sev: {
                "count": cnt,
                "pct": round(cnt / total * 100, 1),
            }
            for sev, cnt in _state["severity"].items()
        },
        "ground_truth_distribution": {
            gt: {
                "count": cnt,
                "pct": round(cnt / total * 100, 1),
            }
            for gt, cnt in _state["ground_truth"].items()
        },
        "tp_breakdown": {
            cls: {
                "count": cnt,
                "pct": round(cnt / tp_total * 100, 1),
            }
            for cls, cnt in _state["severity_class"].items()
        },
    }


@app.post("/alerts/reset", summary="Reset alert counter and statistics")
def reset_alerts() -> dict:
    """Reset all counters so a fresh run of 100 alerts can begin."""
    _state["alert_counter"] = 0
    _state["total_emitted"] = 0
    _state["severity"] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    _state["ground_truth"] = {"FP": 0, "TP": 0}
    _state["severity_class"] = {"routine": 0, "severe": 0}
    return {"status": "reset", "message": "Alert counter and statistics have been reset."}
