"""
Integration demo script.

Workflow:
  1. Reset the SIEM counter
  2. Fetch 20 alerts from the SIEM simulator (port 8081)
  3. Post each alert to the SOC pipeline (port 8082) with a concurrency cap
  4. Print a colour-coded rich table with triage and investigation results
  5. Print summary statistics

Run from the soc_multiagent/ directory:
    python demo.py

Both servers must be running before executing this script:
    uvicorn siem_simulator.main:app --port 8081
    uvicorn soc_agents.main:app    --port 8082
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

import httpx
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

SIEM_URL = "http://localhost:8081"
SOC_URL = "http://localhost:8082"
ALERT_COUNT = 20
MAX_CONCURRENCY = 4  # LLM-safe concurrency cap

console = Console()

# ─── Colour maps ─────────────────────────────────────────────────────────────

_SEV_STYLE = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "bold green"}
_GT_STYLE = {"TP": "bold red", "FP": "bold blue"}
_TRIAGE_STYLE = {"TP": "bold red", "FP": "green"}
_ROUTING_LABEL = {
    "escalate_to_investigation": ("ESCALATED", "bold red"),
    "close": ("CLOSED", "green"),
    "pending": ("PENDING", "dim"),
}
_SEVERITY_ASSESSMENT_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
}


# ─── HTTP helpers ─────────────────────────────────────────────────────────────

async def fetch_alerts(client: httpx.AsyncClient) -> list[dict]:
    resp = await client.post(f"{SIEM_URL}/alerts/reset")
    resp.raise_for_status()

    resp = await client.get(f"{SIEM_URL}/alerts", params={"count": ALERT_COUNT})
    resp.raise_for_status()
    data = resp.json()
    return data["alerts"]


async def process_alert(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    alert: dict,
    idx: int,
    total: int,
) -> dict:
    async with sem:
        console.print(
            f"  [dim]Processing {idx:>2}/{total}: "
            f"{alert['alert_id'][:8]}… "
            f"{alert['severity']:<6} {alert['category']}[/dim]"
        )
        resp = await client.post(
            f"{SOC_URL}/process-alert",
            json={"alert": alert},
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()


# ─── Table builder ────────────────────────────────────────────────────────────

def _sev_text(sev: str) -> Text:
    return Text(sev, style=_SEV_STYLE.get(sev, "white"))


def _gt_text(gt: str) -> Text:
    return Text(gt, style=_GT_STYLE.get(gt, "white"))


def _triage_text(cls: str) -> Text:
    return Text(cls, style=_TRIAGE_STYLE.get(cls, "white"))


def _conf_text(conf: float) -> Text:
    style = "bold red" if conf >= 0.8 else "yellow" if conf >= 0.5 else "green"
    return Text(f"{conf:.0%}", style=style)


def _routing_text(routing: str) -> Text:
    label, style = _ROUTING_LABEL.get(routing, (routing, "white"))
    return Text(label, style=style)


def _attack_stage_text(inv: dict | None) -> Text:
    if not inv:
        return Text("—", style="dim")
    stage = (inv.get("attack_stage") or "")[:18]
    sev_a = inv.get("severity_assessment", "high")
    style = _SEVERITY_ASSESSMENT_STYLE.get(sev_a, "white")
    return Text(stage, style=style)


def build_table(pairs: list[tuple[dict, dict]]) -> Table:
    t = Table(
        title="[bold cyan]SOC Multi-Agent Pipeline — Alert Processing Results[/bold cyan]",
        box=box.ROUNDED,
        header_style="bold magenta",
        show_lines=False,
        expand=True,
    )
    t.add_column("ID",          width=9,  no_wrap=True)
    t.add_column("Sev",         width=6)
    t.add_column("Category",    width=20)
    t.add_column("Ground\nTruth",width=7)
    t.add_column("Triage\nClass",width=7)
    t.add_column("Conf",        width=5)
    t.add_column("Routing",     width=11)
    t.add_column("Attack Stage",width=18)
    t.add_column("MITRE",       width=22)
    t.add_column("Disposition", width=32)

    for alert, result in pairs:
        triage = result.get("triage_result") or {}
        inv = result.get("investigation_report")
        routing = result.get("routing_decision", "close")
        mitre = (inv or {}).get("mitre_technique", "—")
        if len(mitre) > 22:
            mitre = mitre[:19] + "…"
        disp = result.get("final_disposition", "?")
        if len(disp) > 31:
            disp = disp[:28] + "…"

        t.add_row(
            alert.get("alert_id", "")[:8],
            _sev_text(alert.get("severity", "?")),
            alert.get("category", "?")[:19],
            _gt_text(alert.get("ground_truth", "?")),
            _triage_text(triage.get("likely_classification", "?")),
            _conf_text(triage.get("triage_confidence", 0.0)),
            _routing_text(routing),
            _attack_stage_text(inv),
            Text(mitre, style="cyan"),
            disp,
        )

    return t


# ─── Summary stats ────────────────────────────────────────────────────────────

def print_summary(pairs: list[tuple[dict, dict]]) -> None:
    total = len(pairs)
    actual_tp = sum(1 for a, _ in pairs if a.get("ground_truth") == "TP")
    actual_fp = sum(1 for a, _ in pairs if a.get("ground_truth") == "FP")
    triage_fp = sum(
        1 for _, r in pairs
        if (r.get("triage_result") or {}).get("likely_classification") == "FP"
    )
    triage_tp = sum(
        1 for _, r in pairs
        if (r.get("triage_result") or {}).get("likely_classification") == "TP"
    )
    escalated = sum(
        1 for _, r in pairs if r.get("routing_decision") == "escalate_to_investigation"
    )
    critical = sum(
        1 for _, r in pairs
        if (r.get("investigation_report") or {}).get("severity_assessment") == "critical"
    )
    high_inv = sum(
        1 for _, r in pairs
        if (r.get("investigation_report") or {}).get("severity_assessment") == "high"
    )

    # Accuracy: did triage match ground truth?
    correct = sum(
        1 for a, r in pairs
        if a.get("ground_truth") == (r.get("triage_result") or {}).get("likely_classification")
    )

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta")
    t.add_column("Metric", style="bold", min_width=35)
    t.add_column("Value", justify="right", min_width=10)

    t.add_row("Total alerts processed",              str(total))
    t.add_row("─" * 35,                              "─" * 10)
    t.add_row("Actual True Positives  (ground truth)", f"[red]{actual_tp}[/red]")
    t.add_row("Actual False Positives (ground truth)", f"[blue]{actual_fp}[/blue]")
    t.add_row("─" * 35,                              "─" * 10)
    t.add_row("Triage classified as TP",             f"[red]{triage_tp}[/red]")
    t.add_row("Triage classified as FP (closed)",    f"[green]{triage_fp}[/green]")
    t.add_row("Triage accuracy",                     f"[cyan]{correct}/{total} ({correct/total:.0%})[/cyan]")
    t.add_row("─" * 35,                              "─" * 10)
    t.add_row("Escalated for deep investigation",    f"[bold red]{escalated}[/bold red]")
    t.add_row("Findings: CRITICAL",                  f"[bold red]{critical}[/bold red]")
    t.add_row("Findings: HIGH",                      f"[red]{high_inv}[/red]")

    console.print(Panel(t, title="[bold cyan]Summary Statistics[/bold cyan]", expand=False))


def print_investigation_details(pairs: list[tuple[dict, dict]]) -> None:
    escalated = [(a, r) for a, r in pairs if r.get("routing_decision") == "escalate_to_investigation"]
    if not escalated:
        return

    console.print(Panel(
        f"[bold red]{len(escalated)} alert(s) escalated to investigation[/bold red]",
        title="[bold red]Escalated Alert Details[/bold red]",
        expand=False,
    ))

    for alert, result in escalated:
        inv = result.get("investigation_report") or {}
        sev_a = inv.get("severity_assessment", "unknown").upper()
        sev_style = _SEVERITY_ASSESSMENT_STYLE.get(sev_a.lower(), "white")
        console.print(
            f"\n  [bold]Alert[/bold] {alert.get('alert_id','')[:8]}…  "
            f"[{_SEV_STYLE.get(alert.get('severity',''),'white')}]{alert.get('severity')}[/] │ "
            f"{alert.get('category')} │ ground_truth=[{_GT_STYLE.get(alert.get('ground_truth',''),'white')}]{alert.get('ground_truth')}[/]"
        )
        console.print(f"  [yellow]MITRE:[/yellow]        {inv.get('mitre_technique','N/A')}")
        console.print(f"  [yellow]Attack Stage:[/yellow] {inv.get('attack_stage','N/A')}")
        console.print(f"  [yellow]Severity:[/yellow]     [{sev_style}]{sev_a}[/{sev_style}]")
        console.print(f"  [yellow]Threat Actor:[/yellow] {inv.get('threat_actor_profile','Unknown')}")
        console.print(f"  [yellow]Response:[/yellow]     {inv.get('recommended_response','N/A')}")
        iocs = inv.get("ioc_summary") or []
        console.print(f"  [yellow]IOCs:[/yellow]         {', '.join(iocs[:4])}")
        steps = inv.get("containment_steps") or []
        for i, step in enumerate(steps, 1):
            console.print(f"  [yellow]  Step {i}:[/yellow] {step}")
        console.print(f"  [yellow]Analyst Notes:[/yellow] {inv.get('analyst_notes','')[:200]}")


# ─── Main ─────────────────────────────────────────────────────────────────────

async def main() -> None:
    console.rule("[bold cyan]SOC Multi-Agent Demo[/bold cyan]")

    # ── Step 1: fetch alerts from SIEM ─────────────────────────────────────
    console.print("\n[bold]Step 1[/bold] — Fetching alerts from SIEM simulator…")
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            alerts = await fetch_alerts(client)
        except httpx.ConnectError:
            console.print("[bold red]ERROR:[/bold red] Cannot connect to SIEM at "
                          f"{SIEM_URL}. Is it running?")
            sys.exit(1)

    console.print(f"[green]✓ Received {len(alerts)} alerts[/green]")

    # ── Step 2: process each alert through the SOC pipeline ───────────────
    console.print(f"\n[bold]Step 2[/bold] — Processing {len(alerts)} alerts through SOC pipeline…\n")
    sem = asyncio.Semaphore(MAX_CONCURRENCY)

    async with httpx.AsyncClient(timeout=180) as client:
        # Verify the SOC server is reachable first
        try:
            health = await client.get(f"{SOC_URL}/pipeline/status")
            health.raise_for_status()
        except httpx.ConnectError:
            console.print("[bold red]ERROR:[/bold red] Cannot connect to SOC server at "
                          f"{SOC_URL}. Is it running?")
            sys.exit(1)

        tasks = [
            process_alert(client, sem, alert, i + 1, len(alerts))
            for i, alert in enumerate(alerts)
        ]
        results: list[dict] = await asyncio.gather(*tasks)

    pairs = list(zip(alerts, results))
    console.print(f"\n[green]✓ All {len(pairs)} alerts processed[/green]\n")

    # ── Step 3: display results table ─────────────────────────────────────
    console.print(build_table(pairs))

    # ── Step 4: summary stats ─────────────────────────────────────────────
    console.print()
    print_summary(pairs)

    # ── Step 5: investigation details ─────────────────────────────────────
    console.print()
    print_investigation_details(pairs)

    console.rule()


if __name__ == "__main__":
    asyncio.run(main())
