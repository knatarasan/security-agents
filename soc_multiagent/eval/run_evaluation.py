"""
SOC Multi-Agent Pipeline — Evaluation with W&B Weave + wandb.

What this script does
─────────────────────
1. Fetches alerts from the SIEM simulator (or generates them locally if the
   server is not running, or loads a previously saved dataset).
2. Initialises W&B Weave — this auto-patches LangChain/OpenAI/Anthropic so
   every LLM prompt, completion, token count, and latency is traced.
3. Runs weave.Evaluation, which calls predict_alert() on every row, applies
   five scorers, and surfaces per-sample traces in the Weave UI.
4. Collects all predictions (via a side-channel list keyed on alert_id).
5. Computes aggregate metrics and logs them to a standard wandb run:
     - Scalar metrics  (accuracy, FNR, precision, recall, latency…)
     - Confusion matrix
     - Per-alert results table
     - Per-category accuracy table
     - Confidence calibration table

Usage
─────
# Both servers running:
    python -m eval.run_evaluation --count 50

# Offline (no servers):
    python -m eval.run_evaluation --count 50 --offline

# Reproduce a previous run:
    python -m eval.run_evaluation --load-dataset eval/last_dataset.json

Env vars required
─────────────────
  OPENAI_API_KEY   or  ANTHROPIC_API_KEY  (set MODEL_PROVIDER accordingly)
  WANDB_API_KEY    (or run `wandb login` once in the terminal)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional

# ── Resolve project root so imports work when called as `python -m eval.run_evaluation`
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))

from dotenv import load_dotenv

load_dotenv(_ROOT / ".env")

import wandb
import weave
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from eval.scorers import (
    confidence_calibration_scorer,
    escalation_quality_scorer,
    false_negative_scorer,
    investigation_quality_scorer,
    triage_accuracy_scorer,
)
from soc_agents.graph import build_soc_graph
from soc_agents.state import SOCState

console = Console()

# ─── Pipeline singleton ───────────────────────────────────────────────────────

_graph = None


def _get_graph():
    global _graph
    if _graph is None:
        _graph = build_soc_graph()
    return _graph


def _initial_state(alert: dict) -> SOCState:
    return SOCState(
        alert=alert,
        triage_result={},
        investigation_report=None,
        routing_decision="pending",
        final_disposition="pending",
        processing_log=[],
    )


# ─── Side-channel result collector ───────────────────────────────────────────
# weave.Evaluation calls predict_alert() for each row and passes only the
# return value to scorers.  We also need the full prediction for wandb tables,
# so we stash each result here keyed on alert_id.

_predictions: list[dict] = []


# ─── Weave-traced prediction function ────────────────────────────────────────

@weave.op()
async def predict_alert(alert: dict) -> dict:
    """
    Run one alert through the full SOC pipeline.

    This is the root weave trace.  Because weave.init() was called before
    this runs, all nested LangChain chain steps and LLM API calls are
    automatically captured as child spans — no additional decoration needed
    in triage.py or investigation.py.
    """
    t0 = time.perf_counter()
    try:
        result = await asyncio.to_thread(_get_graph().invoke, _initial_state(alert))
        latency_ms = round((time.perf_counter() - t0) * 1000, 1)

        triage = result.get("triage_result") or {}
        inv = result.get("investigation_report") or {}

        prediction = {
            "alert_id": alert.get("alert_id", ""),
            # Triage fields
            "triage_classification": triage.get("likely_classification", "FP"),
            "triage_confidence": round(float(triage.get("triage_confidence", 0.5)), 3),
            "triage_summary": triage.get("triage_summary", ""),
            "key_indicators": triage.get("key_indicators", []),
            # Routing
            "routing_decision": result.get("routing_decision", "close"),
            # Investigation fields (None when not escalated)
            "severity_assessment": inv.get("severity_assessment"),
            "mitre_technique": inv.get("mitre_technique"),
            "attack_stage": inv.get("attack_stage"),
            "recommended_response": inv.get("recommended_response"),
            "threat_actor_profile": inv.get("threat_actor_profile"),
            # Metadata
            "final_disposition": result.get("final_disposition", ""),
            "latency_ms": latency_ms,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        prediction = {
            "alert_id": alert.get("alert_id", ""),
            "triage_classification": "FP",
            "triage_confidence": 0.0,
            "triage_summary": "",
            "key_indicators": [],
            "routing_decision": "close",
            "severity_assessment": None,
            "mitre_technique": None,
            "attack_stage": None,
            "recommended_response": None,
            "threat_actor_profile": None,
            "final_disposition": f"PIPELINE_ERROR: {exc}",
            "latency_ms": latency_ms,
            "error": str(exc),
        }

    _predictions.append(prediction)
    return prediction


# ─── Dataset helpers ──────────────────────────────────────────────────────────

def _fetch_from_siem(count: int, siem_url: str) -> list[dict]:
    """Pull fresh alerts from the running SIEM server."""
    import httpx

    with httpx.Client(timeout=30) as client:
        client.post(f"{siem_url}/alerts/reset")
        resp = client.get(f"{siem_url}/alerts", params={"count": count})
        resp.raise_for_status()
    return resp.json()["alerts"]


def _generate_locally(count: int) -> list[dict]:
    """Generate alerts in-process (no server required)."""
    from siem_simulator.alert_generator import generate_alert

    return [generate_alert() for _ in range(count)]


def _alerts_to_dataset(alerts: list[dict]) -> list[dict]:
    """
    Convert raw SIEM alerts to evaluation dataset rows.

    ground_truth and severity_class are stripped from the `alert` field
    (they would leak labels to the LLM), but kept as top-level columns
    so weave can pass them to scorers by name.
    """
    _hidden = {"ground_truth", "severity_class"}
    return [
        {
            "alert": {k: v for k, v in a.items() if k not in _hidden},
            "ground_truth": a["ground_truth"],
            "severity_class": a.get("severity_class"),  # None for FP rows
        }
        for a in alerts
    ]


def _save_dataset(dataset: list[dict], path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(dataset, f, indent=2, default=str)


def _load_dataset(path: str) -> list[dict]:
    with open(path) as f:
        return json.load(f)


# ─── Aggregate metric computation ────────────────────────────────────────────

def _compute_metrics(
    dataset: list[dict],
    preds_by_id: dict[str, dict],
) -> tuple[dict, list[dict]]:
    """
    Compute aggregate evaluation metrics and build a per-alert detail list.

    Returns
    -------
    metrics : flat dict ready for wandb.log()
    detailed : list of per-alert dicts for wandb.Table
    """
    # Rolling counters
    n = tp_total = fp_total = fn = fp_esc = tp_esc = sv_total = sv_esc = correct = 0
    latencies: list[float] = []
    cat_correct: dict[str, int] = defaultdict(int)
    cat_total: dict[str, int] = defaultdict(int)
    sev_correct: dict[str, int] = defaultdict(int)
    sev_total: dict[str, int] = defaultdict(int)
    # confidence bucket → {correct, total}
    cal_buckets: dict[float, dict] = defaultdict(lambda: {"correct": 0, "total": 0})

    detailed: list[dict] = []

    for row in dataset:
        alert = row["alert"]
        gt = row["ground_truth"]
        sc = row.get("severity_class")
        pred = preds_by_id.get(alert.get("alert_id", ""))
        if pred is None:
            continue

        n += 1
        pred_cls = pred["triage_classification"]
        conf = pred["triage_confidence"]
        routing = pred["routing_decision"]
        escalated = routing == "escalate_to_investigation"
        cat = alert.get("category", "unknown")
        sev = alert.get("severity", "UNKNOWN")
        is_correct = pred_cls == gt
        lat = pred.get("latency_ms", 0.0)

        # Aggregate
        correct += int(is_correct)
        latencies.append(lat)
        if gt == "TP":
            tp_total += 1
            fn += int(pred_cls == "FP")            # missed attack
            tp_esc += int(escalated)
            if sc == "severe":
                sv_total += 1
                sv_esc += int(escalated)
        else:
            fp_total += 1
            fp_esc += int(escalated)

        cat_correct[cat] += int(is_correct)
        cat_total[cat] += 1
        sev_correct[sev] += int(is_correct)
        sev_total[sev] += 1

        bucket = round(conf * 10) / 10
        cal_buckets[bucket]["correct"] += int(is_correct)
        cal_buckets[bucket]["total"] += 1

        detailed.append({
            "alert_id": alert.get("alert_id", "")[:8],
            "severity": sev,
            "category": cat,
            "ground_truth": gt,
            "severity_class": sc or "—",
            "triage_classification": pred_cls,
            "triage_confidence": conf,
            "correct": is_correct,
            "routing_decision": routing,
            "attack_stage": pred.get("attack_stage") or "—",
            "mitre_technique": (pred.get("mitre_technique") or "—")[:35],
            "severity_assessment": pred.get("severity_assessment") or "—",
            "latency_ms": lat,
            "error": pred.get("error") or "—",
        })

    def _pct(num, denom):
        return round(num / denom, 4) if denom else 0.0

    metrics: dict = {
        # Core metrics
        "eval/n_alerts": n,
        "eval/accuracy": _pct(correct, n),
        "eval/false_negative_rate": _pct(fn, tp_total),
        "eval/fp_escalation_rate": _pct(fp_esc, fp_total),
        "eval/escalation_precision": _pct(tp_esc, tp_esc + fp_esc),
        "eval/escalation_recall": _pct(tp_esc, tp_total),
        "eval/severe_tp_recall": _pct(sv_esc, sv_total),
        "eval/mean_latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else 0,
        "eval/p95_latency_ms": round(sorted(latencies)[int(len(latencies) * 0.95)], 1) if latencies else 0,
        # Raw counts
        "counts/total": n,
        "counts/tp_total": tp_total,
        "counts/fp_total": fp_total,
        "counts/missed_attacks_fn": fn,
        "counts/tp_escalated": tp_esc,
        "counts/fp_escalated": fp_esc,
        "counts/severe_total": sv_total,
        "counts/severe_caught": sv_esc,
        # Per-category accuracy
        **{
            f"category_accuracy/{cat}": _pct(cat_correct[cat], cat_total[cat])
            for cat in cat_total
        },
        # Per-severity accuracy
        **{
            f"severity_accuracy/{sev}": _pct(sev_correct[sev], sev_total[sev])
            for sev in sev_total
        },
        # Confidence calibration buckets (0.0 – 1.0 in 0.1 steps)
        **{
            f"conf_calibration/bucket_{int(b * 10)}": (
                _pct(v["correct"], v["total"]) if v["total"] else None
            )
            for b, v in sorted(cal_buckets.items())
        },
    }

    # Remove None values (empty calibration buckets) before wandb.log
    metrics = {k: v for k, v in metrics.items() if v is not None}
    return metrics, detailed


# ─── wandb logging ────────────────────────────────────────────────────────────

def _log_to_wandb(metrics: dict, detailed: list[dict]) -> None:
    """Log scalar metrics, tables, and plots to the active wandb run."""

    # 1. Scalar metrics
    wandb.log(metrics)

    # 2. Confusion matrix — wandb expects integer indices into class_names, not strings
    _cm_classes = ["FP", "TP"]
    _cm_map = {c: i for i, c in enumerate(_cm_classes)}
    y_true_idx = [_cm_map[r["ground_truth"]] for r in detailed]
    y_pred_idx = [_cm_map[r["triage_classification"]] for r in detailed]
    wandb.log({
        "confusion_matrix": wandb.plot.confusion_matrix(
            y_true=y_true_idx,
            preds=y_pred_idx,
            class_names=_cm_classes,
        )
    })

    # 3. Per-alert results table
    cols = list(detailed[0].keys()) if detailed else []
    alert_table = wandb.Table(columns=cols)
    for row in detailed:
        alert_table.add_data(*[row[c] for c in cols])
    wandb.log({"per_alert_results": alert_table})

    # 4. Per-category accuracy table
    cat_agg: dict[str, dict] = defaultdict(lambda: {"correct": 0, "total": 0})
    for r in detailed:
        cat_agg[r["category"]]["correct"] += int(r["correct"])
        cat_agg[r["category"]]["total"] += 1

    cat_table = wandb.Table(columns=["category", "correct", "total", "accuracy_pct"])
    for cat, d in sorted(cat_agg.items()):
        acc = d["correct"] / d["total"] if d["total"] else 0
        cat_table.add_data(cat, d["correct"], d["total"], round(acc * 100, 1))
    wandb.log({"category_accuracy": cat_table})

    # 5. Confidence calibration scatter (confidence → correctness fraction per bucket)
    cal_agg: dict[float, dict] = defaultdict(lambda: {"correct": 0, "total": 0})
    for r in detailed:
        b = round(float(r["triage_confidence"]) * 10) / 10
        cal_agg[b]["correct"] += int(r["correct"])
        cal_agg[b]["total"] += 1
    cal_table = wandb.Table(columns=["confidence_bucket", "accuracy", "n_samples"])
    for b in sorted(cal_agg):
        d = cal_agg[b]
        acc = d["correct"] / d["total"] if d["total"] else 0
        cal_table.add_data(round(b, 1), round(acc, 3), d["total"])
    wandb.log({"confidence_calibration": cal_table})

    # 6. Latency distribution
    lat_table = wandb.Table(
        columns=["latency_ms", "severity", "routing_decision"],
        data=[[r["latency_ms"], r["severity"], r["routing_decision"]] for r in detailed],
    )
    wandb.log({"latency_distribution": lat_table})

    # 7. Key metrics summary table
    key_rows = [
        ("Triage Accuracy",       f"{metrics.get('eval/accuracy', 0):.1%}",          "FP/TP classification"),
        ("False Negative Rate",   f"{metrics.get('eval/false_negative_rate', 0):.1%}","← lower is better"),
        ("FP Escalation Rate",    f"{metrics.get('eval/fp_escalation_rate', 0):.1%}", "wasted investigations"),
        ("Escalation Precision",  f"{metrics.get('eval/escalation_precision', 0):.1%}","escalated = real TP"),
        ("Escalation Recall",     f"{metrics.get('eval/escalation_recall', 0):.1%}",  "TPs that get escalated"),
        ("Severe TP Recall",      f"{metrics.get('eval/severe_tp_recall', 0):.1%}",   "critical attacks caught"),
        ("Mean Latency",          f"{metrics.get('eval/mean_latency_ms', 0):.0f} ms", "pipeline wall time"),
        ("P95 Latency",           f"{metrics.get('eval/p95_latency_ms', 0):.0f} ms",  ""),
    ]
    summary_table = wandb.Table(columns=["metric", "value", "notes"], data=key_rows)
    wandb.log({"metrics_summary": summary_table})


# ─── Rich terminal output ─────────────────────────────────────────────────────

def _print_summary(metrics: dict, detailed: list[dict]) -> None:
    """Print a colourised terminal summary of the evaluation."""

    def _pct_text(val: float, good_threshold=0.85, bad_threshold=0.7, invert=False) -> str:
        """Return a rich-coloured percentage string."""
        if invert:
            style = "bold red" if val > bad_threshold else "yellow" if val > good_threshold else "green"
        else:
            style = "green" if val >= good_threshold else "yellow" if val >= bad_threshold else "bold red"
        return f"[{style}]{val:.1%}[/{style}]"

    # ── Metrics table ─────────────────────────────────────────────────────
    m = Table(
        title="[bold cyan]Evaluation Metrics[/bold cyan]",
        box=box.ROUNDED,
        header_style="bold magenta",
    )
    m.add_column("Metric",  style="bold", min_width=30)
    m.add_column("Value",   justify="right", min_width=10)
    m.add_column("Notes",   style="dim")

    m.add_row("Triage Accuracy",
              _pct_text(metrics.get("eval/accuracy", 0)),
              "FP/TP classification")
    m.add_row("False Negative Rate",
              _pct_text(metrics.get("eval/false_negative_rate", 0), 0.05, 0.10, invert=True),
              "← lower is better  |  missed attacks")
    m.add_row("FP Escalation Rate",
              _pct_text(metrics.get("eval/fp_escalation_rate", 0), 0.10, 0.20, invert=True),
              "wasted analyst time")
    m.add_row("Escalation Precision",
              _pct_text(metrics.get("eval/escalation_precision", 0)),
              "of escalated, fraction real TP")
    m.add_row("Escalation Recall",
              _pct_text(metrics.get("eval/escalation_recall", 0), 0.80, 0.60),
              "of TPs, fraction escalated")
    m.add_row("Severe TP Recall",
              _pct_text(metrics.get("eval/severe_tp_recall", 0), 0.90, 0.70),
              "critical attacks caught  [bold red]← most important[/bold red]")
    m.add_row("─" * 30, "─" * 10, "")
    m.add_row("Alerts evaluated",
              str(metrics.get("counts/total", 0)), "")
    m.add_row("Missed attacks (FN)",
              f"[{'bold red' if metrics.get('counts/missed_attacks_fn', 0) > 0 else 'green'}]"
              f"{metrics.get('counts/missed_attacks_fn', 0)}[/]",
              "TPs closed as FP")
    m.add_row("Escalated",
              str(metrics.get("counts/tp_escalated", 0) + metrics.get("counts/fp_escalated", 0)),
              f"TP:{metrics.get('counts/tp_escalated',0)}  FP:{metrics.get('counts/fp_escalated',0)}")
    m.add_row("Mean / P95 latency",
              f"{metrics.get('eval/mean_latency_ms', 0):.0f} ms  /  "
              f"{metrics.get('eval/p95_latency_ms', 0):.0f} ms",
              "pipeline wall time")

    console.print(m)

    # ── Category breakdown ────────────────────────────────────────────────
    cat_agg: dict[str, dict] = defaultdict(lambda: {"c": 0, "t": 0})
    for r in detailed:
        cat_agg[r["category"]]["c"] += int(r["correct"])
        cat_agg[r["category"]]["t"] += 1

    c = Table(
        title="[bold]Per-Category Accuracy[/bold]",
        box=box.SIMPLE,
        header_style="bold magenta",
    )
    c.add_column("Category",       width=24)
    c.add_column("Correct / Total", width=15, justify="right")
    c.add_column("Accuracy",        width=10, justify="right")
    for cat, d in sorted(cat_agg.items()):
        acc = d["c"] / d["t"] if d["t"] else 0
        style = "green" if acc >= 0.85 else "yellow" if acc >= 0.70 else "red"
        c.add_row(cat, f"{d['c']}/{d['t']}", f"[{style}]{acc:.0%}[/{style}]")
    console.print(c)

    # ── Missed attacks detail ─────────────────────────────────────────────
    missed = [r for r in detailed
              if r["ground_truth"] == "TP" and r["triage_classification"] == "FP"]
    if missed:
        fn_t = Table(
            title="[bold red]⚠  Missed Attacks — False Negatives[/bold red]",
            box=box.SIMPLE,
            header_style="bold red",
        )
        fn_t.add_column("Alert ID",   width=10)
        fn_t.add_column("Severity",   width=8)
        fn_t.add_column("Category",   width=24)
        fn_t.add_column("Confidence", width=10, justify="right")
        for r in missed:
            fn_t.add_row(
                r["alert_id"], r["severity"], r["category"],
                f"{r['triage_confidence']:.0%}",
            )
        console.print(fn_t)
    else:
        console.print("[bold green]✓  No false negatives — all attacks were detected.[/bold green]")


# ─── Main ─────────────────────────────────────────────────────────────────────

async def _run(args: argparse.Namespace) -> None:
    """Async evaluation entrypoint."""

    provider = os.getenv("MODEL_PROVIDER", "openai")

    # ── W&B Weave init ────────────────────────────────────────────────────
    # weave.init() auto-patches LangChain, OpenAI, and Anthropic clients.
    # Every LLM call made inside predict_alert() becomes a child trace with
    # full prompt/completion/token/latency data — no extra decoration needed.
    console.rule("[bold cyan]SOC Multi-Agent Evaluation[/bold cyan]")
    console.print(f"\n[bold]Initialising W&B Weave[/bold]  project=[cyan]{args.wandb_project}[/cyan]")
    weave.init(args.wandb_project)

    # ── wandb run init ────────────────────────────────────────────────────
    run_name = args.run_name or f"soc-eval-{provider}-n{args.count}"
    run = wandb.init(
        project=args.wandb_project,
        name=run_name,
        config={
            "n_alerts": args.count,
            "model_provider": provider,
            "siem_url": args.siem_url,
            "offline": args.offline,
        },
        tags=["soc-eval", "multi-agent", f"provider:{provider}"],
    )
    console.print(f"[bold]W&B run[/bold]  {run.url}\n")

    # ── Build or load dataset ─────────────────────────────────────────────
    if args.load_dataset and Path(args.load_dataset).exists():
        console.print(f"[bold]Loading dataset[/bold] from {args.load_dataset}")
        dataset = _load_dataset(args.load_dataset)
        console.print(f"[green]✓ Loaded {len(dataset)} alerts[/green]")
    else:
        if args.offline:
            console.print(f"[bold]Generating {args.count} alerts locally[/bold] (--offline mode)")
            raw = _generate_locally(args.count)
        else:
            console.print(f"[bold]Fetching {args.count} alerts[/bold] from SIEM at {args.siem_url}")
            try:
                raw = _fetch_from_siem(args.count, args.siem_url)
            except Exception as exc:  # noqa: BLE001
                console.print(f"[yellow]SIEM unreachable ({exc}) — falling back to local generation[/yellow]")
                raw = _generate_locally(args.count)

        dataset = _alerts_to_dataset(raw)
        console.print(f"[green]✓ Dataset ready: {len(dataset)} alerts[/green]")

        if args.save_dataset:
            _save_dataset(dataset, args.save_dataset)
            console.print(f"[dim]Dataset saved to {args.save_dataset}[/dim]")

    # Log dataset as a W&B Artifact for reproducibility
    tmp_path = "/tmp/soc_eval_dataset.json"
    _save_dataset(dataset, tmp_path)
    artifact = wandb.Artifact(
        "soc-eval-dataset",
        type="dataset",
        description=f"{len(dataset)} SIEM alerts with ground truth labels",
        metadata={"n": len(dataset), "provider": provider},
    )
    artifact.add_file(tmp_path)
    wandb.log_artifact(artifact)

    # ── Print dataset distribution summary ─────────────────────────────────
    from collections import Counter
    gt_dist = Counter(r["ground_truth"] for r in dataset)
    sc_dist = Counter(r.get("severity_class") or "—" for r in dataset)
    sev_dist = Counter(r["alert"].get("severity") for r in dataset)

    dist_t = Table(box=box.SIMPLE, show_header=False)
    dist_t.add_column("k", style="bold")
    dist_t.add_column("v")
    dist_t.add_row("Ground truth",
                   f"FP={gt_dist['FP']} ({gt_dist['FP']/len(dataset):.0%})  "
                   f"TP={gt_dist['TP']} ({gt_dist['TP']/len(dataset):.0%})")
    dist_t.add_row("Severity",
                   "  ".join(f"{k}={v}" for k, v in sorted(sev_dist.items())))
    dist_t.add_row("TP class",
                   f"routine={sc_dist.get('routine',0)}  severe={sc_dist.get('severe',0)}")
    console.print(Panel(dist_t, title="Dataset Distribution", expand=False))

    # ── Build pipeline ────────────────────────────────────────────────────
    console.print("[bold]Building SOC pipeline...[/bold]")
    _get_graph()
    console.print("[green]✓ Pipeline ready[/green]\n")

    # ── Run weave.Evaluation ─────────────────────────────────────────────
    # weave.Evaluation calls predict_alert() on every dataset row, runs all
    # five scorers against (output, ground_truth, severity_class), and writes
    # per-sample results + aggregates to the Weave UI.
    console.print(
        f"[bold]Running weave.Evaluation[/bold] on {len(dataset)} alerts\n"
        "[dim]Each alert incurs 1–2 LLM calls (triage + optional investigation)[/dim]\n"
    )

    evaluation = weave.Evaluation(
        name=run_name,
        dataset=dataset,
        scorers=[
            triage_accuracy_scorer,
            false_negative_scorer,
            escalation_quality_scorer,
            confidence_calibration_scorer,
            investigation_quality_scorer,
        ],
    )

    async def _poll_progress(progress, task_id: int, target: int) -> None:
        """Update the progress bar by polling len(_predictions) every 0.5 s.

        Python 3.14 made built-in types immutable so list.append can no longer
        be monkey-patched.  A polling coroutine running concurrently with the
        evaluation is the correct approach.
        """
        while len(_predictions) < target:
            progress.update(task_id, completed=len(_predictions))
            await asyncio.sleep(0.5)
        progress.update(task_id, completed=target)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[cyan]{task.completed}/{task.total}[/cyan]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task_id = progress.add_task("Evaluating alerts…", total=len(dataset))
        eval_task = asyncio.create_task(evaluation.evaluate(predict_alert))
        poll_task = asyncio.create_task(_poll_progress(progress, task_id, len(dataset)))
        try:
            eval_summary = await eval_task
        finally:
            poll_task.cancel()
            try:
                await poll_task
            except asyncio.CancelledError:
                pass

    console.print(f"[green]✓ Evaluation complete  ({len(_predictions)} predictions collected)[/green]\n")

    # ── Compute aggregate metrics ─────────────────────────────────────────
    preds_by_id = {p["alert_id"]: p for p in _predictions}
    metrics, detailed = _compute_metrics(dataset, preds_by_id)

    # ── Log to wandb ──────────────────────────────────────────────────────
    _log_to_wandb(metrics, detailed)

    # ── Print terminal summary ────────────────────────────────────────────
    console.rule("[bold cyan]Results[/bold cyan]")
    _print_summary(metrics, detailed)

    # ── Weave summary ─────────────────────────────────────────────────────
    console.print()
    # Print the weave eval summary in a condensed form
    console.print("[bold]Weave scorer summary:[/bold]")
    for scorer_name, scorer_vals in eval_summary.items():
        if isinstance(scorer_vals, dict):
            parts = []
            for metric, val in scorer_vals.items():
                if isinstance(val, dict):
                    # Weave wraps bool metrics as {true_count, true_fraction}
                    frac = val.get("true_fraction") or val.get("mean")
                    if frac is not None:
                        parts.append(f"{metric}={frac:.1%}")
                elif isinstance(val, (int, float)):
                    parts.append(f"{metric}={val:.3f}")
            console.print(f"  [cyan]{scorer_name}[/cyan]: {', '.join(parts)}")

    console.print(f"\n[bold]W&B Dashboard:[/bold]   {run.url}")
    entity = getattr(run, "entity", None) or ""
    weave_url = f"https://wandb.ai/{entity}/{args.wandb_project}/weave"
    console.print(f"[bold]W&B Weave Traces:[/bold] {weave_url}\n")

    run.finish()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate the SOC multi-agent pipeline with W&B Weave + wandb",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--count", type=int, default=50,
        help="Number of alerts to evaluate",
    )
    parser.add_argument(
        "--wandb-project", default="soc-multiagent-eval",
        help="W&B project name",
    )
    parser.add_argument(
        "--run-name", default=None,
        help="W&B run name (default: soc-eval-<provider>-n<count>)",
    )
    parser.add_argument(
        "--siem-url", default="http://localhost:8081",
        help="SIEM simulator base URL",
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="Generate alerts locally (no SIEM server required)",
    )
    parser.add_argument(
        "--load-dataset", default=None, metavar="FILE",
        help="Load a previously saved dataset JSON for reproducible evaluation",
    )
    parser.add_argument(
        "--save-dataset", default=None, metavar="FILE",
        help="Save the generated dataset to FILE for future reproducibility",
    )
    args = parser.parse_args()
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
