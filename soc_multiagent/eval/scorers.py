"""
Evaluation scorers for the SOC multi-agent pipeline.

Each scorer is decorated with @weave.op() so every call is traced in the
W&B Weave UI alongside the model prediction that triggered it.

Scoring philosophy
──────────────────
A SOC pipeline has asymmetric failure costs:

  False Negative (TP → FP): a real attack is labelled benign and closed.
    → MOST DANGEROUS. An attacker moves undetected.

  False Positive (FP → TP): a benign event is escalated for investigation.
    → WASTEFUL but recoverable. Analyst time is burned.

Scorers reflect this asymmetry: false_negative_scorer fires a hard flag,
while escalation_quality_scorer distinguishes wasted-effort from missed-attack.

Scorer return types
───────────────────
All scorers return dicts.  Weave summarises:
  - bool values  → true_count / true_fraction in the eval summary
  - float values → mean / p50 / p99 in the eval summary
  - None values  → excluded from aggregation (used for "not applicable" rows)
"""

from __future__ import annotations

from typing import Optional

import weave


# ─── Triage accuracy ─────────────────────────────────────────────────────────

@weave.op()
def triage_accuracy_scorer(output: dict, ground_truth: str) -> dict:
    """
    Did the triage agent correctly classify the alert as FP or TP?

    This is the primary correctness metric.  A perfect triage agent would
    score 1.0 here.  In practice, ~90% FP base-rate makes this easier to
    game by always predicting FP, so read it alongside false_negative_rate.
    """
    predicted = output.get("triage_classification", "FP")
    correct = predicted == ground_truth
    return {
        "correct": correct,
    }


# ─── False negative (missed attack) ─────────────────────────────────────────

@weave.op()
def false_negative_scorer(output: dict, ground_truth: str) -> dict:
    """
    Did a real True Positive get closed as a False Positive?

    A false negative means a genuine attack was dismissed without investigation.
    This is the most dangerous failure mode for a SOC — it corresponds to an
    undetected breach.  The target rate is 0 % for severe TPs.
    """
    predicted = output.get("triage_classification", "FP")
    is_false_negative = (ground_truth == "TP") and (predicted == "FP")
    return {
        "is_false_negative": is_false_negative,
    }


# ─── Escalation quality ───────────────────────────────────────────────────────

@weave.op()
def escalation_quality_scorer(
    output: dict,
    ground_truth: str,
    severity_class: Optional[str] = None,
) -> dict:
    """
    Evaluate the *escalation* decision quality along two axes:

    wasted_escalation  — a False Positive was sent to the investigation queue.
                         Costs analyst time but causes no security harm.

    severe_tp_escalated — for the most critical alerts (severe True Positives),
                          did the pipeline escalate them?  None for non-severe rows
                          so Weave excludes them from the aggregate fraction.
    """
    escalated = output.get("routing_decision") == "escalate_to_investigation"
    is_tp = ground_truth == "TP"
    is_severe = severity_class == "severe"

    wasted_escalation = escalated and not is_tp

    # Only meaningful for severe TPs — None rows are excluded from weave aggregate
    severe_tp_escalated: Optional[bool] = None
    if is_tp and is_severe:
        severe_tp_escalated = escalated

    return {
        "wasted_escalation": wasted_escalation,
        "severe_tp_escalated": severe_tp_escalated,
    }


# ─── Confidence calibration ───────────────────────────────────────────────────

@weave.op()
def confidence_calibration_scorer(output: dict, ground_truth: str) -> dict:
    """
    Is the triage agent's confidence score well-calibrated?

    calibration_score:
      - Correct prediction  → score = confidence   (reward certainty when right)
      - Wrong prediction    → score = 1 - confidence (penalise certainty when wrong)
      Perfect calibration → mean ≈ 0.75 (uncertain-but-correct beats confident-but-wrong)

    overconfident_error:
      True when the model is wrong AND confidence > 80 %.
      These are the most harmful classification errors.
    """
    predicted = output.get("triage_classification", "FP")
    confidence = float(output.get("triage_confidence", 0.5))
    correct = predicted == ground_truth

    calibration_score = confidence if correct else (1.0 - confidence)
    overconfident_error = (not correct) and (confidence > 0.8)

    return {
        "calibration_score": round(calibration_score, 4),
        "overconfident_error": overconfident_error,
    }


# ─── Investigation quality (only for escalated alerts) ───────────────────────

@weave.op()
def investigation_quality_scorer(
    output: dict,
    ground_truth: str,
    severity_class: Optional[str] = None,
) -> dict:
    """
    For alerts that reached the investigation node, how complete is the report?

    Checks that the investigation report contains meaningful values for the
    four most critical fields.  Returns None for non-escalated alerts so Weave
    excludes them from the aggregate.
    """
    escalated = output.get("routing_decision") == "escalate_to_investigation"
    if not escalated:
        # Not applicable — weave treats None as "skip this row in aggregate"
        return {
            "report_complete": None,
            "has_mitre_technique": None,
            "has_containment_steps": None,
        }

    mitre = output.get("mitre_technique") or ""
    attack_stage = output.get("attack_stage") or ""
    sev_assess = output.get("severity_assessment") or ""
    response = output.get("recommended_response") or ""

    has_mitre = bool(mitre and mitre != "T0000 – Investigation Unavailable")
    has_stage = bool(attack_stage and attack_stage != "Unknown")
    has_sev = bool(sev_assess in ("critical", "high", "medium"))
    has_response = len(response) > 10

    report_complete = all([has_mitre, has_stage, has_sev, has_response])

    # Flag if investigation ran but ground truth was FP (wasted deep-dive)
    false_positive_investigated = ground_truth == "FP"

    return {
        "report_complete": report_complete,
        "has_mitre_technique": has_mitre,
        "has_containment_steps": has_stage,
        "false_positive_investigated": false_positive_investigated,
    }
