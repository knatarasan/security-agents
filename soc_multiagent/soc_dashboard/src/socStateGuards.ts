import type { Alert, InvestigationReport, SOCState, TriageResult } from "./types/soc";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export function hasAlert(alert: SOCState["alert"] | null | undefined): alert is Alert {
  return isRecord(alert) && typeof alert.alert_id === "string";
}

export function hasTriageResult(
  triage: SOCState["triage_result"] | null | undefined
): triage is TriageResult {
  return (
    isRecord(triage) &&
    (triage.likely_classification === "FP" ||
      triage.likely_classification === "TP") &&
    typeof triage.triage_confidence === "number" &&
    typeof triage.triage_recommendation === "string" &&
    typeof triage.triage_summary === "string" &&
    Array.isArray(triage.key_indicators) &&
    Array.isArray(triage.risk_factors)
  );
}

export function hasInvestigation(
  investigation: SOCState["investigation_report"] | null | undefined
): investigation is InvestigationReport {
  return (
    isRecord(investigation) &&
    typeof investigation.attack_stage === "string" &&
    typeof investigation.mitre_technique === "string" &&
    Array.isArray(investigation.ioc_summary) &&
    typeof investigation.recommended_response === "string" &&
    typeof investigation.severity_assessment === "string" &&
    typeof investigation.analyst_notes === "string" &&
    typeof investigation.threat_actor_profile === "string" &&
    Array.isArray(investigation.containment_steps) &&
    typeof investigation.time_to_investigate === "string"
  );
}
