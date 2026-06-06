export interface Alert {
  alert_id: string;
  timestamp: string;
  severity: "HIGH" | "MEDIUM" | "LOW";
  category: string;
  source_ip: string;
  destination_ip: string;
  hostname: string;
  user: string;
  rule_name: string;
  raw_log: string;
  ground_truth?: "FP" | "TP";
  severity_class?: "routine" | "severe";
}

export interface TriageResult {
  likely_classification: "FP" | "TP";
  triage_confidence: number;
  triage_recommendation: "close_fp" | "monitor" | "escalate";
  triage_summary: string;
  key_indicators: string[];
  risk_factors: string[];
}

export interface InvestigationReport {
  attack_stage: string;
  mitre_technique: string;
  ioc_summary: string[];
  recommended_response: string;
  severity_assessment: "critical" | "high" | "medium";
  analyst_notes: string;
  threat_actor_profile: string;
  containment_steps: string[];
  time_to_investigate: string;
}

export interface SOCState {
  alert: Alert | Record<string, never>;
  triage_result: TriageResult | Record<string, never>;
  investigation_report: InvestigationReport | null;
  routing_decision: string;
  final_disposition: string;
  processing_log: string[];
}

export interface PipelineMetrics {
  total_processed: number;
  escalated: number;
  closed: number;
  critical_findings: number;
}

export interface ActionEntry {
  action: string;
  hostname?: string;
  ip?: string;
  ticket_id: string;
  alert_id: string;
  timestamp: string;
  status?: string;
  priority?: string;
  summary?: string;
}
