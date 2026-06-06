import type { Alert, SOCState, PipelineMetrics, ActionEntry } from "../types/soc";

export type { Alert, SOCState, ActionEntry };

const SIEM = "/api/siem";
const SOC = "/api/soc";

export interface OverridePayload {
  alert_id: string;
  agent_classification: string;
  analyst_classification: string;
  reasoning: string;
  confidence_adjustment: number;
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`HTTP ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export async function fetchAlerts(count = 20): Promise<Alert[]> {
  const res = await fetch(`${SIEM}/alerts?count=${count}`);
  return handleResponse<Alert[]>(res);
}

export async function processAlert(alert: Alert): Promise<SOCState> {
  const res = await fetch(`${SOC}/process-alert`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(alert),
  });
  return handleResponse<SOCState>(res);
}

export async function fetchPipelineStatus(): Promise<{
  stats: PipelineMetrics;
  copilotkit_enabled: boolean;
}> {
  const res = await fetch(`${SOC}/pipeline/status`);
  return handleResponse<{ stats: PipelineMetrics; copilotkit_enabled: boolean }>(res);
}

export async function isolateHost(
  hostname: string,
  alertId: string
): Promise<{ ticket_id: string }> {
  const res = await fetch(`${SOC}/actions/isolate-host`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hostname, alert_id: alertId }),
  });
  return handleResponse<{ ticket_id: string }>(res);
}

export async function createTicket(
  priority: string,
  summary: string,
  alertId: string
): Promise<{ ticket_id: string }> {
  const res = await fetch(`${SOC}/actions/create-ticket`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ priority, summary, alert_id: alertId }),
  });
  return handleResponse<{ ticket_id: string }>(res);
}

export async function blockIP(
  ip: string,
  reason: string,
  alertId: string
): Promise<{ ticket_id?: string; status: string }> {
  const res = await fetch(`${SOC}/actions/block-ip`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip, reason, alert_id: alertId }),
  });
  return handleResponse<{ ticket_id?: string; status: string }>(res);
}

export async function submitOverride(
  body: OverridePayload
): Promise<{ new_triage_weight: number; total_corrections: number }> {
  const res = await fetch(`${SOC}/analyst/override`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return handleResponse<{ new_triage_weight: number; total_corrections: number }>(res);
}

export async function fetchCorrections(): Promise<{
  corrections: unknown[];
  triage_weight: number;
}> {
  const res = await fetch(`${SOC}/analyst/corrections`);
  return handleResponse<{ corrections: unknown[]; triage_weight: number }>(res);
}

export async function fetchActionsLog(): Promise<{ actions: ActionEntry[] }> {
  const res = await fetch(`${SOC}/actions/log`);
  return handleResponse<{ actions: ActionEntry[] }>(res);
}
