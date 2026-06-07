import { useState, useEffect, useCallback } from "react";
import toast from "react-hot-toast";
import { useCopilotReadable, useCopilotAction } from "@copilotkit/react-core";
import type { Alert, SOCState, ActionEntry } from "../types/soc";
import type { OverridePayload } from "../api/socApi";
import {
  isolateHost,
  createTicket,
  blockIP,
  submitOverride,
  fetchActionsLog,
} from "../api/socApi";
import { CorrectionModal } from "./CorrectionModal";
import { hasInvestigation, hasTriageResult } from "../socStateGuards";
import { cn, formatTime } from "../lib/utils";

interface ActionPanelProps {
  activeAlert: Alert | null;
  socState: SOCState | null;
  copilotEnabled: boolean;
}

type TicketPriority = "P1" | "P2" | "P3";

interface CopilotActionBridgeProps {
  activeAlert: Alert | null;
  socState: SOCState | null;
  loadActionsLog: () => Promise<void>;
}

function CopilotActionBridge({
  activeAlert,
  socState,
  loadActionsLog,
}: CopilotActionBridgeProps) {
  useCopilotReadable({
    description: "Currently active security alert",
    value: activeAlert,
  });
  useCopilotReadable({
    description: "SOC pipeline processing result",
    value: socState,
  });
  useCopilotReadable({
    description: "Active alert triage classification",
    value: socState?.triage_result,
  });
  useCopilotReadable({
    description: "Investigation report if escalated",
    value: socState?.investigation_report,
  });

  useCopilotAction({
    name: "isolateHost",
    description: "Isolate a compromised host from the network",
    parameters: [
      { name: "hostname", type: "string", description: "Hostname to isolate" },
      { name: "alert_id", type: "string", description: "Alert ID" },
    ],
    handler: async ({ hostname, alert_id }: { hostname: string; alert_id: string }) => {
      try {
        const result = await isolateHost(hostname, alert_id);
        await loadActionsLog();
        return `Host ${hostname} isolated. Ticket: ${result.ticket_id}`;
      } catch (err) {
        throw new Error(`Failed to isolate host: ${err instanceof Error ? err.message : String(err)}`);
      }
    },
  });

  useCopilotAction({
    name: "createIncidentTicket",
    description: "Create an incident ticket for an alert",
    parameters: [
      { name: "priority", type: "string", description: "P1, P2, or P3" },
      { name: "summary", type: "string", description: "Ticket summary" },
      { name: "alert_id", type: "string", description: "Alert ID" },
    ],
    handler: async ({
      priority,
      summary,
      alert_id,
    }: {
      priority: string;
      summary: string;
      alert_id: string;
    }) => {
      try {
        const result = await createTicket(priority, summary, alert_id);
        await loadActionsLog();
        return `Ticket created: ${result.ticket_id}`;
      } catch (err) {
        throw new Error(`Failed to create ticket: ${err instanceof Error ? err.message : String(err)}`);
      }
    },
  });

  useCopilotAction({
    name: "blockIPAddress",
    description: "Block a suspicious IP address at the perimeter firewall",
    parameters: [
      { name: "ip", type: "string", description: "IP address to block" },
      { name: "reason", type: "string", description: "Reason for block" },
      { name: "alert_id", type: "string", description: "Alert ID" },
    ],
    handler: async ({
      ip,
      reason,
      alert_id,
    }: {
      ip: string;
      reason: string;
      alert_id: string;
    }) => {
      try {
        const result = await blockIP(ip, reason, alert_id);
        await loadActionsLog();
        return `IP ${ip} blocked. Status: ${result.status}${result.ticket_id ? `, Ticket: ${result.ticket_id}` : ""}`;
      } catch (err) {
        throw new Error(`Failed to block IP: ${err instanceof Error ? err.message : String(err)}`);
      }
    },
  });

  return null;
}

export function ActionPanel({ activeAlert, socState, copilotEnabled }: ActionPanelProps) {
  const [recentActions, setRecentActions] = useState<ActionEntry[]>([]);
  const [showCorrectionModal, setShowCorrectionModal] = useState(false);
  const [ticketDropdownOpen, setTicketDropdownOpen] = useState(false);
  const [loading, setLoading] = useState<string | null>(null);

  const triage = socState && hasTriageResult(socState.triage_result)
    ? socState.triage_result
    : null;
  const investigation = socState && hasInvestigation(socState.investigation_report)
    ? socState.investigation_report
    : null;

  const isTP = triage?.likely_classification === "TP";
  const isEscalated = isTP && investigation !== null;
  const actionsEnabled = socState !== null && activeAlert !== null;

  // Load recent actions log
  const loadActionsLog = useCallback(async () => {
    try {
      const data = await fetchActionsLog();
      setRecentActions(data.actions.slice(-3).reverse());
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    loadActionsLog();
  }, [loadActionsLog]);

  // Manual action handlers
  const handleIsolateHost = async () => {
    if (!activeAlert || !actionsEnabled) return;
    setLoading("isolate");
    try {
      const result = await isolateHost(activeAlert.hostname, activeAlert.alert_id);
      toast.success(`Host isolated. Ticket: ${result.ticket_id}`);
      await loadActionsLog();
    } catch (err) {
      toast.error(`Isolation failed: ${err instanceof Error ? err.message : "Unknown error"}`);
    } finally {
      setLoading(null);
    }
  };

  const handleCreateTicket = async (priority: TicketPriority) => {
    if (!activeAlert || !actionsEnabled) return;
    setTicketDropdownOpen(false);
    setLoading("ticket");
    const summary = investigation
      ? `[${priority}] ${investigation.mitre_technique} — ${activeAlert.hostname}`
      : `[${priority}] ${activeAlert.rule_name} — ${activeAlert.hostname}`;
    try {
      const result = await createTicket(priority, summary, activeAlert.alert_id);
      toast.success(`Ticket created: ${result.ticket_id}`);
      await loadActionsLog();
    } catch (err) {
      toast.error(`Ticket creation failed: ${err instanceof Error ? err.message : "Unknown error"}`);
    } finally {
      setLoading(null);
    }
  };

  const handleBlockIP = async () => {
    if (!activeAlert || !actionsEnabled) return;
    setLoading("block");
    const reason = triage?.triage_summary ?? "Suspicious activity detected";
    try {
      const result = await blockIP(activeAlert.source_ip, reason, activeAlert.alert_id);
      toast.success(`IP blocked. Status: ${result.status}`);
      await loadActionsLog();
    } catch (err) {
      toast.error(`Block failed: ${err instanceof Error ? err.message : "Unknown error"}`);
    } finally {
      setLoading(null);
    }
  };

  const handleOverrideSubmit = async (payload: OverridePayload) => {
    try {
      const result = await submitOverride(payload);
      toast.success(
        `Override submitted. Weight: ${result.new_triage_weight.toFixed(2)} (${result.total_corrections} corrections)`
      );
      setShowCorrectionModal(false);
    } catch (err) {
      toast.error(`Override failed: ${err instanceof Error ? err.message : "Unknown error"}`);
    }
  };

  const btnBase =
    "w-full flex items-center gap-2 px-3 py-2 rounded border text-[11px] font-mono font-medium transition-all text-left";
  const btnEnabled =
    "border-gray-700 bg-gray-800/60 text-gray-300 hover:border-gray-600 hover:bg-gray-800 hover:text-gray-100";
  const btnDisabled =
    "border-gray-800 bg-gray-900/30 text-gray-700 cursor-not-allowed";
  const btnDanger =
    "border-red-500/50 bg-red-500/10 text-red-400 hover:bg-red-500/20 hover:border-red-500/70";
  const btnLoading = "opacity-60 cursor-wait";

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {copilotEnabled && (
        <CopilotActionBridge
          activeAlert={activeAlert}
          socState={socState}
          loadActionsLog={loadActionsLog}
        />
      )}
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-2 bg-gray-900 border-b border-gray-800 shrink-0">
        <span className="text-[11px] font-mono font-semibold text-gray-300 tracking-widest uppercase">
          Response Actions
        </span>
      </div>

      <div className="flex-1 overflow-y-auto p-3 space-y-2">
        {/* Context summary */}
        {activeAlert && (
          <div className="bg-gray-900/60 border border-gray-800 rounded p-2.5 space-y-1">
            <div className="text-[9px] font-mono text-gray-600 uppercase tracking-wider">
              Active Alert
            </div>
            <div className="text-[10px] font-mono text-gray-300 truncate">
              {activeAlert.rule_name}
            </div>
            <div className="flex items-center gap-2 text-[9px] font-mono">
              <span className="text-gray-600">Host:</span>
              <span className="text-blue-400">{activeAlert.hostname}</span>
            </div>
            <div className="flex items-center gap-2 text-[9px] font-mono">
              <span className="text-gray-600">Src IP:</span>
              <span className="text-red-400/80">{activeAlert.source_ip}</span>
            </div>
            {triage && (
              <div className="flex items-center gap-1 pt-0.5">
                <span
                  className={cn(
                    "text-[9px] font-bold font-mono px-1 py-0.5 rounded border",
                    triage.likely_classification === "TP"
                      ? "text-red-400 border-red-500/40 bg-red-500/10"
                      : "text-green-400 border-green-500/40 bg-green-500/10"
                  )}
                >
                  {triage.likely_classification}
                </span>
                <span className="text-[9px] font-mono text-gray-600">
                  {Math.round(triage.triage_confidence * 100)}% confidence
                </span>
              </div>
            )}
          </div>
        )}

        {/* Action: Isolate Host */}
        <button
          onClick={handleIsolateHost}
          disabled={!actionsEnabled || loading === "isolate"}
          className={cn(
            btnBase,
            actionsEnabled && loading !== "isolate"
              ? isEscalated
                ? btnDanger
                : btnEnabled
              : btnDisabled,
            loading === "isolate" ? btnLoading : ""
          )}
        >
          <span className="text-base leading-none">🔒</span>
          <span>
            {loading === "isolate" ? "Isolating…" : "Isolate Host"}
            {activeAlert && (
              <span className="block text-[9px] font-normal text-gray-600 mt-0.5">
                {activeAlert.hostname}
              </span>
            )}
          </span>
        </button>

        {/* Action: Create Ticket (dropdown) */}
        <div className="relative">
          <button
            onClick={() => actionsEnabled && setTicketDropdownOpen((v) => !v)}
            disabled={!actionsEnabled || loading === "ticket"}
            className={cn(
              btnBase,
              actionsEnabled && loading !== "ticket" ? btnEnabled : btnDisabled,
              loading === "ticket" ? btnLoading : ""
            )}
          >
            <span className="text-base leading-none">🎫</span>
            <span>
              {loading === "ticket" ? "Creating…" : "Create Ticket"}
              <span className="block text-[9px] font-normal text-gray-600 mt-0.5">
                Select priority
              </span>
            </span>
            <span className="ml-auto text-gray-600 font-mono">▾</span>
          </button>
          {ticketDropdownOpen && (
            <div className="absolute top-full left-0 right-0 z-10 mt-0.5 bg-gray-900 border border-gray-700 rounded shadow-lg overflow-hidden">
              {(["P1", "P2", "P3"] as TicketPriority[]).map((p) => (
                <button
                  key={p}
                  onClick={() => handleCreateTicket(p)}
                  className={cn(
                    "w-full text-left px-3 py-1.5 text-[11px] font-mono hover:bg-gray-800 transition-colors",
                    p === "P1"
                      ? "text-red-400"
                      : p === "P2"
                      ? "text-orange-400"
                      : "text-yellow-400"
                  )}
                >
                  {p} — {p === "P1" ? "Critical" : p === "P2" ? "High" : "Medium"}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Action: Block Source IP */}
        <button
          onClick={handleBlockIP}
          disabled={!actionsEnabled || loading === "block"}
          className={cn(
            btnBase,
            actionsEnabled && loading !== "block" ? btnEnabled : btnDisabled,
            loading === "block" ? btnLoading : ""
          )}
        >
          <span className="text-base leading-none">🚫</span>
          <span>
            {loading === "block" ? "Blocking…" : "Block Source IP"}
            {activeAlert && (
              <span className="block text-[9px] font-normal text-gray-600 mt-0.5">
                {activeAlert.source_ip}
              </span>
            )}
          </span>
        </button>

        {/* Action: Override Classification */}
        <button
          onClick={() => actionsEnabled && setShowCorrectionModal(true)}
          disabled={!actionsEnabled}
          className={cn(
            btnBase,
            actionsEnabled ? btnEnabled : btnDisabled
          )}
        >
          <span className="text-base leading-none">✏️</span>
          <span>
            Override Classification
            <span className="block text-[9px] font-normal text-gray-600 mt-0.5">
              Analyst correction
            </span>
          </span>
        </button>

        {/* AI Assistant hint */}
        <div className="border border-dashed border-gray-800 rounded p-2.5 text-center">
          <div className="text-[10px] font-mono text-gray-600 mb-0.5">
            AI Analyst Assistant
          </div>
          <kbd className="text-[10px] font-mono text-blue-400 bg-blue-500/10 border border-blue-500/30 px-1.5 py-0.5 rounded">
            Ctrl+K
          </kbd>
          <span className="text-[10px] font-mono text-gray-600 ml-1">
            to open
          </span>
        </div>

        {/* Recent Actions Log */}
        <div>
          <div className="text-[9px] font-mono text-gray-600 uppercase tracking-wider mb-1.5 flex items-center justify-between">
            <span>Recent Actions</span>
            <button
              onClick={loadActionsLog}
              className="text-gray-700 hover:text-gray-500 text-[9px] font-mono transition-colors"
            >
              ↻ refresh
            </button>
          </div>

          {recentActions.length === 0 ? (
            <div className="text-[9px] font-mono text-gray-700 italic">
              No actions recorded yet
            </div>
          ) : (
            <div className="space-y-1.5">
              {recentActions.map((action, i) => (
                <div
                  key={i}
                  className="bg-gray-900/60 border border-gray-800 rounded p-2"
                >
                  <div className="flex items-center justify-between mb-0.5">
                    <span className="text-[9px] font-mono text-blue-400 uppercase">
                      {action.action}
                    </span>
                    <span className="text-[9px] font-mono text-gray-700">
                      {action.timestamp
                        ? formatTime(action.timestamp)
                        : "—"}
                    </span>
                  </div>
                  <div className="text-[9px] font-mono text-gray-600">
                    {action.hostname ?? action.ip ?? action.summary ?? action.ticket_id}
                  </div>
                  {action.status && (
                    <span
                      className={cn(
                        "text-[8px] font-mono",
                        action.status === "success"
                          ? "text-green-400"
                          : "text-orange-400"
                      )}
                    >
                      {action.status}
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Correction Modal */}
      {showCorrectionModal && (
        <CorrectionModal
          socState={socState}
          onClose={() => setShowCorrectionModal(false)}
          onSubmit={handleOverrideSubmit}
        />
      )}
    </div>
  );
}
