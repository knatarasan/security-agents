import React, { useEffect, useRef } from "react";
import { useCoAgent } from "@copilotkit/react-core";
import type { Alert, SOCState, TriageResult, InvestigationReport } from "../types/soc";
import { cn, severityColor, classColor } from "../lib/utils";

const EMPTY_SOC_STATE: SOCState = {
  alert: {},
  triage_result: {},
  investigation_report: null,
  routing_decision: "pending",
  final_disposition: "pending",
  processing_log: [],
};

interface PipelineViewerProps {
  activeAlert: Alert | null;
  onComplete: (state: SOCState) => void;
}

// Type guards — must guard against undefined before using `in`
function hasTriageResult(tr: SOCState["triage_result"] | undefined): tr is TriageResult {
  return tr != null && "likely_classification" in tr;
}

function hasInvestigation(
  ir: SOCState["investigation_report"] | undefined
): ir is InvestigationReport {
  return ir != null && "mitre_technique" in ir;
}

type NodeStatus = "idle" | "running" | "done" | "skipped";

interface PipelineNodeProps {
  title: string;
  status: NodeStatus;
  children?: React.ReactNode;
}

function PipelineNode({ title, status, children }: PipelineNodeProps) {
  const borderColor = {
    idle: "border-gray-700",
    running: "border-blue-500/70",
    done: "border-green-500/50",
    skipped: "border-gray-800",
  }[status];

  const headerColor = {
    idle: "text-gray-500",
    running: "text-blue-400",
    done: "text-green-400",
    skipped: "text-gray-700",
  }[status];

  const statusBadge = {
    idle: null,
    running: (
      <span className="text-[9px] font-mono text-blue-400 animate-pulse border border-blue-500/50 px-1 py-0.5 rounded">
        RUNNING
      </span>
    ),
    done: (
      <span className="text-[9px] font-mono text-green-400 border border-green-500/40 px-1 py-0.5 rounded">
        DONE
      </span>
    ),
    skipped: (
      <span className="text-[9px] font-mono text-gray-700 border border-gray-700 px-1 py-0.5 rounded">
        SKIPPED
      </span>
    ),
  }[status];

  return (
    <div
      className={cn(
        "flex-1 min-w-0 bg-gray-900 border rounded p-2.5 flex flex-col gap-1.5",
        borderColor
      )}
    >
      <div className="flex items-center justify-between">
        <span
          className={cn(
            "text-[10px] font-mono font-bold tracking-widest uppercase",
            headerColor
          )}
        >
          {title}
        </span>
        {statusBadge}
      </div>
      {children && (
        <div className="flex flex-col gap-1 min-h-0">{children}</div>
      )}
    </div>
  );
}

export function PipelineViewer({ activeAlert, onComplete }: PipelineViewerProps) {
  const { state: rawState, run, running, setState } = useCoAgent<SOCState>({
    name: "soc_pipeline",
    initialState: EMPTY_SOC_STATE,
  });

  // useCoAgent state may be undefined before the first backend sync
  const state: SOCState = rawState ?? EMPTY_SOC_STATE;

  const prevAlertIdRef = useRef<string | null>(null);
  const onCompleteRef = useRef(onComplete);
  onCompleteRef.current = onComplete;

  useEffect(() => {
    if (!activeAlert) return;
    if (activeAlert.alert_id === prevAlertIdRef.current) return;
    prevAlertIdRef.current = activeAlert.alert_id;

    setState({
      alert: activeAlert as Alert,
      triage_result: {},
      investigation_report: null,
      routing_decision: "pending",
      final_disposition: "pending",
      processing_log: [],
    });

    const timer = setTimeout(() => {
      run();
    }, 100);

    return () => clearTimeout(timer);
  }, [activeAlert, setState, run]);

  // Notify parent when pipeline finishes
  useEffect(() => {
    if (!running && state.final_disposition !== "pending" && activeAlert) {
      onCompleteRef.current(state);
    }
  }, [running, state, activeAlert]);

  const triage = hasTriageResult(state.triage_result) ? state.triage_result : null;
  const investigation = hasInvestigation(state.investigation_report)
    ? state.investigation_report
    : null;

  // Derive node statuses
  const supervisorStatus: NodeStatus = activeAlert
    ? running && !triage
      ? "running"
      : triage || investigation
      ? "done"
      : "running"
    : "idle";

  const triageStatus: NodeStatus = !activeAlert
    ? "idle"
    : triage
    ? "done"
    : running
    ? "running"
    : "idle";

  const investigationStatus: NodeStatus = !activeAlert
    ? "idle"
    : investigation
    ? "done"
    : state.routing_decision === "escalate" && running
    ? "running"
    : state.routing_decision === "close_fp" || state.routing_decision === "monitor"
    ? "skipped"
    : "idle";

  const outputStatus: NodeStatus = !activeAlert
    ? "idle"
    : !running && state.final_disposition !== "pending"
    ? "done"
    : running
    ? "running"
    : "idle";

  // Processing log ref for auto-scroll
  const logEndRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [state.processing_log]);

  const displayedLogs = state.processing_log.slice(-6);

  return (
    <div className="flex flex-col h-full p-3 gap-3">
      {/* Header */}
      <div className="flex items-center justify-between shrink-0">
        <span className="text-[11px] font-mono font-semibold text-gray-300 tracking-widest uppercase">
          Pipeline Viewer
        </span>
        {running && (
          <span className="flex items-center gap-1 text-[10px] font-mono text-blue-400 animate-pulse">
            <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-ping" />
            ANALYZING
          </span>
        )}
        {!running && activeAlert && state.final_disposition !== "pending" && (
          <span className="flex items-center gap-1 text-[10px] font-mono text-green-400">
            <span className="h-1.5 w-1.5 rounded-full bg-green-400" />
            COMPLETE
          </span>
        )}
      </div>

      {/* No alert placeholder */}
      {!activeAlert && (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <div className="text-3xl mb-2 opacity-30">⚙</div>
            <p className="text-xs font-mono text-gray-600">
              Select an alert to begin analysis
            </p>
          </div>
        </div>
      )}

      {/* Pipeline nodes */}
      {activeAlert && (
        <>
          <div className="flex items-stretch gap-2 shrink-0">
            {/* Supervisor */}
            <PipelineNode title="Supervisor" status={supervisorStatus}>
              <div className="text-[10px] font-mono text-gray-400 truncate">
                {activeAlert.category}
              </div>
              <span
                className={cn(
                  "text-[10px] font-bold font-mono",
                  severityColor(activeAlert.severity)
                )}
              >
                {activeAlert.severity}
              </span>
            </PipelineNode>

            <div className="flex items-center text-gray-700 font-mono text-sm shrink-0">
              →
            </div>

            {/* Triage */}
            <PipelineNode title="Triage" status={triageStatus}>
              {triage ? (
                <>
                  <span
                    className={cn(
                      "text-[10px] font-bold font-mono",
                      classColor(triage.likely_classification)
                    )}
                  >
                    {triage.likely_classification}
                  </span>
                  {/* Confidence bar */}
                  <div className="w-full bg-gray-800 rounded-full h-1 mt-0.5">
                    <div
                      className={cn(
                        "h-1 rounded-full transition-all",
                        triage.likely_classification === "TP"
                          ? "bg-red-500"
                          : "bg-green-500"
                      )}
                      style={{
                        width: `${Math.round(triage.triage_confidence * 100)}%`,
                      }}
                    />
                  </div>
                  <div className="text-[9px] font-mono text-gray-600 mt-0.5">
                    {Math.round(triage.triage_confidence * 100)}% confidence
                  </div>
                  <p className="text-[9px] font-mono text-gray-500 line-clamp-2 leading-relaxed">
                    {triage.triage_summary}
                  </p>
                </>
              ) : (
                <span className="text-[9px] text-gray-700 font-mono">
                  awaiting triage…
                </span>
              )}
            </PipelineNode>

            <div className="flex items-center text-gray-700 font-mono text-sm shrink-0">
              →
            </div>

            {/* Investigation */}
            <PipelineNode title="Investigation" status={investigationStatus}>
              {investigation ? (
                <>
                  <span className="text-[9px] font-mono text-orange-400 truncate">
                    {investigation.mitre_technique}
                  </span>
                  <span className="text-[9px] font-mono text-blue-400 truncate">
                    {investigation.attack_stage}
                  </span>
                </>
              ) : investigationStatus === "skipped" ? (
                <span className="text-[9px] text-gray-700 font-mono">
                  not escalated
                </span>
              ) : (
                <span className="text-[9px] text-gray-700 font-mono">
                  {investigationStatus === "running"
                    ? "investigating…"
                    : "pending routing"}
                </span>
              )}
            </PipelineNode>

            <div className="flex items-center text-gray-700 font-mono text-sm shrink-0">
              →
            </div>

            {/* Output */}
            <PipelineNode title="Output" status={outputStatus}>
              {state.final_disposition !== "pending" ? (
                <span
                  className="text-[9px] font-mono text-gray-300 leading-relaxed line-clamp-3"
                  title={state.final_disposition}
                >
                  {state.final_disposition}
                </span>
              ) : (
                <span className="text-[9px] text-gray-700 font-mono">
                  pending…
                </span>
              )}
            </PipelineNode>
          </div>

          {/* Processing log terminal */}
          <div className="flex-1 bg-black/80 border border-gray-800 rounded p-2 overflow-y-auto min-h-0">
            <div className="text-[9px] font-mono text-gray-600 mb-1 border-b border-gray-800 pb-1">
              ▸ PROCESSING LOG
            </div>
            {displayedLogs.length === 0 ? (
              <span className="text-[10px] font-mono text-gray-700">
                Waiting for log entries…
              </span>
            ) : (
              displayedLogs.map((entry, i) => (
                <div
                  key={i}
                  className="text-[10px] font-mono text-green-400/80 leading-relaxed"
                >
                  <span className="text-gray-700 mr-1">
                    [{String(i + 1).padStart(2, "0")}]
                  </span>
                  {entry}
                </div>
              ))
            )}
            <div ref={logEndRef} />
          </div>
        </>
      )}
    </div>
  );
}
