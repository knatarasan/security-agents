import React, { useState } from "react";
import type { SOCState, TriageResult } from "../types/soc";
import type { OverridePayload } from "../api/socApi";
import { cn, classColor } from "../lib/utils";

interface CorrectionModalProps {
  socState: SOCState | null;
  onClose: () => void;
  onSubmit: (override: OverridePayload) => void;
}

function hasTriageResult(tr: SOCState["triage_result"]): tr is TriageResult {
  return "likely_classification" in tr;
}

export function CorrectionModal({
  socState,
  onClose,
  onSubmit,
}: CorrectionModalProps) {
  const agentClassification =
    socState && hasTriageResult(socState.triage_result)
      ? socState.triage_result.likely_classification
      : "FP";

  const alertId =
    socState && "alert_id" in socState.alert
      ? (socState.alert as { alert_id: string }).alert_id
      : "";

  const [analystClassification, setAnalystClassification] = useState<"FP" | "TP">(
    agentClassification
  );
  const [reasoning, setReasoning] = useState("");
  const [confidenceAdj, setConfidenceAdj] = useState(0);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reasoning.trim()) return;
    setSubmitting(true);
    onSubmit({
      alert_id: alertId,
      agent_classification: agentClassification,
      analyst_classification: analystClassification,
      reasoning: reasoning.trim(),
      confidence_adjustment: confidenceAdj,
    });
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="bg-gray-900 border border-gray-700 rounded-lg w-full max-w-md mx-4 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
          <span className="text-sm font-mono font-semibold text-gray-200 tracking-wider uppercase">
            Analyst Override
          </span>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-gray-300 font-mono text-lg leading-none"
          >
            ✕
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          {/* Agent's classification (readonly) */}
          <div>
            <label className="block text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-1.5">
              Agent Classification (read-only)
            </label>
            <div className="flex items-center gap-2 bg-black/40 border border-gray-800 rounded px-3 py-2">
              <span
                className={cn(
                  "text-sm font-mono font-bold",
                  classColor(agentClassification)
                )}
              >
                {agentClassification}
              </span>
              <span className="text-[10px] text-gray-600 font-mono">
                — agent's determination
              </span>
            </div>
          </div>

          {/* Analyst's classification toggle */}
          <div>
            <label className="block text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-1.5">
              Your Classification
            </label>
            <div className="flex gap-2">
              {(["FP", "TP"] as const).map((cls) => (
                <button
                  key={cls}
                  type="button"
                  onClick={() => setAnalystClassification(cls)}
                  className={cn(
                    "flex-1 py-1.5 rounded border font-mono text-sm font-bold transition-all",
                    analystClassification === cls
                      ? cls === "TP"
                        ? "bg-red-500/20 border-red-500/60 text-red-400"
                        : "bg-green-500/20 border-green-500/60 text-green-400"
                      : "bg-gray-800 border-gray-700 text-gray-500 hover:border-gray-600"
                  )}
                >
                  {cls}
                </button>
              ))}
            </div>
          </div>

          {/* Reasoning */}
          <div>
            <label className="block text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-1.5">
              Reasoning <span className="text-red-400">*</span>
            </label>
            <textarea
              value={reasoning}
              onChange={(e) => setReasoning(e.target.value)}
              required
              rows={3}
              placeholder="Explain why the agent's classification is incorrect…"
              className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-[11px] font-mono text-gray-300 placeholder-gray-700 resize-none focus:outline-none focus:border-blue-500/60 transition-colors"
            />
          </div>

          {/* Confidence adjustment slider */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">
                Confidence Adjustment
              </label>
              <span
                className={cn(
                  "text-[11px] font-mono font-bold",
                  confidenceAdj > 0
                    ? "text-green-400"
                    : confidenceAdj < 0
                    ? "text-red-400"
                    : "text-gray-500"
                )}
              >
                {confidenceAdj > 0 ? "+" : ""}
                {confidenceAdj.toFixed(1)}
              </span>
            </div>
            <input
              type="range"
              min="-1.0"
              max="1.0"
              step="0.1"
              value={confidenceAdj}
              onChange={(e) => setConfidenceAdj(parseFloat(e.target.value))}
              className="w-full accent-blue-500 cursor-pointer"
            />
            <div className="flex justify-between text-[9px] font-mono text-gray-700 mt-0.5">
              <span>-1.0 (lower)</span>
              <span>0 (no change)</span>
              <span>+1.0 (raise)</span>
            </div>
          </div>

          {/* Buttons */}
          <div className="flex gap-2 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 py-1.5 rounded border border-gray-700 bg-gray-800 text-gray-400 font-mono text-xs hover:border-gray-600 hover:text-gray-300 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!reasoning.trim() || submitting}
              className={cn(
                "flex-1 py-1.5 rounded border font-mono text-xs font-semibold transition-all",
                reasoning.trim() && !submitting
                  ? "bg-blue-500/20 border-blue-500/60 text-blue-400 hover:bg-blue-500/30"
                  : "bg-gray-800 border-gray-700 text-gray-600 cursor-not-allowed"
              )}
            >
              {submitting ? "Submitting…" : "Submit Override"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
