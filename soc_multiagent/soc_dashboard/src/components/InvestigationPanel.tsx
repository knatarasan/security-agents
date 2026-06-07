import type { SOCState, InvestigationReport } from "../types/soc";
import { hasInvestigation, hasTriageResult } from "../socStateGuards";
import { cn, classColor } from "../lib/utils";

interface InvestigationPanelProps {
  socState: SOCState | null;
}

function severityAssessmentColor(
  sev: InvestigationReport["severity_assessment"]
): string {
  if (sev === "critical") return "text-red-400 border-red-500/40 bg-red-500/10";
  if (sev === "high") return "text-orange-400 border-orange-500/40 bg-orange-500/10";
  return "text-yellow-400 border-yellow-500/40 bg-yellow-500/10";
}

export function InvestigationPanel({ socState }: InvestigationPanelProps) {
  const investigation = socState && hasInvestigation(socState.investigation_report)
    ? socState.investigation_report
    : null;

  const triage = socState && hasTriageResult(socState.triage_result)
    ? socState.triage_result
    : null;

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* ─── INVESTIGATION REPORT ─── */}
      {investigation && (
        <>
          <div className="flex items-center gap-2 px-3 py-2 bg-gray-900 border-b border-gray-800 shrink-0">
            <span className="text-[11px] font-mono font-semibold text-red-400 tracking-widest uppercase">
              Investigation Report
            </span>
            <span
              className={cn(
                "text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border uppercase",
                severityAssessmentColor(investigation.severity_assessment)
              )}
            >
              {investigation.severity_assessment}
            </span>
          </div>

          <div className="flex-1 overflow-y-auto p-3 space-y-2.5">
            {/* Badges row */}
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[9px] font-mono text-orange-400 border border-orange-500/40 bg-orange-500/10 px-1.5 py-0.5 rounded uppercase">
                {investigation.mitre_technique}
              </span>
              <span className="text-[9px] font-mono text-blue-400 border border-blue-500/40 bg-blue-500/10 px-1.5 py-0.5 rounded">
                {investigation.attack_stage}
              </span>
            </div>

            {/* Analyst notes */}
            <div>
              <div className="text-[9px] font-mono text-gray-600 uppercase tracking-wider mb-1">
                Analyst Notes
              </div>
              <div className="bg-black/60 border border-gray-800 rounded p-2 max-h-16 overflow-y-auto">
                <p className="text-[10px] font-mono text-gray-400 leading-relaxed">
                  {investigation.analyst_notes}
                </p>
              </div>
            </div>

            {/* IOC summary */}
            {investigation.ioc_summary.length > 0 && (
              <div>
                <div className="text-[9px] font-mono text-gray-600 uppercase tracking-wider mb-1">
                  IOC Summary
                </div>
                <div className="flex flex-wrap gap-1">
                  {investigation.ioc_summary.map((ioc, i) => (
                    <code
                      key={i}
                      className="text-[9px] font-mono text-green-400 bg-green-500/10 border border-green-500/30 px-1.5 py-0.5 rounded"
                    >
                      {ioc}
                    </code>
                  ))}
                </div>
              </div>
            )}

            {/* Containment steps */}
            {investigation.containment_steps.length > 0 && (
              <div>
                <div className="text-[9px] font-mono text-gray-600 uppercase tracking-wider mb-1">
                  Containment Steps
                </div>
                <ol className="space-y-0.5">
                  {investigation.containment_steps.map((step, i) => (
                    <li
                      key={i}
                      className="flex items-start gap-1.5 text-[10px] font-mono text-gray-400"
                    >
                      <span className="text-gray-700 shrink-0 w-4 text-right">
                        {i + 1}.
                      </span>
                      <span>{step}</span>
                    </li>
                  ))}
                </ol>
              </div>
            )}

            {/* Threat actor + recommended response */}
            <div className="grid grid-cols-2 gap-2">
              <div>
                <div className="text-[9px] font-mono text-gray-600 uppercase tracking-wider mb-1">
                  Threat Actor
                </div>
                <p className="text-[10px] font-mono text-gray-400 leading-relaxed">
                  {investigation.threat_actor_profile}
                </p>
              </div>
              <div>
                <div className="text-[9px] font-mono text-gray-600 uppercase tracking-wider mb-1">
                  Recommended Response
                </div>
                <p className="text-[10px] font-mono text-gray-400 leading-relaxed">
                  {investigation.recommended_response}
                </p>
              </div>
            </div>

            {/* Time to investigate */}
            {investigation.time_to_investigate && (
              <div className="text-[9px] font-mono text-gray-700">
                ⏱ Time to investigate: {investigation.time_to_investigate}
              </div>
            )}
          </div>
        </>
      )}

      {/* ─── TRIAGE SUMMARY (no investigation yet) ─── */}
      {!investigation && triage && (
        <>
          <div className="flex items-center gap-2 px-3 py-2 bg-gray-900 border-b border-gray-800 shrink-0">
            <span className="text-[11px] font-mono font-semibold text-gray-300 tracking-widest uppercase">
              Triage Summary
            </span>
            <span
              className={cn(
                "text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border",
                triage.likely_classification === "TP"
                  ? "text-red-400 border-red-500/40 bg-red-500/10"
                  : "text-green-400 border-green-500/40 bg-green-500/10"
              )}
            >
              {triage.likely_classification}
            </span>
          </div>

          <div className="flex-1 overflow-y-auto p-3 space-y-2.5">
            {/* Confidence bar */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-[9px] font-mono text-gray-600 uppercase tracking-wider">
                  Confidence
                </span>
                <span
                  className={cn(
                    "text-[10px] font-mono font-bold",
                    classColor(triage.likely_classification)
                  )}
                >
                  {Math.round(triage.triage_confidence * 100)}%
                </span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-1.5">
                <div
                  className={cn(
                    "h-1.5 rounded-full transition-all",
                    triage.likely_classification === "TP"
                      ? "bg-red-500"
                      : "bg-green-500"
                  )}
                  style={{ width: `${Math.round(triage.triage_confidence * 100)}%` }}
                />
              </div>
            </div>

            {/* Summary */}
            <div>
              <div className="text-[9px] font-mono text-gray-600 uppercase tracking-wider mb-1">
                Summary
              </div>
              <p className="text-[10px] font-mono text-gray-400 leading-relaxed">
                {triage.triage_summary}
              </p>
            </div>

            {/* Key indicators */}
            {triage.key_indicators.length > 0 && (
              <div>
                <div className="text-[9px] font-mono text-gray-600 uppercase tracking-wider mb-1">
                  Key Indicators
                </div>
                <ul className="space-y-0.5">
                  {triage.key_indicators.map((ind, i) => (
                    <li
                      key={i}
                      className="flex items-start gap-1.5 text-[10px] font-mono text-gray-400"
                    >
                      <span className="text-blue-400 shrink-0">▸</span>
                      <span>{ind}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Risk factors */}
            {triage.risk_factors.length > 0 && (
              <div>
                <div className="text-[9px] font-mono text-gray-600 uppercase tracking-wider mb-1">
                  Risk Factors
                </div>
                <ul className="space-y-0.5">
                  {triage.risk_factors.map((rf, i) => (
                    <li
                      key={i}
                      className="flex items-start gap-1.5 text-[10px] font-mono text-orange-400/80"
                    >
                      <span className="text-orange-500 shrink-0">⚠</span>
                      <span>{rf}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Final disposition */}
            {socState && socState.final_disposition !== "pending" && (
              <div className="border-t border-gray-800 pt-2">
                <div className="text-[9px] font-mono text-gray-600 uppercase tracking-wider mb-1">
                  Final Disposition
                </div>
                <span className="text-[10px] font-mono text-blue-400">
                  {socState.final_disposition}
                </span>
              </div>
            )}
          </div>
        </>
      )}

      {/* ─── EMPTY ─── */}
      {!investigation && !triage && (
        <div className="flex flex-col items-center justify-center h-full text-gray-700">
          <div className="text-2xl mb-2 opacity-30">🔍</div>
          <span className="text-xs font-mono text-gray-600">
            Waiting for pipeline results…
          </span>
        </div>
      )}
    </div>
  );
}
