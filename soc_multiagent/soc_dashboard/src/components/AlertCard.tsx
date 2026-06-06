import type { Alert } from "../types/soc";
import {
  cn,
  severityColor,
  severityBorder,
  severityBg,
  formatTime,
  timeAgo,
} from "../lib/utils";

interface AlertCardProps {
  alert: Alert;
  isActive: boolean;
  isProcessing: boolean;
  onClick: () => void;
}

function SeverityBadge({ severity }: { severity: Alert["severity"] }) {
  const label = severity === "MEDIUM" ? "MED" : severity;
  return (
    <span
      className={cn(
        "text-[9px] font-bold font-mono px-1 py-0.5 rounded border leading-none",
        severityColor(severity),
        severityBorder(severity),
        severityBg(severity)
      )}
    >
      {label}
    </span>
  );
}

export function AlertCard({ alert, isActive, isProcessing, onClick }: AlertCardProps) {
  const severityStripe = {
    HIGH: "border-red-500",
    MEDIUM: "border-orange-500",
    LOW: "border-yellow-500",
  }[alert.severity];

  return (
    <button
      onClick={onClick}
      className={cn(
        "w-full text-left p-2.5 border-b border-gray-800 transition-all duration-150",
        "hover:bg-gray-800/60 cursor-pointer",
        "border-l-2",
        severityStripe,
        isActive && "bg-gray-800/80 ring-1 ring-inset ring-blue-500/50",
        isProcessing && "ring-1 ring-inset ring-blue-500/80 animate-pulse bg-blue-500/5"
      )}
    >
      {/* Top row: severity badge + category + time */}
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-1.5">
          <SeverityBadge severity={alert.severity} />
          <span className="text-[9px] font-mono uppercase tracking-widest text-gray-500 bg-gray-800 px-1 py-0.5 rounded">
            {alert.category}
          </span>
          {isProcessing && (
            <span className="text-[9px] font-mono text-blue-400 animate-pulse">
              ◌ PROCESSING
            </span>
          )}
        </div>
        <span className="text-[9px] text-gray-600 font-mono shrink-0 ml-1">
          {timeAgo(alert.timestamp)}
        </span>
      </div>

      {/* Rule name */}
      <div
        className="text-[11px] font-mono text-gray-200 truncate mb-1"
        title={alert.rule_name}
      >
        {alert.rule_name}
      </div>

      {/* IPs */}
      <div className="flex items-center gap-1 text-[10px] font-mono text-gray-500 mb-0.5">
        <span className="text-red-400/80">{alert.source_ip}</span>
        <span className="text-gray-700">→</span>
        <span className="text-blue-400/80">{alert.destination_ip}</span>
      </div>

      {/* Host / user */}
      <div className="flex items-center gap-2 text-[9px] text-gray-600 font-mono">
        <span>
          <span className="text-gray-700">host:</span> {alert.hostname}
        </span>
        <span className="text-gray-700">|</span>
        <span>
          <span className="text-gray-700">user:</span> {alert.user}
        </span>
      </div>

      {/* Timestamp */}
      <div className="text-[9px] text-gray-700 font-mono mt-0.5">
        {formatTime(alert.timestamp)}
      </div>
    </button>
  );
}
