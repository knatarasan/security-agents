import { usePipelineStats } from "../hooks/usePipelineStats";
import { cn } from "../lib/utils";

interface StatTileProps {
  label: string;
  value: number;
  icon: string;
  colorClass: string;
  pulse?: boolean;
}

function StatTile({ label, value, icon, colorClass, pulse }: StatTileProps) {
  return (
    <div className="flex items-center gap-2 px-4 py-2 bg-gray-900/60 border border-gray-800 rounded">
      <span className="text-base leading-none">{icon}</span>
      <div className="flex flex-col">
        <span
          className={cn(
            "text-lg font-bold font-mono leading-none",
            colorClass,
            pulse && value > 0 ? "animate-pulse" : ""
          )}
        >
          {value}
        </span>
        <span className="text-[10px] text-gray-500 uppercase tracking-wider leading-tight mt-0.5">
          {label}
        </span>
      </div>
    </div>
  );
}

export function MetricsBar() {
  const { metrics, copilotEnabled } = usePipelineStats();

  return (
    <div className="flex items-center gap-2 px-4 py-1.5 bg-gray-900 border-b border-gray-800 shrink-0">
      <StatTile
        label="Processed"
        value={metrics.total_processed}
        icon="⚡"
        colorClass="text-gray-200"
      />
      <StatTile
        label="Escalated"
        value={metrics.escalated}
        icon="⚠"
        colorClass="text-orange-400"
      />
      <StatTile
        label="Closed"
        value={metrics.closed}
        icon="✓"
        colorClass="text-green-400"
      />
      <StatTile
        label="Critical"
        value={metrics.critical_findings}
        icon="🔴"
        colorClass="text-red-400"
        pulse
      />
      <div className="ml-auto flex items-center gap-1.5">
        <span
          className={cn(
            "h-1.5 w-1.5 rounded-full",
            copilotEnabled ? "bg-green-400" : "bg-gray-600"
          )}
        />
        <span className="text-[10px] text-gray-500 font-mono">
          {copilotEnabled ? "CopilotKit ON" : "CopilotKit OFF"}
        </span>
      </div>
    </div>
  );
}
