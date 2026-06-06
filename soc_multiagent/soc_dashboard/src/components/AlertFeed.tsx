import { useState } from "react";
import type { Alert } from "../types/soc";
import { useSIEMStream } from "../hooks/useSIEMStream";
import { AlertCard } from "./AlertCard";
import { cn } from "../lib/utils";

interface AlertFeedProps {
  onAlertSelect: (alert: Alert) => void;
  activeAlertId: string | null;
}

export function AlertFeed({ onAlertSelect, activeAlertId }: AlertFeedProps) {
  const { alerts, isStreaming, error, reconnect } = useSIEMStream();
  const [processingAlertId, setProcessingAlertId] = useState<string | null>(null);

  const handleAlertClick = (alert: Alert) => {
    setProcessingAlertId(alert.alert_id);
    onAlertSelect(alert);
  };

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 bg-gray-900 border-b border-gray-800 shrink-0">
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono font-semibold text-gray-300 tracking-widest uppercase">
            Alert Feed
          </span>
          <span className="text-[10px] font-mono bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded">
            {alerts.length}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {isStreaming ? (
            <span className="flex items-center gap-1 text-[10px] text-green-400 font-mono">
              <span className="h-1.5 w-1.5 rounded-full bg-green-400 animate-pulse" />
              LIVE
            </span>
          ) : (
            <button
              onClick={reconnect}
              className="text-[10px] font-mono text-blue-400 hover:text-blue-300 border border-blue-500/40 hover:border-blue-400/60 px-2 py-0.5 rounded transition-colors"
            >
              Reconnect
            </button>
          )}
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="px-3 py-1.5 bg-red-500/10 border-b border-red-500/30 shrink-0">
          <span className="text-[10px] font-mono text-red-400">{error}</span>
        </div>
      )}

      {/* Empty state */}
      {alerts.length === 0 && !error && (
        <div className="flex flex-col items-center justify-center flex-1 text-gray-700">
          <div className="text-2xl mb-2">⚡</div>
          <span className="text-xs font-mono text-gray-600">
            {isStreaming ? "Waiting for alerts…" : "No alerts received"}
          </span>
        </div>
      )}

      {/* Alert list */}
      <div className="flex-1 overflow-y-auto">
        {alerts.map((alert) => (
          <AlertCard
            key={alert.alert_id}
            alert={alert}
            isActive={alert.alert_id === activeAlertId}
            isProcessing={
              alert.alert_id === processingAlertId &&
              alert.alert_id !== activeAlertId
            }
            onClick={() => handleAlertClick(alert)}
          />
        ))}
      </div>

      {/* Footer status */}
      <div
        className={cn(
          "px-3 py-1 border-t border-gray-800 shrink-0",
          "flex items-center justify-between"
        )}
      >
        <span className="text-[9px] font-mono text-gray-700">
          {isStreaming ? "Stream active" : "Stream idle"} · max 50 alerts
        </span>
        <span className="text-[9px] font-mono text-gray-700">
          /api/siem/alerts/stream
        </span>
      </div>
    </div>
  );
}
