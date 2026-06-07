import { useState, useEffect, useCallback } from "react";
import { CopilotSidebar } from "@copilotkit/react-ui";
import { Toaster } from "react-hot-toast";
import type { Alert, SOCState } from "./types/soc";
import { MetricsBar } from "./components/MetricsBar";
import { AlertFeed } from "./components/AlertFeed";
import { PipelineViewer } from "./components/PipelineViewer";
import { InvestigationPanel } from "./components/InvestigationPanel";
import { ActionPanel } from "./components/ActionPanel";

interface AppProps {
  copilotEnabled: boolean;
}

export default function App({ copilotEnabled }: AppProps) {
  const [activeAlert, setActiveAlert] = useState<Alert | null>(null);
  const [socState, setSocState] = useState<SOCState | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (!copilotEnabled) return;
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        setSidebarOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [copilotEnabled]);

  const handleAlertSelect = useCallback((alert: Alert) => {
    setActiveAlert(alert);
    setSocState(null);
  }, []);

  const handlePipelineComplete = useCallback((state: SOCState) => {
    setSocState(state);
  }, []);

  return (
    <div className="flex flex-col h-screen bg-gray-950 text-gray-100 font-sans overflow-hidden">
      <header className="flex items-center justify-between px-4 py-2 bg-gray-900 border-b border-gray-800 shrink-0">
        <div className="flex items-center gap-3">
          <span className="text-green-400 font-bold font-mono text-sm">
            SOC OPERATIONS CENTER
          </span>
          <span className="text-gray-500 text-xs font-mono">
            LangGraph + CopilotKit
          </span>
        </div>
        <div className="flex items-center gap-2 text-xs text-gray-400">
          <span className="text-green-400">LIVE</span>
          {copilotEnabled && (
            <>
              <span className="ml-3 text-gray-600 font-mono">
                Ctrl+K - AI Assistant
              </span>
              <button
                onClick={() => setSidebarOpen((v) => !v)}
                className="ml-2 px-2 py-0.5 rounded border border-gray-700 bg-gray-800 text-gray-400 hover:text-gray-200 hover:border-gray-600 font-mono text-[10px] transition-colors"
              >
                {sidebarOpen ? "Close AI" : "Open AI"}
              </button>
            </>
          )}
        </div>
      </header>

      <MetricsBar />

      <div className="flex flex-1 overflow-hidden">
        <div className="w-[35%] border-r border-gray-800 overflow-hidden flex flex-col">
          <AlertFeed
            onAlertSelect={handleAlertSelect}
            activeAlertId={activeAlert?.alert_id ?? null}
          />
        </div>

        <div className="w-[40%] border-r border-gray-800 overflow-hidden flex flex-col">
          <div className="flex-[3] border-b border-gray-800 overflow-hidden">
            <PipelineViewer
              activeAlert={activeAlert}
              onComplete={handlePipelineComplete}
              copilotEnabled={copilotEnabled}
            />
          </div>

          <div className="flex-[2] overflow-hidden">
            <InvestigationPanel socState={socState} />
          </div>
        </div>

        <div className="w-[25%] overflow-hidden">
          <ActionPanel
            activeAlert={activeAlert}
            socState={socState}
            copilotEnabled={copilotEnabled}
          />
        </div>
      </div>

      <Toaster
        position="bottom-right"
        toastOptions={{
          style: {
            background: "#1f2937",
            color: "#f9fafb",
            border: "1px solid #374151",
            fontFamily: "JetBrains Mono, Fira Code, monospace",
            fontSize: "12px",
          },
          duration: 4000,
        }}
      />

      {copilotEnabled && (
        <CopilotSidebar
          instructions="You are a SOC analyst AI assistant. Help the analyst investigate security alerts, interpret triage results, and recommend appropriate response actions. You can isolate hosts, create tickets, and block IPs. Always explain your reasoning."
          defaultOpen={sidebarOpen}
          labels={{
            title: "SOC AI Assistant",
            initial: "How can I help you analyze this alert?",
          }}
          clickOutsideToClose
        />
      )}
    </div>
  );
}
