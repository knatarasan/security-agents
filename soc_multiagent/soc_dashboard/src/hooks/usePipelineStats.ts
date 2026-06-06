import { useState, useEffect, useRef } from "react";
import type { PipelineMetrics } from "../types/soc";
import { fetchPipelineStatus } from "../api/socApi";

const POLL_INTERVAL_MS = 5000;

export function usePipelineStats() {
  const [metrics, setMetrics] = useState<PipelineMetrics>({
    total_processed: 0,
    escalated: 0,
    closed: 0,
    critical_findings: 0,
  });
  const [copilotEnabled, setCopilotEnabled] = useState(false);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;

    const poll = async () => {
      try {
        const data = await fetchPipelineStatus();
        if (!mountedRef.current) return;
        setMetrics(data.stats);
        setCopilotEnabled(data.copilotkit_enabled);
      } catch {
        // silently ignore polling errors — backend may not be up yet
      }
    };

    poll();
    const interval = setInterval(poll, POLL_INTERVAL_MS);

    return () => {
      mountedRef.current = false;
      clearInterval(interval);
    };
  }, []);

  return { metrics, copilotEnabled };
}
