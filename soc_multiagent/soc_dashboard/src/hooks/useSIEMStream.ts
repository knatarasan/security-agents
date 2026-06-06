import { useState, useEffect, useCallback, useRef } from "react";
import type { Alert } from "../types/soc";

const MAX_ALERTS = 50;
const RECONNECT_DELAY_MS = 3000;

export function useSIEMStream() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [isStreaming, setIsStreaming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);

  const connect = useCallback(async () => {
    // Cancel any existing connection
    if (abortRef.current) {
      abortRef.current.abort();
    }
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      setIsStreaming(true);
      setError(null);

      const response = await fetch("/api/siem/alerts/stream", {
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`Stream error: HTTP ${response.status}`);
      }

      if (!response.body) {
        throw new Error("No response body for SSE stream");
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const raw = line.slice(6).trim();
          if (!raw) continue;
          try {
            const data = JSON.parse(raw) as Record<string, unknown>;
            // Filter out control events like { event: "stream_complete" }
            if ("event" in data) continue;
            // It's an alert
            const alert = data as unknown as Alert;
            if (!mountedRef.current) return;
            setAlerts((prev) => {
              const updated = [alert, ...prev];
              return updated.slice(0, MAX_ALERTS);
            });
          } catch {
            // ignore parse errors
          }
        }
      }

      // Stream completed naturally — schedule reconnect
      if (mountedRef.current) {
        setIsStreaming(false);
        reconnectTimerRef.current = setTimeout(() => {
          if (mountedRef.current) connect();
        }, RECONNECT_DELAY_MS);
      }
    } catch (err) {
      if (!mountedRef.current) return;
      if (err instanceof Error && err.name === "AbortError") return;
      setIsStreaming(false);
      setError(err instanceof Error ? err.message : "Stream connection failed");
      // Schedule reconnect on error
      reconnectTimerRef.current = setTimeout(() => {
        if (mountedRef.current) connect();
      }, RECONNECT_DELAY_MS);
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    connect();
    return () => {
      mountedRef.current = false;
      if (abortRef.current) abortRef.current.abort();
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
    };
  }, [connect]);

  const reconnect = useCallback(() => {
    connect();
  }, [connect]);

  return { alerts, isStreaming, error, reconnect };
}
