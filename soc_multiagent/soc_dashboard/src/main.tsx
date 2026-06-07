import React from "react";
import ReactDOM from "react-dom/client";
import { CopilotKit } from "@copilotkit/react-core";
import "@copilotkit/react-ui/styles.css";
import App from "./App";
import "./index.css";

// Catch any React render errors and display them instead of a silent blank page
class ErrorBoundary extends React.Component<
  { children: React.ReactNode; label?: string },
  { hasError: boolean; error: Error | null }
> {
  constructor(props: { children: React.ReactNode; label?: string }) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }
  render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "#0d1117",
            color: "#ff6b6b",
            fontFamily: "monospace",
            padding: "24px",
            overflow: "auto",
            zIndex: 99999,
          }}
        >
          <div style={{ color: "#58a6ff", marginBottom: 8, fontSize: 14 }}>
            ⚠ {this.props.label ?? "React"} Error
          </div>
          <pre style={{ color: "#ffd93d", fontSize: 13, marginBottom: 16 }}>
            {this.state.error?.message}
          </pre>
          <pre style={{ color: "#8b949e", fontSize: 11 }}>
            {this.state.error?.stack}
          </pre>
        </div>
      );
    }
    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary label="CopilotKit Provider">
      <CopilotKit runtimeUrl="/copilotkit">
        <ErrorBoundary label="App">
          <App />
        </ErrorBoundary>
      </CopilotKit>
    </ErrorBoundary>
  </React.StrictMode>
);
