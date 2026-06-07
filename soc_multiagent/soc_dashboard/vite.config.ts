import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      // CopilotKit's analytics dep (@segment/analytics-node) pulls in node-fetch
      // which uses Node.js built-ins that don't exist in the browser. Alias it
      // to a thin wrapper around the native browser fetch so the bundle works.
      "node-fetch": path.resolve(__dirname, "src/node-fetch-browser.ts"),
    },
  },
  server: {
    proxy: {
      "/api/siem": {
        target: "http://localhost:8081",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/siem/, ""),
      },
      "/api/soc": {
        target: "http://localhost:8082",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/soc/, ""),
      },
      "/copilotkit": {
        target: "http://localhost:8082",
        changeOrigin: true,
        // Ensure trailing slash so FastAPI serves directly (no 307 redirect)
        rewrite: (path) => (path === "/copilotkit" ? "/copilotkit/" : path),
      },
    },
  },
});
