import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
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
      },
    },
  },
});
