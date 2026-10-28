import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// Dev: proxy API/SSE/shots to the Rust backend on :8787.
// Prod: `npm run build` -> dist/, which the Rust server serves directly.
const target = process.env.METSEC_BACKEND || "http://127.0.0.1:8787";

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": path.resolve(__dirname, "src") } },
  server: {
    proxy: {
      "/api": { target, changeOrigin: true },
      "/stream": { target, changeOrigin: true },
      "/shot": { target, changeOrigin: true },
    },
  },
});
