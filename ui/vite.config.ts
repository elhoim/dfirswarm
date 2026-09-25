import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const apiPort = process.env.SWARM_UI_PORT || "43173";

// Dev: `npm run ui:dev` serves the React app and proxies /api to the node
// server (`npm run ui:server`). Prod: `vite build` → ui/dist, served by that
// same node server, so one process is the whole local app.
export default defineConfig({
  root: here,
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": resolve(here, "src") },
  },
  server: {
    host: true,
    port: 43174,
    strictPort: false,
    proxy: {
      "/api": { target: `http://127.0.0.1:${apiPort}`, changeOrigin: false },
    },
  },
  build: {
    outDir: resolve(here, "dist"),
    emptyOutDir: true,
    sourcemap: false,
    // Off, not lightningcss: that minifier ships a native binary macOS
    // Gatekeeper blocks on a machine that has not been asked to trust it, and
    // the alternative wants a package this tree does not carry. The stylesheet
    // is small and it is served gzipped, so the difference does not show.
    cssMinify: false,
    rolldownOptions: {
      output: {
        // React, the router and the rest of node_modules in one long-lived
        // chunk; the app code in another. Both stay well under the 500 kB
        // line Vite warns at, and a UI change no longer invalidates the
        // vendor bytes in the browser cache.
        codeSplitting: {
          groups: [{ name: "vendor", test: /node_modules/ }],
        },
      },
    },
  },
});
