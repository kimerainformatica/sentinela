import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Em desenvolvimento, `npm run dev` encaminha /api para o servidor Go local.
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", emptyOutDir: false },
  server: {
    proxy: {
      "/api": { target: "https://localhost:8443", secure: false, changeOrigin: true },
    },
  },
});
