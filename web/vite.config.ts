import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Em desenvolvimento, `npm run dev` encaminha /api para o servidor Go local.
export default defineConfig({
  plugins: [react()],
  // public/.keep é copiado para dist/, mantendo o diretório que o Go embute.
  build: { outDir: "dist", emptyOutDir: true },
  server: {
    proxy: {
      "/api": { target: "https://localhost:8443", secure: false, changeOrigin: true },
    },
  },
});
