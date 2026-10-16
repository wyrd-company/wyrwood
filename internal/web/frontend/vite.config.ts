// ---
// relationships:
//   implements: web-interface
// ---
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath, URL } from "node:url";

export default defineConfig(({ isSsrBuild }) => ({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  base: "/static/",
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    rollupOptions: isSsrBuild
      ? { output: { entryFileNames: "render.mjs" } }
      : undefined,
  },
  ssr: { noExternal: true },
  test: { environment: "jsdom", setupFiles: ["./src/test-setup.ts"] },
}));
