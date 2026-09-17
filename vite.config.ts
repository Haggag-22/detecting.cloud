import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import { componentTagger } from "lovable-tagger";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => ({
  server: {
    host: "::",
    port: 8080,
    hmr: {
      overlay: true,
    },
    fs: {
      // Allow importing detection rule files from /rules
      allow: ["."],
    },
  },
  plugins: [react(), mode === "development" && componentTagger()].filter(Boolean),
  css: {
    postcss: path.resolve(__dirname, "./config/postcss.config.js"),
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
      "@rules": path.resolve(__dirname, "./rules"),
      "@techniques": path.resolve(__dirname, "./techniques"),
      "@attack-paths": path.resolve(__dirname, "./attack-paths"),
    },
  },
  assetsInclude: ["**/*.yml"],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
  },
}));
