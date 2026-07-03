import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

export default defineConfig({
  plugins: [
    cloudflareTest({
      main: "./src/index.js",
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        kvNamespaces: ["MEMOS_KV"],
        compatibilityDate: "2025-01-01",
        bindings: {
          USERNAME: "admin",
          PASSWORD: "memo2024",
          SESSION_SECRET: "test-secret-change-me",
        },
      },
    }),
  ],
});
