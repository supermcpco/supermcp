import { defineConfig } from "@hey-api/openapi-ts";

// Input is produced by `bin/supermcp openapi > web/openapi.json` (see the
// Makefile). Output is committed so CI can check it is fresh.
export default defineConfig({
  input: "./openapi.json",
  output: { path: "./src/api" },
  plugins: [
    "@hey-api/typescript",
    "@hey-api/sdk",
    { name: "@hey-api/client-fetch", baseUrl: "" },
    "@tanstack/react-query",
  ],
});
