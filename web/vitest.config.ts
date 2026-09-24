import { defineConfig } from "vitest/config";

// The browser suite lives in e2e/ and is run by Playwright, which owns its
// own test() function. Vitest picking those files up produces a confusing
// failure about test() being called in the wrong place, so the two are
// kept apart here rather than by convention.
export default defineConfig({
  test: {
    include: ["src/**/*.test.{ts,tsx}"],
    environment: "node",
  },
});
