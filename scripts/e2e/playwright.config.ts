import { defineConfig } from "@playwright/test";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 2,
  timeout: 30_000,
  reporter: [
    ["list"],
    ["junit", { outputFile: root + ".scratch/oidc-pro/tmp/browser-junit.xml" }],
  ],
  outputDir: root + ".scratch/oidc-pro/tmp/browser-results",
  use: {
    baseURL: "http://127.0.0.1:43181",
    locale: "en-US",
    serviceWorkers: "block",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    launchOptions: process.env.CHROMIUM_EXECUTABLE
      ? { executablePath: process.env.CHROMIUM_EXECUTABLE }
      : {},
  },
  webServer: {
    command: "python3 scripts/serve-frontend.py",
    cwd: root,
    url: "http://127.0.0.1:43181/session",
    reuseExistingServer: false,
    timeout: 20_000,
  },
});
