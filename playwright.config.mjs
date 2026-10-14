/** Jason Stys: real local evidence viewer across three browser engines and mobile, with no artifact/cache uploads. */
/* BEGIN CODE MAP (generated; npm run code-map)
END CODE MAP */
import { defineConfig, devices } from "@playwright/test";
export default defineConfig({
  testDir: "tests/e2e",
  workers: 1,
  retries: 0,
  reporter: [["list"], ["json", { outputFile: "out/browser.json" }]],
  use: {
    baseURL: "http://127.0.0.1:53034",
    trace: "off",
    screenshot: "off",
    video: "off",
  },
  webServer: {
    command:
      process.platform === "win32"
        ? '".venv/Scripts/python.exe" -m cial serve --port 53034'
        : "python -m cial serve --port 53034",
    url: "http://127.0.0.1:53034/health",
    reuseExistingServer: false,
    timeout: 30000,
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
    { name: "mobile", use: { ...devices["Pixel 7"] } },
  ],
});
