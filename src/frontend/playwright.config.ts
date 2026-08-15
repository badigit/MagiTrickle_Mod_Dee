import { defineConfig, devices } from "@playwright/test";

// Порт дев-сервера переопределяется E2E_PORT: 5173 на машине разработчика
// нередко занят другим проектом, и reuseExistingServer молча подсовывает
// тестам ЧУЖОЕ приложение — падения в таком прогоне ничего не значат.
const PORT = Number(process.env.E2E_PORT || 5173);

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: "list",
  outputDir: "node_modules/.playwright-results",
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: "off",
    screenshot: "off",
    video: "off",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: `npm run dev:frontend -- --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}`,
    reuseExistingServer: !process.env.CI,
  },
});
