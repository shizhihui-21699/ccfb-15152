import { defineConfig, devices } from '@playwright/test';

// 使用系统已缓存的 Chromium（npm install 时跳过了浏览器下载）
export default defineConfig({
  testDir: './tests/e2e',
  timeout: 60_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [['list'], ['html', { open: 'never', outputDir: 'test-report/html' }]],
  use: {
    baseURL: 'http://127.0.0.1:7777',
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
