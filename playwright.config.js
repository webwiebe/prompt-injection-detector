import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  timeout: 30000,
  retries: 1,
  use: {
    // Extensions require headed Chromium with persistent context
    // Configuration is handled in the test fixtures
  },
  projects: [
    {
      name: 'chromium-extension',
      use: {
        browserName: 'chromium',
      },
    },
  ],
  reporter: [['list'], ['html', { open: 'never' }]],
});
