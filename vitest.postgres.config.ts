import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: {
    include: ['backend/tests/postgres/**/*.test.ts'],
    maxWorkers: 1,
    testTimeout: 20000,
  },
});
