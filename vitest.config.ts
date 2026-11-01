import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: {
    include: ['backend/tests/**/*.test.ts'],
    exclude: ['backend/tests/postgres/**'],
    fileParallelism: true,
    maxWorkers: 2,
    testTimeout: 20000,
  },
});
