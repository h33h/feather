import prettier from 'eslint-config-prettier';
import next from 'eslint-config-next/core-web-vitals';
const config = [
  ...next,
  prettier,
  {
    settings: { next: { rootDir: 'web/' } },
    rules: { '@next/next/no-html-link-for-pages': ['error', 'web/src/app'] },
  },
  {
    ignores: [
      'node_modules/**',
      'ios/**',
      '.superpowers/**',
      'backend/.venv*/**',
      'backend/.tools/**',
      '.pnpm-store/**',
      'web/.next*/**',
      '.local-data/**',
      'experiments/**',
      'test-results/**',
      'playwright-report/**',
      'blob-report/**',
      'coverage/**',
      '.impeccable/**',
      '**/next-env.d.ts',
    ],
  },
];

export default config;
