import { createRequire } from 'node:module';

const require = createRequire(new URL('./package.json', import.meta.url));

const config = {
  printWidth: 100,
  tabWidth: 2,
  useTabs: false,
  singleQuote: true,
  semi: true,
  trailingComma: 'all',
  endOfLine: 'lf',
  plugins: [require.resolve('prettier-plugin-sql')],
  overrides: [
    { files: '*.sql', options: { parser: 'sql', language: 'postgresql' } },
    { files: '*.json.example', options: { parser: 'json' } },
  ],
};

export default config;
