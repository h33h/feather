const config = {
  '*.{js,cjs,mjs,jsx,ts,tsx}': [
    'node backend/scripts/lint-staged-js.mjs',
    'node_modules/.bin/prettier --write --ignore-path .prettierignore --ignore-path .gitignore --ignore-path backend/.gitignore',
  ],
  '*.{json,jsonc,css,scss,yml,yaml,sql}':
    'node_modules/.bin/prettier --write --ignore-path .prettierignore --ignore-path .gitignore --ignore-path backend/.gitignore',
  '*.json.example':
    'node_modules/.bin/prettier --write --ignore-path .prettierignore --ignore-path .gitignore --ignore-path backend/.gitignore',
  'backend/**/*.py': [
    'node backend/scripts/ruff.mjs format',
    'node backend/scripts/ruff.mjs check',
  ],
};

export default config;
