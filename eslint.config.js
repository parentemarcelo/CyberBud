import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';

export default tseslint.config(
  { ignores: ['.output/', '.wxt/', 'node_modules/', 'web-ext-artifacts/', 'coverage/'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      globals: { ...globals.browser, ...globals.webextensions },
    },
    rules: {
      // SPEC §9 S3/S4: no HTML injection, no eval.
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-restricted-properties': [
        'error',
        { property: 'innerHTML', message: 'Render API data as text (SPEC §9 S3).' },
        { property: 'outerHTML', message: 'Render API data as text (SPEC §9 S3).' },
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: 'Render API data as text (SPEC §9 S3).',
        },
      ],
    },
  },
);
