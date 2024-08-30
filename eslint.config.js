import globals from 'globals'
import pluginPrettier from 'eslint-plugin-prettier/recommended'

export default [
  { languageOptions: { globals: globals.node } },
  pluginPrettier,
  {
    rules: {
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }]
    },
    ignores: [
      'coverage',
      'lib',
      'tmp'
    ]
  }
]
