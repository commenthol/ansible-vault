export default [
  {
    input: 'src/index.js',
    output: [
      {
        file: './lib/index.cjs',
        format: 'cjs',
        exports: 'named',
        footer: ''
      }
    ],
    plugins: []
  }
]
