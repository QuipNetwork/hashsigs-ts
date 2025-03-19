import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    coverage: {
      provider: 'v8', // Using V8 coverage provider
      enabled: true,
      reporter: [
        'text',       // Console output
        'text-summary', // Summary in console
        'json',       // JSON file output
        'html',       // HTML report
        'lcov',       // Standard coverage report format
      ],
      exclude: [
        'node_modules/**',
        'dist/**',
        '**/*.d.ts',
        'coverage/**',
        'vitest.config.ts',
      ],
      all: true,
    }
  }
})
