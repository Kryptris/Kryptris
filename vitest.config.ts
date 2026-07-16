import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'node',
    include: ['tests/**/*.test.{ts,tsx}'],
    setupFiles: ['tests/setup.ts'],
    // Kryptografie- und Dateisystemtests konkurrieren auf Windows-Runnern stark um Ressourcen.
    // Seriell und mit einem realistischen Timeout bleiben sie aussagekräftig statt flake-anfällig.
    fileParallelism: false,
    testTimeout: 20_000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      exclude: ['src/main/index.ts', 'src/preload/index.ts'],
    },
  },
});
