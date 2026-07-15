import { resolve } from 'node:path';

import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    target: 'node24',
    outDir: 'dist/main/preload',
    emptyOutDir: true,
    copyPublicDir: false,
    sourcemap: false,
    minify: false,
    lib: {
      entry: resolve(process.cwd(), 'src/preload/index.ts'),
      formats: ['cjs'],
      fileName: () => 'index.js',
    },
    rollupOptions: {
      external: ['electron'],
    },
  },
});
