import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// The bundle is emitted straight into the Python package so setuptools ships it
// as package data and `eventiq serve` can read it off disk with no build step.
//
// Everything is inlined into one index.html (assetsInlineLimit: Infinity plus
// the single-file output below) for the same reason the static export is one
// file: it keeps the artifact portable and makes the offline check trivial.
export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    outDir: '../src/eventiq/web',
    emptyOutDir: true,
    target: 'es2020',
    assetsInlineLimit: Number.MAX_SAFE_INTEGER,
    rollupOptions: {
      output: {
        // One JS file, not a chunk graph. The bundle is committed to the repo,
        // so a stable, reviewable filename beats hashed code-split chunks.
        codeSplitting: false,
        entryFileNames: 'app.js',
        assetFileNames: 'app.[ext]',
      },
    },
  },
  server: {
    // `npm run dev` talks to a locally running `eventiq serve`.
    proxy: {
      '/analyze': 'http://127.0.0.1:8000',
    },
  },
})
