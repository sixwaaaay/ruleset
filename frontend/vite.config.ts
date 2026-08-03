import { fileURLToPath, URL } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    // Proxy management API and subscription routes to the local backend in dev mode
    proxy: {
      '/rulesets': 'http://127.0.0.1:3500',
      '/r': 'http://127.0.0.1:3500',
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
});