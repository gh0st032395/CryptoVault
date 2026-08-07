import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// A desktop application served from the local filesystem, not a website.
// Relative asset paths matter; a dev server that reaches outside localhost does
// not, and must not.
export default defineConfig({
  plugins: [svelte()],
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // The interface handles vault contents. A source map shipped in a release
    // would be an odd thing to hand an attacker along with the binary.
    sourcemap: false,
    target: 'es2022',
  },
  server: {
    port: 5173,
    strictPort: true,
  },
  clearScreen: false,
});
