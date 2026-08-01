import { defineConfig } from 'vite'
import { resolve } from 'path'
import { nodePolyfills } from 'vite-plugin-node-polyfills'
import wasm from 'vite-plugin-wasm'

export default defineConfig({
  root: 'src',
  plugins: [
    nodePolyfills(),
    wasm()
  ],
  optimizeDeps: {
    exclude: ['@shelby-protocol/clay-codes', '@shelby-protocol/sdk']
  },
  build: {
    outDir: '../dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
  main: resolve(__dirname, 'src/index.html'),
  open: resolve(__dirname, 'src/open.html'),
  register: resolve(__dirname, 'src/register.html')
}
    }
  },
  server: {
    port: 5173
  }
})