import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://localhost:8000', changeOrigin: true },
      '/health': { target: 'http://localhost:8000', changeOrigin: true },
      '/score': { target: 'http://localhost:8000', changeOrigin: true },
      '/prometheus': { target: 'http://localhost:9090', changeOrigin: true, rewrite: p => p.replace(/^\/prometheus/, '') },
    },
  },
  build: { outDir: 'dist', sourcemap: false },
})
