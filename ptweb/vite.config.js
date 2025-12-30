import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [vue()],
  server: {
    proxy: {
      '/config': 'http://localhost:8080',
      '/generate': 'http://localhost:8080',
      '/run': 'http://localhost:8080',
      '/health': 'http://localhost:8080',
      '/state': 'http://localhost:8080',
      '/stats': 'http://localhost:8080',
    }
  }
})
