import path from "node:path"
import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": path.resolve(__dirname, "./src") } },
  server: { proxy: { "/api": "http://127.0.0.1:8787" } },
  build: {
    cssCodeSplit: false,
    rollupOptions: {
      output: {
        entryFileNames: "assets/app.js",
        chunkFileNames: "assets/[name].js",
        assetFileNames: (asset) => asset.name?.endsWith(".css") ? "assets/app.css" : "assets/[name][extname]",
      },
    },
  },
})
