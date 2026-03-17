import { mkdir, copyFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const extensionFiles = [
  'manifest.json',
  'background.js',
  'content.js',
  'utils.js',
];

function copyExtensionFiles() {
  return {
    name: 'copy-extension-files',
    async writeBundle(options) {
      const outDir = options.dir || resolve(process.cwd(), 'dist');

      for (const file of extensionFiles) {
        const source = resolve(process.cwd(), file);
        const destination = resolve(outDir, file);
        await mkdir(dirname(destination), { recursive: true });
        await copyFile(source, destination);
      }
    },
  };
}

export default defineConfig({
  plugins: [
    react(),
    copyExtensionFiles(),
  ],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        popup: resolve(process.cwd(), 'popup/index.html'),
      },
    },
  },
});
