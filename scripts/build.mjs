// Build: ESM ships as-is from src/; this emits a bundled CommonJS entry and generated .d.ts.
import * as esbuild from 'esbuild';
import { rmSync } from 'node:fs';
import { execSync } from 'node:child_process';

rmSync('dist', { recursive: true, force: true });
await esbuild.build({
  entryPoints: ['src/index.js'],
  outfile: 'dist/index.cjs',
  bundle: true,
  packages: 'external',
  format: 'cjs',
  platform: 'node',
  target: 'node18',
  define: { 'import.meta.url': '__importMetaUrl' },
  banner: { js: "const __importMetaUrl = require('node:url').pathToFileURL(__filename).href;" },
  logLevel: 'warning',
});
execSync('npx tsc -p tsconfig.build.json', { stdio: 'inherit' });
