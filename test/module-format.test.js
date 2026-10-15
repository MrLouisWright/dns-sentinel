import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { existsSync } from 'node:fs';

const require = createRequire(import.meta.url);

test('dist is built (run npm run build first)', () => {
  assert.ok(existsSync(new URL('../dist/index.cjs', import.meta.url)));
  assert.ok(existsSync(new URL('../dist/types/index.d.ts', import.meta.url)));
});

test('require() and import() expose the same API', async () => {
  const cjs = require('dns-sentinel');
  const esm = await import('dns-sentinel');
  const esmKeys = Object.keys(esm).filter((k) => k !== 'default').sort();
  assert.ok(esmKeys.length > 0);
  for (const k of esmKeys) assert.equal(typeof cjs[k], typeof esm[k], k);
  if ('VERSION' in esm) assert.equal(cjs.VERSION, esm.VERSION);
});
