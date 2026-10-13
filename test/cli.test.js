import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startDnsServer } from './server.js';
import { goodZone } from './helpers.js';

const BIN = fileURLToPath(new URL('../bin/dns-sentinel.js', import.meta.url));
const dir = mkdtempSync(join(tmpdir(), 'dnss-'));
const run = (args, cwd = dir) => new Promise((resolve) => {
  const p = spawn(process.execPath, [BIN, ...args], { cwd, env: { ...process.env, NO_COLOR: '1' } });
  let out = '', err = ''; p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d));
  p.on('close', (code) => resolve({ code, out, err }));
});
const zone = { ...goodZone(), ...goodZone('bad.test'), 'weak.test': { TXT: ['v=spf1 +all'], SOA: [{ nsname: 'x' }] }, 'old.good.test': { CNAME: ['gone-bucket.s3.amazonaws.com'] } };
zone['bad.test'] = { ...zone['bad.test'], TXT: [], DS: [], DNSKEY: [], AD: false, CAA: [] };
zone['_dmarc.bad.test'] = { TXT: ['v=DMARC1; p=none'] };
let srv, base;
test.before(async () => { srv = await startDnsServer(zone); base = ['--resolver', srv.server, '--dnssec-doh', srv.doh, '--no-http']; });
test.after(() => srv.close());

test('exit 0 clean, 1 findings, 2 errors and usage', async () => {
  const ok = await run(['good.test', ...base, '--fail-on', 'low']);
  assert.equal(ok.code, 0, ok.out); assert.match(ok.out, /✔ no findings/);
  const bad = await run(['bad.test', ...base]);
  assert.equal(bad.code, 1); assert.match(bad.out, /spf-missing/); assert.match(bad.out, /↳ fix:/);
  assert.equal((await run(['weak.test', ...base, '--fail-on', 'critical'])).code, 1);
  assert.equal((await run(['bad.test', ...base, '--fail-on', 'none'])).code, 0);
  assert.equal((await run(['nx.test', ...base])).code, 2);
  assert.equal((await run([])).code, 2);
  assert.equal((await run(['not a domain'])).code, 2);
  assert.equal((await run(['good.test', '--fail-on', 'x'])).code, 2);
  assert.equal((await run(['good.test', '--checks', 'nope', ...base])).code, 2);
});
test('multiple domains, --checks/--skip, subdomains file, DKIM selectors', async () => {
  const f = join(dir, 'subs.txt'); writeFileSync(f, '# subs\nold\nwww\n');
  const j = JSON.parse((await run(['good.test', 'bad.test', ...base, '--subdomains-file', f, '--dkim-selector', 's1,s2', '-f', 'json'])).out);
  assert.deepEqual(j.domains.map((d) => d.domain), ['good.test', 'bad.test']);
  assert.ok(j.findings.some((x) => x.rule === 'subdomain-takeover' && x.name === 'old.good.test'));
  assert.ok(j.findings.some((x) => x.rule === 'dkim-missing' && x.name === 's2._domainkey.good.test'));
  const only = JSON.parse((await run(['bad.test', ...base, '--checks', 'spf,caa', '-f', 'json'])).out);
  assert.deepEqual([...new Set(only.findings.map((x) => x.rule.split('-')[0]))].sort(), ['caa', 'spf']);
  const skip = JSON.parse((await run(['bad.test', ...base, '--skip', 'dnssec,caa', '-f', 'json'])).out);
  assert.ok(!skip.findings.some((x) => /^(dnssec|caa)/.test(x.rule)));
});
test('DoH for everything via --doh <url>', async () => {
  const r = JSON.parse((await run(['bad.test', '--doh', srv.doh, '--no-http', '-f', 'json'])).out);
  assert.match(r.resolver, /^DoH http:\/\/127\.0\.0\.1/);
  assert.ok(r.findings.some((x) => x.rule === 'dnssec-disabled'));
});
test('config file: allowlist with expiry, severity, domains', async () => {
  const cfg = join(dir, 'cfg.json');
  writeFileSync(cfg, JSON.stringify({ domains: ['bad.test'], failOn: 'medium', severity: { 'dmarc-no-rua': 'off', 'caa-missing': 'high' }, allow: [{ rule: 'spf-missing', domain: 'bad.test', reason: 'parked', expires: '2099-01-01' }, { rule: 'dnssec-*', reason: 'registrar lacks support', expires: '2020-01-01' }] }));
  const r = await run([...base, '-c', cfg, '-f', 'json']);
  const j = JSON.parse(r.out);
  assert.equal(r.code, 1);
  assert.ok(!j.findings.some((x) => x.rule === 'spf-missing' || x.rule === 'dmarc-no-rua'));
  assert.equal(j.findings.find((x) => x.rule === 'caa-missing').severity, 'high');
  assert.ok(j.findings.some((x) => x.rule === 'allow-expired'));
  writeFileSync(cfg, JSON.stringify({ allow: [{ rule: 'spf-missing' }] }));
  const e = await run(['bad.test', ...base, '-c', cfg]); assert.equal(e.code, 2); assert.match(e.err, /reason/);
  writeFileSync(join(dir, '.dns-sentinel.json'), JSON.stringify({ severity: { 'spf-missing': 'off', 'dmarc-policy-none': 'off', 'dmarc-no-rua': 'off', 'caa-missing': 'off', 'dnssec-disabled': 'off' } }));
  assert.equal((await run(['bad.test', ...base, '--fail-on', 'low'])).code, 0);
});
test('json, sarif, markdown outputs and files', async () => {
  const o = (n) => join(dir, n);
  const r = await run(['bad.test', ...base, '-f', 'sarif', '--json', o('r.json'), '--sarif', o('r.sarif'), '--markdown', o('r.md'), '-c', join(dir, 'none.json')].filter((x) => !x.endsWith('none.json') && x !== '-c'), mkdtempSync(join(tmpdir(), 'x-')));
  const s = JSON.parse(r.out);
  assert.equal(s.version, '2.1.0');
  for (const x of s.runs[0].results) assert.equal(s.runs[0].tool.driver.rules[x.ruleIndex].id, x.ruleId);
  assert.deepEqual(JSON.parse(readFileSync(o('r.sarif'), 'utf8')), s);
  assert.ok(JSON.parse(readFileSync(o('r.json'), 'utf8')).domains[0].summary.mx);
  assert.match(readFileSync(o('r.md'), 'utf8'), /### bad\.test/);
  assert.match((await run(['bad.test', ...base, '-f', 'markdown'], mkdtempSync(join(tmpdir(), 'y-')))).out, /❌ Failing/);
});
test('--help, --version, --list-rules', async () => {
  assert.match((await run(['--help'])).out, /Exit codes/);
  assert.match((await run(['--version'])).out, /^\d+\.\d+\.\d+/);
  assert.match((await run(['--list-rules'])).out, /subdomain-takeover/);
});
