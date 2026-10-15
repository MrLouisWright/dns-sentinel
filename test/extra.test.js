import test from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync, deflateRawSync } from 'node:zlib';
import { run, rules, find, goodZone } from './helpers.js';
import { parseBimi, checkArcHeaders, detectProviders, snapshot, diffBaseline, parseDmarcReport, summarizeDmarcReports, unpackReport } from '../src/index.js';

test('BIMI: valid with VMC is clean; bad logo, no a=, unenforced DMARC', async () => {
  const z = goodZone(); z['default._bimi.good.test'] = { TXT: ['v=BIMI1; l=https://good.test/logo.svg; a=https://good.test/vmc.pem'] };
  const r = await run(z);
  assert.deepEqual(rules(r), []); assert.match(r.domains[0].summary.bimi, /BIMI1/);
  const z2 = goodZone(); z2['default._bimi.good.test'] = { TXT: ['v=BIMI1; l=http://good.test/logo.png'] }; z2['_dmarc.good.test'] = { TXT: ['v=DMARC1; p=none; rua=mailto:d@good.test'] };
  const r2 = await run(z2);
  for (const x of ['bimi-invalid', 'bimi-no-certificate', 'bimi-dmarc-not-enforced']) assert.ok(find(r2, x), x);
  assert.deepEqual(parseBimi('v=BIMI1;').errors, ['missing l= (logo URL)']);
});
test('DKIM selectors from detected providers', async () => {
  assert.deepEqual(detectProviders(['aspmx.l.google.com'], 'v=spf1 include:sendgrid.net -all').map((p) => p.name), ['Google Workspace', 'SendGrid']);
  const z = goodZone(); z['good.test'].MX = [{ exchange: 'good-test.mail.protection.outlook.com', priority: 0 }]; z['good-test.mail.protection.outlook.com'] = { A: ['192.0.2.1'] };
  const r = await run(z, { dkimProviders: true });
  assert.deepEqual(r.domains[0].summary.mailProviders, ['Microsoft 365']);
  assert.ok(['selector1', 'selector2'].every((s) => s in r.domains[0].summary.dkim));
});
test('SPF near the lookup limit', async () => {
  const z = goodZone(); const inc = Array.from({ length: 8 }, (_, i) => `include:s${i}.mail.test`).join(' ');
  z['good.test'].TXT = [`v=spf1 ${inc} -all`]; for (let i = 0; i < 8; i++) z[`s${i}.mail.test`] = { TXT: ['v=spf1 ip4:192.0.2.1 -all'] };
  assert.ok(find(await run(z), 'spf-lookups-near-limit'));
});
test('baseline: snapshot, record-changed and spf-lookups-increased', async () => {
  const base = snapshot(await run(goodZone()));
  assert.equal(base.domains['good.test'].spfLookups, 1);
  assert.deepEqual(rules(await run(goodZone(), { baseline: base })), []);
  const z = goodZone(); z['_dmarc.good.test'] = { TXT: ['v=DMARC1; p=quarantine; rua=mailto:d@good.test'] }; z['_spf.mail.test'] = { TXT: ['v=spf1 include:extra.mail.test -all'] }; z['extra.mail.test'] = { TXT: ['v=spf1 ip4:192.0.2.9 -all'] };
  const r = await run(z, { baseline: base });
  assert.ok(find(r, 'record-changed', (f) => /dmarc changed/.test(f.message)));
  assert.ok(find(r, 'spf-lookups-increased'));
  assert.ok(diffBaseline(base, r).some((c) => c.field === 'spfLookups' && c.after === 2));
});
const XML = `<?xml version="1.0"?><feedback><report_metadata><org_name>google.com</org_name><email>noreply@google.com</email><report_id>123</report_id><date_range><begin>1760400000</begin><end>1760486399</end></date_range></report_metadata>
<policy_published><domain>good.test</domain><adkim>r</adkim><aspf>r</aspf><p>reject</p><pct>100</pct></policy_published>
<record><row><source_ip>192.0.2.10</source_ip><count>40</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>good.test</header_from></identifiers><auth_results><dkim><domain>good.test</domain><selector>s1</selector><result>pass</result></dkim><spf><domain>good.test</domain><result>pass</result></spf></auth_results></record>
<record><row><source_ip>203.0.113.66</source_ip><count>10</count><policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>good.test</header_from></identifiers><auth_results><spf><domain>evil.test</domain><result>fail</result></spf></auth_results></record></feedback>`;
function zip(name, data) {
  const comp = deflateRawSync(Buffer.from(data)); const n = Buffer.from(name); const h = Buffer.alloc(30);
  h.writeUInt32LE(0x04034b50, 0); h.writeUInt16LE(20, 4); h.writeUInt16LE(0, 6); h.writeUInt16LE(8, 8); h.writeUInt32LE(comp.length, 18); h.writeUInt32LE(data.length, 22); h.writeUInt16LE(n.length, 26); h.writeUInt16LE(0, 28);
  return Buffer.concat([h, n, comp]);
}
test('DMARC aggregate reports: xml, gzip, zip; summary', () => {
  const r = parseDmarcReport(XML);
  assert.equal(r.orgName, 'google.com'); assert.equal(r.policy.p, 'reject'); assert.equal(r.records.length, 2); assert.equal(r.records[0].dkimAuth[0].selector, 's1');
  assert.equal(unpackReport(gzipSync(XML)), XML);
  assert.equal(unpackReport(zip('google.com!good.test!1!2.xml', XML)), XML);
  const s = summarizeDmarcReports([r, parseDmarcReport(gzipSync(XML))]);
  assert.equal(s.messages, 100); assert.equal(s.passRate, 80); assert.equal(s.failingSources[0].sourceIp, '203.0.113.66'); assert.equal(s.failingSources[0].fail, 20);
  assert.throws(() => parseDmarcReport('<x/>'), /not a DMARC/);
});
test('ARC header-set validation', () => {
  const good = 'ARC-Seal: i=1; a=rsa-sha256; cv=none; d=google.com; s=arc-20160816; b=abc\nARC-Message-Signature: i=1; a=rsa-sha256; d=google.com; s=arc; b=x\nARC-Authentication-Results: i=1; mx.google.com; dkim=pass\nARC-Seal: i=2; cv=pass; d=list.test; s=a; b=def\nARC-Message-Signature: i=2; d=list.test; s=a; b=y\nARC-Authentication-Results: i=2; list.test; arc=pass\n';
  const r = checkArcHeaders(good); assert.equal(r.valid, true); assert.equal(r.instances, 2); assert.deepEqual(r.sealers, ['google.com', 'list.test']);
  const bad = checkArcHeaders(good.replace('cv=pass', 'cv=fail').replace(/ARC-Authentication-Results: i=2[^\n]*\n/, ''));
  assert.equal(bad.valid, false); assert.ok(bad.problems.some((p) => /broken/.test(p))); assert.ok(bad.problems.some((p) => /ArcAuthenticationResults|Authentication/i.test(p)));
  assert.equal(checkArcHeaders('Subject: hi').valid, null);
});
import { spawnSync } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
test('CLI dmarc-report summarises files', () => {
  const d = mkdtempSync(join(tmpdir(), 'dmarc-')); const f = join(d, 'r.xml.gz'); writeFileSync(f, gzipSync(XML));
  const bin = new URL('../bin/dns-sentinel.js', import.meta.url).pathname;
  const r = spawnSync(process.execPath, [bin, 'dmarc-report', f], { encoding: 'utf8' });
  assert.equal(r.status, 0); assert.match(r.stdout, /80% passing/); assert.match(r.stdout, /203\.0\.113\.66/);
  const j = JSON.parse(spawnSync(process.execPath, [bin, 'dmarc-report', f, '-f', 'json'], { encoding: 'utf8' }).stdout);
  assert.equal(j.messages, 50);
  assert.equal(spawnSync(process.execPath, [bin, 'dmarc-report', join(d, 'missing.xml')], { encoding: 'utf8' }).status, 2);
});
