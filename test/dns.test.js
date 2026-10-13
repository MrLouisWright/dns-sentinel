import test from 'node:test';
import assert from 'node:assert/strict';
import { run, rules, find, goodZone, mockFetch } from './helpers.js';
import { MockResolver, auditDomains } from '../src/index.js';

test('CAA: missing, inherited from parent, permissive, critical unknown, no iodef', async () => {
  const base = goodZone();
  const t = (caa) => run({ ...base, 'good.test': { ...base['good.test'], CAA: caa } });
  assert.ok(find(await t([]), 'caa-missing'));
  assert.ok(find(await t([{ critical: 0, tag: 'iodef', value: 'mailto:x@y' }]), 'caa-permissive'));
  const many = await t(['a.com', 'b.com', 'c.com', 'd.com'].map((v) => ({ critical: 0, tag: 'issue', value: v })).concat([{ critical: 0, tag: 'iodef', value: 'mailto:a@b' }]));
  assert.match(find(many, 'caa-permissive').message, /4 CAs/);
  assert.equal(find(await t([{ critical: 128, tag: 'tbs', value: 'x' }, { critical: 0, tag: 'issue', value: 'a.com' }]), 'caa-critical-unknown').severity, 'high');
  assert.ok(find(await t([{ critical: 0, tag: 'issue', value: 'letsencrypt.org' }]), 'caa-no-iodef'));
  const sub = goodZone('app.good.test'); delete sub['app.good.test'].CAA;
  const inh = await run({ ...sub, 'good.test': { CAA: [{ critical: 0, tag: 'issue', value: 'letsencrypt.org' }] }, '_dmarc.app.good.test': { TXT: ['v=DMARC1; p=reject; rua=mailto:a@b.c'] } }, { domains: ['app.good.test'] }, { 'https://mta-sts.app.good.test/.well-known/mta-sts.txt': { body: 'version: STSv1\nmode: enforce\nmx: *.app.good.test\nmax_age: 604800' } });
  assert.equal(find(inh, 'caa-missing'), undefined);
  assert.equal(find(inh, 'caa-no-iodef').name, 'good.test');
});

test('DNSSEC: validated, disabled, no DS, broken (SERVFAIL or DS without AD), weak algorithms', async () => {
  const base = goodZone();
  const t = (o) => run({ ...base, 'good.test': { ...base['good.test'], ...o } });
  assert.deepEqual(rules(await t({})).filter((r) => r.startsWith('dnssec')), []);
  assert.ok(find(await t({ DS: [], DNSKEY: [], AD: false }), 'dnssec-disabled'));
  assert.ok(find(await t({ DS: [], AD: false }), 'dnssec-no-ds'));
  assert.match(find(await t({ AD: false }), 'dnssec-broken').message, /not validated/);
  assert.ok(find(await t({ DNSKEY: [{ flags: 257, protocol: 3, algorithm: 5, key: 'AA' }] }), 'dnssec-weak-algorithm'));
  assert.equal(find(await t({ DS: [{ keyTag: 1, algorithm: 13, digestType: 1, digest: 'aa' }] }), 'dnssec-weak-algorithm').severity, 'low');
  // SERVFAIL from the validating resolver with a DS from elsewhere
  const z = { ...base };
  const resolver = new MockResolver(z);
  const dnssecResolver = new MockResolver({ 'good.test': { SERVFAIL: true } });
  const r = await auditDomains(['good.test'], { resolver, dnssecResolver, fetch: mockFetch({ 'https://mta-sts.good.test/.well-known/mta-sts.txt': { body: 'version: STSv1\nmode: enforce\nmx: *.good.test\nmax_age: 604800' } }), randomLabel: 'p' });
  assert.ok(find(r, 'dnssec-broken'));
});

test('dangling CNAMEs and subdomain takeover with fingerprints', async () => {
  const base = goodZone();
  const z = { ...base,
    'old.good.test': { CNAME: ['gone.example.net'] },
    'assets.good.test': { CNAME: ['bucket-x.s3.amazonaws.com'] },
    'docs.good.test': { CNAME: ['acme.github.io'] }, 'acme.github.io': { A: ['185.199.108.153'] },
    'blog.good.test': { CNAME: ['acme-blog.github.io'] }, 'acme-blog.github.io': { A: ['185.199.108.153'] },
    'app.good.test': { CNAME: ['acme.azurewebsites.net'] },
    'chain.good.test': { CNAME: ['hop.good.test'] }, 'hop.good.test': { CNAME: ['nowhere.good.test'] },
    'empty.good.test': { CNAME: ['noaddr.good.test'] }, 'noaddr.good.test': { TXT: ['x'] },
    'loop1.good.test': { CNAME: ['loop2.good.test'] }, 'loop2.good.test': { CNAME: ['loop1.good.test'] },
  };
  const routes = { 'https://mta-sts.good.test/.well-known/mta-sts.txt': { body: 'version: STSv1\nmode: enforce\nmx: *.good.test\nmax_age: 604800' }, 'https://docs.good.test/': { status: 404, body: "<h1>404</h1> There isn't a GitHub Pages site here." }, 'https://blog.good.test/': { body: '<h1>Our blog</h1>' } };
  const r = await run(z, { subdomains: ['old', 'assets', 'docs', 'blog', 'app', 'chain', 'empty', 'www', 'missing', 'loop1.good.test'] }, routes);
  const at = (rule, n) => find(r, rule, (f) => f.name === n);
  assert.equal(at('dangling-cname', 'old.good.test').severity, 'high');
  assert.match(at('dangling-cname', 'old.good.test').message, /register it/);
  assert.equal(at('subdomain-takeover', 'assets.good.test').severity, 'critical');
  assert.match(at('subdomain-takeover', 'assets.good.test').message, /AWS S3/);
  assert.match(at('subdomain-takeover', 'docs.good.test').message, /GitHub Pages site here/);
  assert.equal(at('subdomain-takeover', 'blog.good.test'), undefined);
  assert.equal(at('takeover-prone-cname', 'blog.good.test').severity, 'info');
  assert.ok(at('subdomain-takeover', 'app.good.test'), 'Azure NXDOMAIN');
  assert.match(at('dangling-cname', 'chain.good.test').message, /nowhere\.good\.test/);
  assert.equal(at('dangling-cname', 'empty.good.test').severity, 'medium');
  assert.match(at('dangling-cname', 'loop1.good.test').message, /loop/);
  assert.equal(r.domains[0].summary.subdomains['www.good.test'], 'no CNAME');
  assert.equal(r.domains[0].summary.subdomains['missing.good.test'], 'NXDOMAIN');
  // --no-http: fingerprints not fetched
  const nh = await run(z, { subdomains: ['docs'], http: false }, {});
  assert.equal(find(nh, 'subdomain-takeover'), undefined); assert.ok(find(nh, 'takeover-prone-cname'));
});

test('wildcards: plain and dangerous wildcard CNAME', async () => {
  const base = goodZone();
  const w = await run({ ...base, '*.good.test': { A: ['192.0.2.99'] } });
  assert.match(find(w, 'wildcard-record').message, /A 192\.0\.2\.99/);
  const wc = await run({ ...base, '*.good.test': { CNAME: ['old-site.herokuapp.com'] } });
  assert.ok(find(wc, 'wildcard-record'));
  assert.match(find(wc, 'subdomain-takeover').message, /^Wildcard \*\.good\.test points to old-site\.herokuapp\.com \(Heroku\)/);
  assert.deepEqual(rules(await run(base)).filter((x) => x === 'wildcard-record'), []);
});

test('zone transfer (opt-in)', async () => {
  const base = goodZone();
  const r = await run(base, { axfr: true, axfrZones: { 'good.test': [{ name: 'good.test', type: 'SOA' }, { name: 'secret.good.test', type: 'A' }] } });
  assert.match(find(r, 'zone-transfer').message, /ns1\.good\.test allows a full zone transfer.*2 records/);
  assert.equal(find(await run(base), 'zone-transfer'), undefined, 'off by default');
  assert.equal(find(await run(base, { axfr: true }), 'zone-transfer'), undefined, 'refused');
});

test('multiple domains, NXDOMAIN and SERVFAIL domains, allowlist with expiry, severity overrides, check selection', async () => {
  const z = { ...goodZone('a.test'), ...goodZone('b.test'), 'broken.test': { SERVFAIL: true } };
  z['b.test'].CAA = [];
  z['_dmarc.a.test'] = { TXT: ['v=DMARC1; p=none; rua=mailto:x@a.test'] };
  const routes = { ...{ 'https://mta-sts.a.test/.well-known/mta-sts.txt': { body: 'version: STSv1\nmode: enforce\nmx: *.a.test\nmax_age: 604800' } }, 'https://mta-sts.b.test/.well-known/mta-sts.txt': { body: 'version: STSv1\nmode: enforce\nmx: *.b.test\nmax_age: 604800' } };
  const r = await run(z, { domains: ['a.test', 'B.test.', 'nx.test', 'broken.test'], allow: [{ rule: 'caa-missing', domain: 'b.test', reason: 'CA set by host', expires: '2027-01-01' }, { rule: 'dmarc-policy-none', domain: 'a.test', reason: 'rollout', expires: '2026-01-01' }], severity: { 'dmarc-no-rua': 'off' } }, routes);
  assert.deepEqual(r.domains.map((d) => d.domain), ['a.test', 'b.test', 'nx.test', 'broken.test']);
  assert.ok(r.domains[2].fatal && /NXDOMAIN/.test(r.domains[2].errors[0]));
  assert.ok(r.domains[3].fatal && /SERVFAIL/.test(r.domains[3].errors[0]));
  assert.equal(find(r, 'caa-missing'), undefined); assert.equal(r.suppressed.length, 1);
  assert.match(find(r, 'dmarc-policy-none').message, /expired 2026-01-01/);
  assert.ok(find(r, 'allow-expired'));
  const only = await run(goodZone(), { checks: ['caa'], domains: ['good.test'] });
  assert.ok(only.resolverLog.every((l) => !l.includes('_dmarc')));
  await assert.rejects(run(goodZone(), { checks: ['bogus'] }), /Unknown check/);
  await assert.rejects(run(goodZone(), { allow: [{ rule: 'caa-missing' }] }), /reason/);
  await assert.rejects(run(goodZone(), { severity: { 'caa-missing': 'huge' } }), /Invalid severity/);
});
