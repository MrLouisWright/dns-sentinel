import test from 'node:test';
import assert from 'node:assert/strict';
import { run, rules, find, goodZone, goodFetch, dkimKey, mockFetch } from './helpers.js';
import { parseSpf, parseStsPolicy, dkimKeyBits } from '../src/index.js';

test('a well-configured domain is clean', async () => {
  const r = await run(goodZone(), { dkimSelectors: ['s1'] }, undefined).catch((e) => { throw e; });
  // add a DKIM key and rerun
  const z = goodZone(); z['s1._domainkey.good.test'] = { TXT: [`v=DKIM1; k=rsa; p=${dkimKey(2048)}`] };
  const r2 = await run(z, { dkimSelectors: ['s1'] });
  assert.deepEqual(rules(r2), []);
  assert.equal(r2.domains[0].summary.dkim.s1, 'rsa 2048');
  assert.equal(r2.domains[0].summary.spfLookups, 1);
  assert.ok(find(r, 'dkim-missing'));
});

test('SPF: missing (mail vs non-mail), multiple, +all, ?all, ~all, no all, ptr, syntax', async () => {
  const base = goodZone();
  const t = async (txt, extra = {}) => run({ ...base, 'good.test': { ...base['good.test'], TXT: txt }, ...extra });
  assert.equal(find(await t([]), 'spf-missing').severity, 'high');
  const nonMail = await run({ ...base, 'good.test': { ...base['good.test'], TXT: [], MX: [{ exchange: '', priority: 0 }] } });
  assert.equal(find(nonMail, 'spf-missing').severity, 'medium');
  assert.match(find(nonMail, 'spf-missing').fix, /v=spf1 -all/);
  assert.ok(find(await t(['v=spf1 -all', 'v=spf1 mx -all']), 'spf-multiple'));
  assert.equal(find(await t(['v=spf1 +all']), 'spf-pass-all').severity, 'critical');
  assert.equal(find(await t(['v=spf1 all']), 'spf-pass-all').severity, 'critical');
  assert.ok(find(await t(['v=spf1 mx ?all']), 'spf-neutral-all'));
  assert.equal(find(await t(['v=spf1 mx ~all']), 'spf-softfail-all').severity, 'info');
  assert.ok(find(await t(['v=spf1 mx']), 'spf-no-all'));
  assert.equal(find(await t(['v=spf1 redirect=_spf.mail.test']), 'spf-no-all'), undefined);
  assert.ok(find(await t(['v=spf1 ptr -all']), 'spf-ptr'));
  assert.ok(find(await t(['v=spf1 ipv4:1.2.3.4 -all']), 'spf-invalid'));
  assert.ok(find(await t(['v=spf1 ip4:999.1.1.1 -all']), 'spf-invalid'));
  assert.match(find(await t(['v=spf1 -all mx']), 'spf-invalid').message, /never evaluated/);
  assert.match(find(await t(['v=spf1 include:nospf.test -all'], { 'nospf.test': { A: ['1.1.1.1'] } }), 'spf-invalid').message, /no SPF record/);
});

test('SPF: more than 10 lookups across nested includes, include loops, void lookups, nested ptr', async () => {
  const base = goodZone();
  const inc = {};
  for (let i = 0; i < 4; i++) inc[`i${i}.test`] = { TXT: [`v=spf1 include:j${i}.test a mx -all`] };
  for (let i = 0; i < 4; i++) inc[`j${i}.test`] = { TXT: ['v=spf1 ip4:10.0.0.1 -all'], A: ['10.0.0.1'], MX: [{ exchange: 'm.test', priority: 1 }] };
  const r = await run({ ...base, 'good.test': { ...base['good.test'], TXT: ['v=spf1 include:i0.test include:i1.test include:i2.test include:i3.test -all'] }, ...inc });
  assert.match(find(r, 'spf-too-many-lookups').message, /\d+ DNS lookups/);
  assert.equal(r.domains[0].summary.spfLookups, 16);
  const loop = await run({ ...base, 'good.test': { ...base['good.test'], TXT: ['v=spf1 include:l1.test -all'] }, 'l1.test': { TXT: ['v=spf1 include:l2.test -all'] }, 'l2.test': { TXT: ['v=spf1 include:l1.test -all'] } });
  assert.match(find(loop, 'spf-invalid').message, /loop/);
  const voids = await run({ ...base, 'good.test': { ...base['good.test'], TXT: ['v=spf1 a:x1.test a:x2.test a:x3.test -all'] } });
  assert.ok(find(voids, 'spf-void-lookups'));
  const nptr = await run({ ...base, 'good.test': { ...base['good.test'], TXT: ['v=spf1 include:p.test -all'] }, 'p.test': { TXT: ['v=spf1 ptr -all'] } });
  assert.match(find(nptr, 'spf-ptr').message, /via include/);
});

test('DMARC: missing, multiple, invalid, p=none, no rua, pct, weak sp, inherited org policy', async () => {
  const base = goodZone();
  const t = async (txt) => run({ ...base, '_dmarc.good.test': { TXT: txt } });
  assert.ok(find(await run({ ...base, '_dmarc.good.test': {} }), 'dmarc-missing'));
  assert.ok(find(await t(['v=DMARC1; p=reject', 'v=DMARC1; p=none']), 'dmarc-multiple'));
  assert.ok(find(await t(['v=DMARC1; rua=mailto:a@b.c']), 'dmarc-invalid'));
  assert.ok(find(await t(['v=DMARC1; p=block']), 'dmarc-invalid'));
  const none = await t(['v=DMARC1; p=none']);
  assert.ok(find(none, 'dmarc-policy-none')); assert.ok(find(none, 'dmarc-no-rua'));
  assert.equal(find(await t(['v=DMARC1; p=quarantine; pct=25; rua=mailto:a@good.test']), 'dmarc-pct').message.includes('25%'), true);
  assert.ok(find(await t(['v=DMARC1; p=reject; sp=none; rua=mailto:a@good.test']), 'dmarc-weak-subdomain'));
  // subdomain inherits org record and its sp
  const sub = goodZone('mail.good.test');
  const r = await run({ ...sub, '_dmarc.mail.good.test': {}, 'good.test': { A: ['1.1.1.1'] }, '_dmarc.good.test': { TXT: ['v=DMARC1; p=reject; sp=none; rua=mailto:a@good.test'] } }, { domains: ['mail.good.test'] }, goodFetch('mail.good.test'));
  assert.match(find(r, 'dmarc-policy-none').message, /inherited from good\.test/);
  assert.equal(find(r, 'dmarc-missing'), undefined);
  // non-mail domain with p=none is high
  const nm = await run({ ...base, 'good.test': { ...base['good.test'], MX: [{ exchange: '', priority: 0 }], TXT: ['v=spf1 -all'] }, '_dmarc.good.test': { TXT: ['v=DMARC1; p=none; rua=mailto:a@good.test'] } });
  assert.equal(find(nm, 'dmarc-policy-none').severity, 'high');
});

test('DKIM: weak keys (critical < 1024, medium < 2048), revoked, testing, missing, invalid, ed25519, common selectors', async () => {
  const base = goodZone();
  const z = { ...base,
    'weak._domainkey.good.test': { TXT: [`v=DKIM1; k=rsa; p=${dkimKey(768)}`] },
    'mid._domainkey.good.test': { TXT: [`v=DKIM1; p=${dkimKey(1024)}`] },
    'old._domainkey.good.test': { TXT: ['v=DKIM1; p='] },
    'test._domainkey.good.test': { TXT: [`v=DKIM1; t=y; p=${dkimKey(2048)}`] },
    'bad._domainkey.good.test': { TXT: ['v=DKIM1; p=bm90IGEga2V5'] },
    'ed._domainkey.good.test': { TXT: ['v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='] },
  };
  const r = await run(z, { dkimSelectors: ['weak', 'mid', 'old', 'test', 'bad', 'ed', 'nope'] });
  assert.equal(find(r, 'dkim-weak-key', (f) => f.name.startsWith('weak.')).severity, 'critical');
  assert.equal(find(r, 'dkim-weak-key', (f) => f.name.startsWith('mid.')).severity, 'medium');
  assert.ok(find(r, 'dkim-revoked')); assert.ok(find(r, 'dkim-testing')); assert.ok(find(r, 'dkim-invalid'));
  assert.ok(find(r, 'dkim-missing', (f) => f.name.startsWith('nope.')));
  assert.equal(r.domains[0].summary.dkim.ed, 'ed25519 256');
  const c = await run({ ...base, 'selector1._domainkey.good.test': { TXT: [`v=DKIM1; p=${dkimKey(2048)}`] } }, { dkimCommon: true });
  assert.equal(c.domains[0].summary.dkim.selector1, 'rsa 2048');
  assert.equal(find(c, 'dkim-missing'), undefined, 'common selectors that are absent are not findings');
  assert.ok(find(await run(base, { dkimCommon: true }), 'dkim-not-found'));
  assert.deepEqual(dkimKeyBits(dkimKey(1024)), { type: 'rsa', bits: 1024 });
});

test('MX sanity and null MX', async () => {
  const base = goodZone();
  const t = (mx, extra = {}) => run({ ...base, 'good.test': { ...base['good.test'], MX: mx }, ...extra });
  assert.match(find(await t([]), 'mx-missing').fix, /MX 0 \./);
  assert.ok(find(await t([{ exchange: '', priority: 0 }, { exchange: 'mx1.good.test', priority: 10 }]), 'null-mx-misconfigured'));
  assert.equal(find(await t([{ exchange: 'gone.example', priority: 10 }]), 'mx-dangling').severity, 'high');
  assert.ok(find(await t([{ exchange: '192.0.2.1', priority: 10 }]), 'mx-ip-literal'));
  assert.ok(find(await t([{ exchange: 'alias.good.test', priority: 10 }], { 'alias.good.test': { CNAME: ['mx1.good.test'] } }), 'mx-cname'));
  const nullOk = await run({ ...base, 'good.test': { ...base['good.test'], MX: [{ exchange: '', priority: 0 }], TXT: ['v=spf1 -all'] } });
  assert.deepEqual(rules(nullOk), [], 'null MX + -all + reject is clean, no MTA-STS needed');
  assert.ok(find(await run({ ...base, 'good.test': { ...base['good.test'], MX: [{ exchange: '', priority: 0 }], TXT: ['v=spf1 ip4:1.2.3.4 -all'] } }), 'null-mx-spf'));
});

test('MTA-STS and TLS-RPT', async () => {
  const base = goodZone();
  const url = 'https://mta-sts.good.test/.well-known/mta-sts.txt';
  assert.ok(find(await run({ ...base, '_mta-sts.good.test': {}, '_smtp._tls.good.test': {} }), 'mta-sts-missing'));
  assert.ok(find(await run({ ...base, '_smtp._tls.good.test': {} }), 'tlsrpt-missing'));
  assert.ok(find(await run({ ...base, '_smtp._tls.good.test': { TXT: ['v=TLSRPTv1; rua=ftp://x'] } }), 'tlsrpt-invalid'));
  assert.ok(find(await run({ ...base, '_mta-sts.good.test': { TXT: ['v=STSv1; id=bad-id!'] } }), 'mta-sts-invalid'));
  assert.match(find(await run(base, {}, {}), 'mta-sts-invalid').message, /could not be fetched/);
  assert.match(find(await run(base, {}, { [url]: { status: 404 } }), 'mta-sts-invalid').message, /HTTP 404/);
  assert.ok(find(await run(base, {}, { [url]: { body: 'version: STSv1\nmode: testing\nmx: *.good.test\nmax_age: 86400' } }), 'mta-sts-testing'));
  const mm = await run(base, {}, { [url]: { body: 'version: STSv1\nmode: enforce\nmx: mail.other.test\nmax_age: 604800' } });
  assert.equal(find(mm, 'mta-sts-mx-mismatch').severity, 'high');
  assert.ok(find(await run(base, {}, { [url]: { body: 'nonsense' } }), 'mta-sts-invalid'));
  const nohttp = await run(base, { http: false }, {});
  assert.equal(find(nohttp, 'mta-sts-invalid'), undefined);
  assert.deepEqual(parseStsPolicy('version: STSv1\r\nmode: enforce\r\nmx: a.b\r\nmx: *.c.d\r\nmax_age: 5'), { mx: ['a.b', '*.c.d'], version: 'STSv1', mode: 'enforce', max_age: '5' });
});

test('parseSpf', () => {
  const s = parseSpf('v=spf1 -ip4:1.2.3.4 ~include:x.test redirect=y.test exp=e.test');
  assert.deepEqual(s.mechanisms.map((m) => `${m.qualifier}${m.name}`), ['-ip4', '~include']);
  assert.deepEqual(s.modifiers, { redirect: 'y.test', exp: 'e.test' });
});
