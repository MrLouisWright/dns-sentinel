import test from 'node:test';
import assert from 'node:assert/strict';
import { encodeQuery, decodeMessage, encodeResponse, WireResolver, SystemResolver, DohResolver, attemptAxfr } from '../src/index.js';
import { startDnsServer } from './server.js';
import { goodZone } from './helpers.js';

const zone = { ...goodZone(), 'long.good.test': { TXT: ['v=DKIM1; p=' + 'A'.repeat(400)] }, 'alias.good.test': { CNAME: ['www.good.test'] } };
let srv;
test.before(async () => { srv = await startDnsServer(zone, { axfr: { 'good.test': [{ name: 'good.test', type: 'SOA', data: { nsname: 'ns1.good.test', hostmaster: 'h.good.test' } }, { name: 'a.good.test', type: 'A', data: '10.0.0.1' }, { name: 'b.good.test', type: 'TXT', data: ['secret'] }, { name: 'good.test', type: 'SOA', data: { nsname: 'ns1.good.test', hostmaster: 'h.good.test' } }] } }); });
test.after(() => srv.close());

test('codec round trip with compression-free names, EDNS DO/AD bits', () => {
  const q = encodeQuery('Example.COM.', 'DNSKEY', { dnssec: true, id: 42 });
  const d = decodeMessage(q);
  assert.equal(d.id, 42); assert.equal(d.flags.ad, true); assert.equal(d.questions[0].name, 'Example.COM'); assert.equal(d.additional[0].type, 'OPT');
  const r = decodeMessage(encodeResponse(q, { rcode: 'NXDOMAIN' }));
  assert.equal(r.rcode, 'NXDOMAIN');
  assert.throws(() => decodeMessage(Buffer.alloc(5)), /too short/);
  assert.throws(() => encodeQuery('x', 'BOGUS'), /Unknown record type/);
});

for (const kind of ['wire', 'system', 'doh']) {
  test(`${kind} resolver against a local DNS server`, async () => {
    const r = kind === 'wire' ? new WireResolver([srv.server]) : kind === 'system' ? new SystemResolver([srv.server]) : new DohResolver(srv.doh);
    assert.deepEqual((await r.query('good.test', 'MX')).answers, [{ exchange: 'mx1.good.test', priority: 10 }]);
    assert.equal((await r.query('good.test', 'TXT')).answers.length, 2);
    assert.equal((await r.query('long.good.test', 'TXT')).answers[0].length, 411, 'multi-string TXT joined');
    assert.equal((await r.query('nx.good.test', 'A')).status, 'NXDOMAIN');
    assert.equal((await r.query('www.good.test', 'MX')).status, 'NODATA');
    assert.deepEqual((await r.query('good.test', 'CAA')).answers[0], { critical: 0, tag: 'issue', value: 'letsencrypt.org' });
    assert.deepEqual((await r.query('alias.good.test', 'CNAME')).answers, ['www.good.test']);
    const ds = await r.query('good.test', 'DS');
    assert.equal(ds.answers[0].algorithm, 13);
    if (kind !== 'system') assert.equal(ds.ad, true);
  });
}

test('resolver errors map to statuses', async () => {
  assert.equal((await new WireResolver(['127.0.0.1:1'], { timeout: 300 }).query('x.test', 'A')).status, 'TIMEOUT');
  assert.equal((await new DohResolver('http://127.0.0.1:1/dns-query', { timeout: 500 }).query('x.test', 'A')).status, 'ERROR');
});

test('AXFR over TCP: multi-message transfer and refusal', async () => {
  const recs = await attemptAxfr('127.0.0.1', 'good.test', { port: srv.port });
  assert.equal(recs.length, 4); assert.equal(recs[2].data[0], 'secret');
  assert.equal(await attemptAxfr('127.0.0.1', 'other.test', { port: srv.port }), null);
});

export { srv };
