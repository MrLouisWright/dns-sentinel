// A tiny authoritative DNS server (UDP + TCP + DoH) backed by a MockResolver zone, for end-to-end tests.
import dgram from 'node:dgram';
import net from 'node:net';
import http from 'node:http';
import { MockResolver, decodeMessage, encodeResponse, TYPES } from '../src/index.js';

const TYPE_NAMES = Object.fromEntries(Object.entries(TYPES).map(([k, v]) => [v, k]));

export async function answer(zone, axfr, buf) {
  const q = decodeMessage(buf);
  const { name, type } = q.questions[0];
  const t = TYPE_NAMES[type];
  if (t === 'AXFR') return null;
  const m = new MockResolver(zone);
  const r = await m.query(name, t);
  const rcode = { NXDOMAIN: 3, SERVFAIL: 2 }[r.status] || 0;
  const answers = [];
  let owner = name;
  for (const c of r.cnames || []) { answers.push({ name: owner, type: 'CNAME', data: c }); owner = c; }
  for (const a of r.answers) answers.push({ name: owner, type: t, data: t === 'TXT' ? (a.length > 255 ? a.match(/.{1,255}/g) : [a]) : t === 'MX' ? { priority: a.priority, exchange: a.exchange || '' } : a });
  return encodeResponse(buf, { rcode, ad: !!r.ad, answers });
}

export async function startDnsServer(zone, { axfr = {} } = {}) {
  const udp = dgram.createSocket('udp4');
  udp.on('message', async (msg, rinfo) => { const out = await answer(zone, axfr, msg); if (out) udp.send(out, rinfo.port, rinfo.address); });
  await new Promise((r) => udp.bind(0, '127.0.0.1', r));
  const port = udp.address().port;
  const tcp = net.createServer((sock) => {
    let buf = Buffer.alloc(0);
    sock.on('data', async (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length < 2 || buf.length < 2 + buf.readUInt16BE(0)) return;
      const q = buf.subarray(2, 2 + buf.readUInt16BE(0));
      const dq = decodeMessage(q);
      const send = (m) => { const l = Buffer.alloc(2); l.writeUInt16BE(m.length); sock.write(Buffer.concat([l, m])); };
      if (dq.questions[0].type === TYPES.AXFR) {
        const recs = axfr[dq.questions[0].name];
        if (!recs) { send(encodeResponse(q, { rcode: 5 })); return sock.end(); }
        send(encodeResponse(q, { answers: recs.slice(0, 2) }));
        send(encodeResponse(q, { answers: recs.slice(2) }));
        return sock.end();
      }
      send(await answer(zone, axfr, q)); sock.end();
    });
  });
  await new Promise((r) => tcp.listen(port, '127.0.0.1', r));
  const doh = http.createServer((req, res) => {
    const chunks = []; req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      if (req.headers['content-type'] !== 'application/dns-message') { res.statusCode = 415; return res.end(); }
      res.setHeader('content-type', 'application/dns-message'); res.end(await answer(zone, axfr, Buffer.concat(chunks)));
    });
  });
  await new Promise((r) => doh.listen(0, '127.0.0.1', r));
  return { port, server: `127.0.0.1:${port}`, doh: `http://127.0.0.1:${doh.address().port}/dns-query`, close: () => { udp.close(); tcp.close(); doh.close(); } };
}
