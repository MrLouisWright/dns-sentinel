// Minimal DNS wire-format codec (RFC 1035, EDNS0/DNSSEC bits) used for DoH, DS/DNSKEY, AD flag and AXFR.

export const TYPES = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, OPT: 41, DS: 43, RRSIG: 46, NSEC: 47, DNSKEY: 48, NSEC3: 50, HTTPS: 65, AXFR: 252, ANY: 255, CAA: 257 };
export const TYPE_NAMES = Object.fromEntries(Object.entries(TYPES).map(([k, v]) => [v, k]));
export const RCODES = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED', 9: 'NOTAUTH' };

function encodeName(name) {
  const parts = String(name).replace(/\.$/, '').split('.').filter(Boolean);
  const bufs = [];
  for (const p of parts) {
    const b = Buffer.from(p, 'utf8');
    if (b.length > 63) throw new Error(`DNS label too long: ${p}`);
    bufs.push(Buffer.from([b.length]), b);
  }
  bufs.push(Buffer.from([0]));
  return Buffer.concat(bufs);
}

/** Encode a query. dnssec: set DO (EDNS) and AD bits. */
export function encodeQuery(name, type, { id = Math.floor(Math.random() * 65536), dnssec = false, rd = true, edns = true } = {}) {
  const qtype = typeof type === 'number' ? type : TYPES[type];
  if (!qtype) throw new Error(`Unknown record type ${type}`);
  const h = Buffer.alloc(12);
  h.writeUInt16BE(id, 0);
  h.writeUInt16BE((rd ? 0x0100 : 0) | (dnssec ? 0x0020 : 0), 2); // RD, AD
  h.writeUInt16BE(1, 4);
  h.writeUInt16BE(edns ? 1 : 0, 10);
  const q = Buffer.alloc(4); q.writeUInt16BE(qtype, 0); q.writeUInt16BE(1, 2);
  const parts = [h, encodeName(name), q];
  if (edns) { const o = Buffer.alloc(11); o[0] = 0; o.writeUInt16BE(41, 1); o.writeUInt16BE(1232, 3); o.writeUInt32BE(dnssec ? 0x00008000 : 0, 5); o.writeUInt16BE(0, 9); parts.push(o); }
  return Buffer.concat(parts);
}

function readName(buf, off) {
  const labels = []; let jumped = false; let end = off; let guard = 0;
  for (;;) {
    if (off >= buf.length || guard++ > 128) throw new Error('Malformed DNS name');
    const len = buf[off];
    if (len === 0) { if (!jumped) end = off + 1; break; }
    if ((len & 0xc0) === 0xc0) { const ptr = buf.readUInt16BE(off) & 0x3fff; if (!jumped) end = off + 2; jumped = true; off = ptr; continue; }
    labels.push(buf.toString('utf8', off + 1, off + 1 + len)); off += 1 + len;
  }
  return { name: labels.join('.'), end };
}

function parseRdata(buf, type, off, len) {
  const end = off + len;
  switch (type) {
    case 1: return [...buf.subarray(off, end)].join('.');
    case 28: { const p = []; for (let i = 0; i < 16; i += 2) p.push(buf.readUInt16BE(off + i).toString(16)); return p.join(':'); }
    case 2: case 5: case 12: return readName(buf, off).name;
    case 15: return { priority: buf.readUInt16BE(off), exchange: readName(buf, off + 2).name };
    case 16: { const out = []; let i = off; while (i < end) { const l = buf[i]; out.push(buf.toString('utf8', i + 1, i + 1 + l)); i += 1 + l; } return out; }
    case 6: { const m = readName(buf, off); const r = readName(buf, m.end); const o = r.end; return { nsname: m.name, hostmaster: r.name, serial: buf.readUInt32BE(o), refresh: buf.readUInt32BE(o + 4), retry: buf.readUInt32BE(o + 8), expire: buf.readUInt32BE(o + 12), minttl: buf.readUInt32BE(o + 16) }; }
    case 257: { const flags = buf[off]; const tl = buf[off + 1]; return { critical: (flags & 0x80) ? 128 : 0, tag: buf.toString('ascii', off + 2, off + 2 + tl), value: buf.toString('utf8', off + 2 + tl, end) }; }
    case 43: return { keyTag: buf.readUInt16BE(off), algorithm: buf[off + 2], digestType: buf[off + 3], digest: buf.toString('hex', off + 4, end) };
    case 48: return { flags: buf.readUInt16BE(off), protocol: buf[off + 2], algorithm: buf[off + 3], key: buf.toString('base64', off + 4, end) };
    default: return buf.toString('hex', off, end);
  }
}

export function decodeMessage(buf) {
  if (buf.length < 12) throw new Error('DNS message too short');
  const id = buf.readUInt16BE(0); const f = buf.readUInt16BE(2);
  const counts = [4, 6, 8, 10].map((o) => buf.readUInt16BE(o));
  let off = 12;
  const questions = [];
  for (let i = 0; i < counts[0]; i++) { const n = readName(buf, off); questions.push({ name: n.name, type: buf.readUInt16BE(n.end) }); off = n.end + 4; }
  const sections = [[], [], []];
  for (let s = 0; s < 3; s++) {
    for (let i = 0; i < counts[s + 1]; i++) {
      const n = readName(buf, off); off = n.end;
      const type = buf.readUInt16BE(off); const cls = buf.readUInt16BE(off + 2); const ttl = buf.readUInt32BE(off + 4); const rdlen = buf.readUInt16BE(off + 8); off += 10;
      if (off + rdlen > buf.length) throw new Error('Truncated DNS record');
      sections[s].push({ name: n.name, type: TYPE_NAMES[type] || type, class: cls, ttl, data: type === 41 ? null : parseRdata(buf, type, off, rdlen) });
      off += rdlen;
    }
  }
  return { id, flags: { qr: !!(f & 0x8000), aa: !!(f & 0x0400), tc: !!(f & 0x0200), rd: !!(f & 0x0100), ra: !!(f & 0x0080), ad: !!(f & 0x0020), cd: !!(f & 0x0010) }, rcode: RCODES[f & 0xf] || String(f & 0xf), questions, answers: sections[0], authority: sections[1], additional: sections[2] };
}

// ---- encoder for answers (used by tests and the mock DNS server) ----
function encodeRdata(type, data) {
  switch (type) {
    case 'A': return Buffer.from(data.split('.').map(Number));
    case 'AAAA': { const full = data.includes('::') ? (() => { const [a, b] = data.split('::'); const A = a ? a.split(':') : []; const B = b ? b.split(':') : []; return [...A, ...Array(8 - A.length - B.length).fill('0'), ...B]; })() : data.split(':'); const out = Buffer.alloc(16); full.forEach((h, i) => out.writeUInt16BE(parseInt(h, 16), i * 2)); return out; }
    case 'NS': case 'CNAME': case 'PTR': return encodeName(data);
    case 'MX': { const p = Buffer.alloc(2); p.writeUInt16BE(data.priority); return Buffer.concat([p, encodeName(data.exchange)]); }
    case 'TXT': return Buffer.concat((Array.isArray(data) ? data : [data]).flatMap((s) => { const b = Buffer.from(s); return [Buffer.from([b.length]), b]; }));
    case 'SOA': { const t = Buffer.alloc(20); ['serial', 'refresh', 'retry', 'expire', 'minttl'].forEach((k, i) => t.writeUInt32BE(data[k] || 1, i * 4)); return Buffer.concat([encodeName(data.nsname), encodeName(data.hostmaster), t]); }
    case 'CAA': return Buffer.concat([Buffer.from([data.critical ? 128 : data.flags || 0, data.tag.length]), Buffer.from(data.tag), Buffer.from(data.value)]);
    case 'DS': { const h = Buffer.alloc(4); h.writeUInt16BE(data.keyTag); h[2] = data.algorithm; h[3] = data.digestType; return Buffer.concat([h, Buffer.from(data.digest, 'hex')]); }
    case 'DNSKEY': { const h = Buffer.alloc(4); h.writeUInt16BE(data.flags); h[2] = data.protocol ?? 3; h[3] = data.algorithm; return Buffer.concat([h, Buffer.from(data.key, 'base64')]); }
    default: throw new Error(`Cannot encode ${type}`);
  }
}
export function encodeResponse(query, { rcode = 0, ad = false, aa = true, answers = [], authority = [] } = {}) {
  const q = decodeMessage(query);
  const h = Buffer.alloc(12);
  h.writeUInt16BE(q.id, 0);
  h.writeUInt16BE(0x8000 | (aa ? 0x0400 : 0) | 0x0100 | 0x0080 | (ad ? 0x0020 : 0) | (typeof rcode === 'string' ? Number(Object.keys(RCODES).find((k) => RCODES[k] === rcode)) : rcode), 2);
  h.writeUInt16BE(q.questions.length, 4); h.writeUInt16BE(answers.length, 6); h.writeUInt16BE(authority.length, 8);
  const parts = [h];
  for (const qq of q.questions) { const t = Buffer.alloc(4); t.writeUInt16BE(qq.type); t.writeUInt16BE(1, 2); parts.push(encodeName(qq.name), t); }
  for (const rr of [...answers, ...authority]) {
    const rd = encodeRdata(rr.type, rr.data);
    const m = Buffer.alloc(10); m.writeUInt16BE(TYPES[rr.type]); m.writeUInt16BE(1, 2); m.writeUInt32BE(rr.ttl ?? 300, 4); m.writeUInt16BE(rd.length, 8);
    parts.push(encodeName(rr.name), m, rd);
  }
  return Buffer.concat(parts);
}
