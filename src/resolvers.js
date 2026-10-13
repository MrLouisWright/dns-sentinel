import { Resolver } from 'node:dns/promises';
import dgram from 'node:dgram';
import net from 'node:net';
import { isIP } from 'node:net';
import { encodeQuery, decodeMessage, TYPES } from './wire.js';

/**
 * Every resolver implements:
 *   query(name, type) -> Promise<{ status, answers: [data...], records: [rr...], ad: boolean|undefined }>
 * status: NOERROR | NODATA | NXDOMAIN | SERVFAIL | REFUSED | TIMEOUT | ERROR
 * TXT answers are joined strings; MX {exchange, priority}; CAA {critical, tag, value}; others as decoded.
 */

const normName = (n) => String(n).toLowerCase().replace(/\.$/, '');

function fromMessage(msg, name, type) {
  if (msg.rcode !== 'NOERROR') return { status: msg.rcode, answers: [], records: [], ad: msg.flags.ad };
  const want = type;
  const records = msg.answers.filter((r) => r.type === want);
  const answers = records.map((r) => (want === 'TXT' ? r.data.join('') : r.data));
  const cnames = msg.answers.filter((r) => r.type === 'CNAME').map((r) => r.data);
  return { status: answers.length ? 'NOERROR' : 'NODATA', answers, records, ad: msg.flags.ad, ...(cnames.length && want !== 'CNAME' ? { cnames } : {}) };
}

/** UDP (with TCP fallback on truncation) query to a DNS server. */
export function wireQuery(server, name, type, { timeout = 5000, dnssec = true, port = 53, tcp = false } = {}) {
  const q = encodeQuery(name, type, { dnssec });
  if (tcp) return tcpExchange(server, port, q, timeout).then(([m]) => decodeMessage(m));
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket(isIP(server) === 6 ? 'udp6' : 'udp4');
    const t = setTimeout(() => { sock.close(); reject(Object.assign(new Error(`DNS timeout (${server})`), { code: 'TIMEOUT' })); }, timeout);
    sock.on('message', (m) => {
      clearTimeout(t); sock.close();
      try {
        const d = decodeMessage(m);
        if (d.flags.tc) return resolve(tcpExchange(server, port, q, timeout).then(([x]) => decodeMessage(x)));
        resolve(d);
      } catch (e) { reject(e); }
    });
    sock.on('error', (e) => { clearTimeout(t); sock.close(); reject(e); });
    sock.send(q, port, server);
  });
}

/** Send one query over TCP and collect length-prefixed responses until `done(messages)` is true. */
export function tcpExchange(server, port, query, timeout = 5000, done = (msgs) => msgs.length >= 1) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: server, port });
    const msgs = []; let buf = Buffer.alloc(0);
    const finish = (err) => { clearTimeout(t); sock.destroy(); err ? reject(err) : resolve(msgs); };
    const t = setTimeout(() => finish(Object.assign(new Error(`DNS TCP timeout (${server})`), { code: 'TIMEOUT' })), timeout);
    sock.on('connect', () => { const l = Buffer.alloc(2); l.writeUInt16BE(query.length); sock.write(Buffer.concat([l, query])); });
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) {
        const len = buf.readUInt16BE(0); msgs.push(buf.subarray(2, 2 + len)); buf = buf.subarray(2 + len);
        try { if (done(msgs)) return finish(); } catch (e) { return finish(e); }
      }
    });
    sock.on('end', () => finish());
    sock.on('error', (e) => finish(e));
  });
}

/** DNS-over-HTTPS (RFC 8484, wire format, POST). */
export class DohResolver {
  constructor(url = 'https://cloudflare-dns.com/dns-query', { timeout = 8000, fetchImpl = globalThis.fetch } = {}) { this.url = url; this.timeout = timeout; this.fetch = fetchImpl; this.kind = 'doh'; }
  async message(name, type) {
    const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), this.timeout);
    try {
      const res = await this.fetch(this.url, { method: 'POST', headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' }, body: encodeQuery(name, type, { dnssec: true, id: 0 }), signal: ctrl.signal });
      if (!res.ok) throw Object.assign(new Error(`DoH HTTP ${res.status}`), { code: 'ERROR' });
      return decodeMessage(Buffer.from(await res.arrayBuffer()));
    } catch (e) { if (e.name === 'AbortError') throw Object.assign(new Error('DoH timeout'), { code: 'TIMEOUT' }); throw e; } finally { clearTimeout(t); }
  }
  async query(name, type) {
    try { return fromMessage(await this.message(normName(name), type), name, type); } catch (e) { return { status: e.code === 'TIMEOUT' ? 'TIMEOUT' : 'ERROR', answers: [], records: [], error: e.message }; }
  }
}

/** Classic DNS over UDP/TCP to explicit servers. Gives AD flag and every record type. */
export class WireResolver {
  constructor(servers, { timeout = 5000 } = {}) { this.servers = servers; this.timeout = timeout; this.kind = 'wire'; }
  async message(name, type) {
    let last;
    for (const s of this.servers) {
      const [host, port] = splitServer(s);
      try { return await wireQuery(host, normName(name), type, { timeout: this.timeout, port }); } catch (e) { last = e; }
    }
    throw last || new Error('No DNS servers');
  }
  async query(name, type) {
    try { return fromMessage(await this.message(name, type), name, type); } catch (e) { return { status: e.code === 'TIMEOUT' ? 'TIMEOUT' : 'ERROR', answers: [], records: [], error: e.message }; }
  }
}

export function splitServer(s) {
  const m = String(s).match(/^\[(.+)\](?::(\d+))?$/) || String(s).match(/^([^:]+):(\d+)$/);
  return m ? [m[1], Number(m[2] || 53)] : [String(s), 53];
}

const ERR = { ENOTFOUND: 'NXDOMAIN', ENODATA: 'NODATA', ESERVFAIL: 'SERVFAIL', ETIMEOUT: 'TIMEOUT', EREFUSED: 'REFUSED', ECONNREFUSED: 'ERROR' };

/** node:dns/promises resolver (system or configured servers). DS/DNSKEY go over the wire to the same servers. */
export class SystemResolver {
  constructor(servers = [], { timeout = 5000, tries = 2 } = {}) {
    this.r = new Resolver({ timeout, tries });
    if (servers.length) this.r.setServers(servers);
    this.servers = this.r.getServers();
    this.wire = new WireResolver(this.servers, { timeout });
    this.kind = 'system';
  }
  async query(name, type) {
    const n = normName(name);
    const map = { A: 'resolve4', AAAA: 'resolve6', CNAME: 'resolveCname', MX: 'resolveMx', TXT: 'resolveTxt', NS: 'resolveNs', CAA: 'resolveCaa', SOA: 'resolveSoa' };
    if (!map[type]) return this.wire.query(n, type);
    try {
      let a = await this.r[map[type]](n);
      if (type === 'TXT') a = a.map((chunks) => chunks.join(''));
      if (type === 'SOA') a = [a];
      if (type === 'CAA') a = a.map((c) => { const tag = Object.keys(c).find((k) => k !== 'critical'); return { critical: c.critical || 0, tag, value: c[tag] }; });
      if (type === 'MX') a = a.map((m) => ({ exchange: normName(m.exchange), priority: m.priority }));
      return { status: a.length ? 'NOERROR' : 'NODATA', answers: a, records: [] };
    } catch (e) {
      return { status: ERR[e.code] || 'ERROR', answers: [], records: [], error: e.code || e.message };
    }
  }
}

/**
 * In-memory resolver for tests and offline use.
 * zone: { 'example.com': { TXT: ['v=spf1 -all'], MX: [{exchange, priority}], A: [...], CNAME: ['x.y'], DS: [...], DNSKEY: [...], AD: true } }
 * Names starting with '*.' act as wildcards. Special per-name keys: SERVFAIL: true, TIMEOUT: true.
 */
export class MockResolver {
  constructor(zone = {}, { axfr = {} } = {}) {
    this.zone = Object.fromEntries(Object.entries(zone).map(([k, v]) => [normName(k), v]));
    this.axfrZones = axfr; this.kind = 'mock'; this.log = [];
  }
  lookupNode(n) {
    if (this.zone[n]) return this.zone[n];
    if (Object.keys(this.zone).some((k) => k.endsWith('.' + n) && !k.startsWith('*.' + n))) return {}; // empty non-terminal
    const labels = n.split('.');
    for (let i = 1; i < labels.length; i++) {
      const suffix = labels.slice(i).join('.');
      if (this.zone['*.' + suffix]) return this.zone['*.' + suffix];
      if (this.zone[suffix]) return null;
    }
    return null;
  }
  async query(name, type) {
    const n = normName(name); this.log.push(`${type} ${n}`);
    const node = this.lookupNode(n);
    if (!node) return { status: 'NXDOMAIN', answers: [], records: [], ad: !!this.zone[n.split('.').slice(-2).join('.')]?.AD };
    if (node.SERVFAIL) return { status: 'SERVFAIL', answers: [], records: [] };
    if (node.TIMEOUT) return { status: 'TIMEOUT', answers: [], records: [] };
    if (node.CNAME && type !== 'CNAME') {
      const t = await this.query(node.CNAME[0], type);
      return { ...t, cnames: [node.CNAME[0], ...(t.cnames || [])] };
    }
    const a = node[type] || [];
    return { status: a.length ? 'NOERROR' : 'NODATA', answers: a, records: [], ad: !!node.AD };
  }
  async axfr(zone) { return this.axfrZones[normName(zone)] || null; }
}

/** Attempt a zone transfer against one nameserver IP. Returns records or null if refused. */
export async function attemptAxfr(server, zone, { timeout = 8000, port = 53 } = {}) {
  const q = encodeQuery(zone, TYPES.AXFR, { edns: false });
  let soaSeen = 0;
  const msgs = await tcpExchange(server, port, q, timeout, (ms) => {
    const d = decodeMessage(ms[ms.length - 1]);
    if (d.rcode !== 'NOERROR') return true;
    soaSeen += d.answers.filter((r) => r.type === 'SOA').length;
    return soaSeen >= 2 || (ms.length === 1 && d.answers.length === 0);
  });
  const records = [];
  for (const m of msgs) { const d = decodeMessage(m); if (d.rcode !== 'NOERROR') return null; records.push(...d.answers); }
  return records.length ? records : null;
}
