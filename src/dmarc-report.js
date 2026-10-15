// DMARC aggregate (RUA) report parsing: XML, .xml.gz and single-file .zip, as receivers send them.
import { gunzipSync, inflateRawSync } from 'node:zlib';

/** Unpack a report attachment (Buffer) to XML text. */
export function unpackReport(buf) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  if (b[0] === 0x1f && b[1] === 0x8b) return gunzipSync(b).toString('utf8');
  if (b.length >= 30 && b.readUInt32LE(0) === 0x04034b50) {
    // first entry of a zip archive (local file header)
    const method = b.readUInt16LE(8); let size = b.readUInt32LE(18); const nameLen = b.readUInt16LE(26); const extra = b.readUInt16LE(28);
    const start = 30 + nameLen + extra;
    if (size === 0 || (b.readUInt16LE(6) & 8)) { const cd = b.lastIndexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02])); if (cd > 0) size = b.readUInt32LE(cd + 20); }
    const data = b.subarray(start, start + size);
    return (method === 8 ? inflateRawSync(data) : data).toString('utf8');
  }
  return b.toString('utf8');
}

const tag = (xml, name) => { const m = new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, 'i').exec(xml); return m ? m[1].trim() : undefined; };
const tags = (xml, name) => [...xml.matchAll(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, 'gi'))].map((m) => m[1]);
const unesc = (s) => s?.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');

/** Parse one aggregate report (RFC 7489 appendix C). */
export function parseDmarcReport(input) {
  const xml = typeof input === 'string' ? input : unpackReport(input);
  if (!/<feedback[\s>]/i.test(xml)) throw new Error('not a DMARC aggregate report (no <feedback> element)');
  const meta = tag(xml, 'report_metadata') || ''; const pol = tag(xml, 'policy_published') || '';
  const range = tag(meta, 'date_range') || '';
  const records = tags(xml, 'record').map((r) => {
    const row = tag(r, 'row') || ''; const pe = tag(row, 'policy_evaluated') || ''; const ids = tag(r, 'identifiers') || ''; const auth = tag(r, 'auth_results') || '';
    return {
      sourceIp: tag(row, 'source_ip'), count: Number(tag(row, 'count') || 0),
      disposition: tag(pe, 'disposition'), dkim: tag(pe, 'dkim'), spf: tag(pe, 'spf'),
      headerFrom: unesc(tag(ids, 'header_from')), envelopeFrom: unesc(tag(ids, 'envelope_from')),
      dkimAuth: tags(auth, 'dkim').map((x) => ({ domain: tag(x, 'domain'), selector: tag(x, 'selector'), result: tag(x, 'result') })),
      spfAuth: tags(auth, 'spf').map((x) => ({ domain: tag(x, 'domain'), result: tag(x, 'result') })),
    };
  });
  return {
    orgName: unesc(tag(meta, 'org_name')), email: unesc(tag(meta, 'email')), reportId: unesc(tag(meta, 'report_id')),
    begin: range ? new Date(Number(tag(range, 'begin')) * 1000).toISOString() : null, end: range ? new Date(Number(tag(range, 'end')) * 1000).toISOString() : null,
    policy: { domain: tag(pol, 'domain'), p: tag(pol, 'p'), sp: tag(pol, 'sp'), pct: tag(pol, 'pct') ? Number(tag(pol, 'pct')) : undefined, adkim: tag(pol, 'adkim'), aspf: tag(pol, 'aspf') },
    records,
  };
}

/** Summarise one or more parsed reports: totals, DMARC pass rate, and failing sources. */
export function summarizeDmarcReports(reports) {
  const bySource = new Map(); let total = 0; let pass = 0;
  for (const rep of reports) for (const r of rep.records) {
    total += r.count; const ok = r.dkim === 'pass' || r.spf === 'pass'; if (ok) pass += r.count;
    const k = `${r.sourceIp}|${r.headerFrom}`; const s = bySource.get(k) || { sourceIp: r.sourceIp, headerFrom: r.headerFrom, count: 0, pass: 0, fail: 0, reporters: new Set(), dispositions: {} };
    s.count += r.count; if (ok) s.pass += r.count; else s.fail += r.count; s.reporters.add(rep.orgName); s.dispositions[r.disposition] = (s.dispositions[r.disposition] || 0) + r.count; bySource.set(k, s);
  }
  const sources = [...bySource.values()].map((s) => ({ ...s, reporters: [...s.reporters] })).sort((a, b) => b.fail - a.fail || b.count - a.count);
  return { reports: reports.length, messages: total, passing: pass, passRate: total ? Math.round((pass / total) * 1000) / 10 : null, failingSources: sources.filter((s) => s.fail > 0), sources };
}
