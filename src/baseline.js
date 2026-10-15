// Baseline snapshots: record what the DNS looked like and report changes on the next run.
const FIELDS = ['spf', 'spfLookups', 'dmarc', 'mx', 'mtaSts', 'tlsRpt', 'caa', 'dkim', 'bimi', 'dnssec'];

/** Snapshot the summaries of a report. */
export function snapshot(report) {
  return { tool: 'dns-sentinel', version: 1, takenAt: report.generatedAt, domains: Object.fromEntries(report.domains.filter((d) => !d.fatal).map((d) => [d.domain, Object.fromEntries(FIELDS.filter((f) => d.summary[f] !== undefined).map((f) => [f, d.summary[f]]))])) };
}

const norm = (v) => JSON.stringify(Array.isArray(v) ? [...v].map(String).sort() : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).sort()) : v);

/** Compare a report with a baseline: [{ domain, field, before, after }] plus SPF lookup growth. */
export function diffBaseline(baseline, report) {
  const changes = [];
  for (const d of report.domains) {
    const b = baseline?.domains?.[d.domain]; if (!b || d.fatal) continue;
    for (const f of FIELDS) { if (!(f in b) && d.summary[f] === undefined) continue; if (f === 'spfLookups') continue; if (norm(b[f]) !== norm(d.summary[f])) changes.push({ domain: d.domain, field: f, before: b[f] ?? null, after: d.summary[f] ?? null }); }
    if (typeof b.spfLookups === 'number' && typeof d.summary.spfLookups === 'number' && d.summary.spfLookups > b.spfLookups) changes.push({ domain: d.domain, field: 'spfLookups', before: b.spfLookups, after: d.summary.spfLookups });
  }
  return changes;
}
