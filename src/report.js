import { RULES, SEVERITIES, rank } from './rules.js';

const C = { critical: '\x1b[35;1m', high: '\x1b[31;1m', medium: '\x1b[33m', low: '\x1b[36m', info: '\x1b[2m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m', red: '\x1b[31m', green: '\x1b[32m' };
const summary = (counts) => SEVERITIES.filter((k) => counts[k]).map((k) => `${counts[k]} ${k}`).join(', ') || 'no findings';
const failing = (r, failOn) => failOn && failOn !== 'none' && r.findings.some((f) => rank(f.severity) <= rank(failOn));

function overview(s) {
  const out = [];
  if (s.mx) out.push(`MX: ${s.mx.join(', ') || 'none'}`);
  if (s.spf) out.push(`SPF: ${s.spf.length ? s.spf.join(' | ') : 'none'}${s.spfLookups !== undefined ? ` (${s.spfLookups} lookups)` : ''}`);
  if (s.dmarc !== undefined) out.push(`DMARC: ${s.dmarc ?? 'none'}`);
  if (s.dkim) out.push(`DKIM: ${Object.entries(s.dkim).filter(([, v]) => v !== 'missing').map(([k, v]) => `${k} (${v})`).join(', ') || 'no keys found'}`);
  if (s.mtaSts !== undefined) out.push(`MTA-STS: ${s.mtaSts ? `${s.mtaSts}${s.mtaStsMode ? `, mode ${s.mtaStsMode}` : ''}` : 'none'}`);
  if (s.tlsRpt !== undefined) out.push(`TLS-RPT: ${s.tlsRpt ?? 'none'}`);
  if (s.caa) out.push(`CAA: ${s.caa.join(', ') || 'none'}`);
  if (s.dnssec) out.push(`DNSSEC: ${s.dnssec.validated ? 'validated' : s.dnssec.ds ? 'DS present, not validated' : s.dnssec.dnskey ? 'signed, no DS' : 'off'}`);
  if (s.wildcard !== undefined) out.push(`Wildcard: ${s.wildcard ? s.wildcard.join(', ') : 'none'}`);
  for (const [k, v] of Object.entries(s.subdomains || {})) out.push(`${k}: ${v}`);
  for (const [k, v] of Object.entries(s.axfr || {})) out.push(`AXFR ${k}: ${v}`);
  return out;
}

export function formatText(r, { color = false, failOn } = {}) {
  const c = (k, s) => (color ? `${C[k]}${s}${C.reset}` : s);
  const l = [c('bold', `dns-sentinel — ${r.domains.length} domain(s)`) + c('dim', ` · resolver: ${r.resolver}; DNSSEC: ${r.dnssecResolver}`), ''];
  for (const d of r.domains) {
    l.push(c('bold', d.domain));
    for (const o of overview(d.summary)) l.push(c('dim', `  ${o}`));
    for (const e of d.errors) l.push(c('red', `  ✖ ${e}`));
    for (const f of d.findings) {
      l.push(`  ${c(f.severity, f.severity.toUpperCase().padEnd(8))} ${f.message} [${f.rule}]`);
      l.push(c('dim', `           ↳ fix: ${f.fix}`));
    }
    if (!d.findings.length && !d.errors.length) l.push(c('green', '  ✔ no findings'));
    l.push('');
  }
  if (r.suppressed.length) l.push(c('dim', `${r.suppressed.length} finding(s) suppressed by allowlist`));
  l.push(summary(r.counts));
  if (failOn) l.push(failing(r, failOn) ? c('red', `✖ Failing (fail-on: ${failOn}).`) : c('green', `✔ Passing (fail-on: ${failOn}).`));
  return l.join('\n') + '\n';
}

export const formatJson = (r) => JSON.stringify(r, null, 2) + '\n';

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SCORE = { critical: '9.0', high: '7.5', medium: '5.0', low: '3.0', info: '1.0' };
export function formatSarif(r, { version = '0.0.0' } = {}) {
  const ids = Object.keys(RULES);
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'dns-sentinel', version, informationUri: 'https://github.com/MrLouisWright/dns-sentinel', rules: ids.map((id) => ({ id, name: id.replace(/(^|-)(\w)/g, (_, __, ch) => ch.toUpperCase()), shortDescription: { text: RULES[id].title }, helpUri: `https://github.com/MrLouisWright/dns-sentinel#${id}`, defaultConfiguration: { level: LEVEL[RULES[id].severity] }, properties: { tags: ['security', 'dns', RULES[id].group], 'security-severity': SCORE[RULES[id].severity] } })) } },
      results: r.findings.map((f) => ({ ruleId: f.rule, ruleIndex: ids.indexOf(f.rule), level: LEVEL[f.severity], message: { text: `${f.message}. Fix: ${f.fix}` }, locations: [{ physicalLocation: { artifactLocation: { uri: `dns:${f.name}` } }, logicalLocations: [{ name: f.name, kind: 'resource' }] }], partialFingerprints: { dnsRule: `${f.rule}:${f.domain}:${f.name}` }, properties: { domain: f.domain, severity: f.severity, 'security-severity': SCORE[f.severity] } })),
    }],
  }, null, 2) + '\n';
}

const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
export function formatMarkdown(r, { failOn } = {}) {
  const l = ['## 🌐 dns-sentinel', '', `Checked **${r.domains.length}** domain(s): ${summary(r.counts)}.`];
  if (failOn) l.push('', failing(r, failOn) ? `❌ Failing at \`--fail-on ${failOn}\`.` : `✅ Passing at \`--fail-on ${failOn}\`.`);
  for (const d of r.domains) {
    l.push('', `### ${d.domain}`, '');
    for (const e of d.errors) l.push(`> ⚠️ ${esc(e)}`);
    if (d.findings.length) {
      l.push('| Severity | Record | Rule | Finding | Fix |', '|---|---|---|---|---|');
      for (const f of d.findings) l.push(`| ${f.severity} | \`${esc(f.name)}\` | \`${f.rule}\` | ${esc(f.message)} | ${esc(f.fix)} |`);
    } else if (!d.errors.length) l.push('✅ No findings.');
    const o = overview(d.summary);
    if (o.length) l.push('', '<details><summary>Records</summary>', '', ...o.map((x) => `- ${esc(x)}`), '', '</details>');
  }
  if (r.suppressed.length) l.push('', `_${r.suppressed.length} finding(s) suppressed by allowlist._`);
  return l.join('\n') + '\n';
}
