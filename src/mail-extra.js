// BIMI, provider DKIM selectors and ARC header-set validation.
import { parseTags } from './util.js';

/** Known mail providers: how to recognise them (MX / SPF include) and the DKIM selectors they use. */
export const DKIM_PROVIDERS = [
  { name: 'Google Workspace', mx: /(^|\.)google(mail)?\.com\.?$|aspmx\.l\.google\.com/i, spf: /_spf\.google\.com/i, selectors: ['google', 'google2048'] },
  { name: 'Microsoft 365', mx: /mail\.protection\.outlook\.com\.?$/i, spf: /spf\.protection\.outlook\.com/i, selectors: ['selector1', 'selector2'] },
  { name: 'Zoho', mx: /zoho\.(com|eu|in)\.?$/i, spf: /zoho\.(com|eu|in)/i, selectors: ['zmail', 'zoho'] },
  { name: 'Fastmail', mx: /messagingengine\.com\.?$/i, spf: /messagingengine\.com/i, selectors: ['fm1', 'fm2', 'fm3'] },
  { name: 'Proton Mail', mx: /protonmail\.ch\.?$/i, spf: /_spf\.protonmail\.ch/i, selectors: ['protonmail', 'protonmail2', 'protonmail3'] },
  { name: 'iCloud', mx: /mail\.icloud\.com\.?$/i, spf: /icloud\.com/i, selectors: ['sig1'] },
  { name: 'Amazon SES', mx: /amazonses\.com|amazonaws\.com\.?$/i, spf: /amazonses\.com/i, selectors: ['amazonses'] },
  { name: 'Mailchimp / Mandrill', spf: /servers\.mcsv\.net|mandrillapp\.com/i, selectors: ['k1', 'k2', 'k3', 'mandrill'] },
  { name: 'SendGrid', spf: /sendgrid\.net/i, selectors: ['s1', 's2', 'smtpapi'] },
  { name: 'Mailgun', mx: /mailgun\.org\.?$/i, spf: /mailgun\.org/i, selectors: ['mx', 'k1', 'krs', 'pic'] },
  { name: 'Postmark', spf: /mtasv\.net|spf\.postmarkapp\.com/i, selectors: ['pm', '20210112'] },
  { name: 'Brevo (Sendinblue)', spf: /sendinblue\.com|brevo\.com/i, selectors: ['mail', 'brevo1', 'brevo2'] },
  { name: 'Mailjet', spf: /mailjet\.com/i, selectors: ['mailjet'] },
  { name: 'HubSpot', spf: /hubspotemail\.net|hubspot\.com/i, selectors: ['hs1', 'hs2'] },
  { name: 'Salesforce', spf: /_spf\.salesforce\.com/i, selectors: ['sf1', 'sf2'] },
  { name: 'Zendesk', spf: /mail\.zendesk\.com/i, selectors: ['zendesk1', 'zendesk2'] },
];

/** Providers detected from MX hosts and SPF record text. */
export function detectProviders(mxHosts = [], spf = '') {
  return DKIM_PROVIDERS.filter((p) => (p.mx && mxHosts.some((h) => p.mx.test(h))) || (p.spf && p.spf.test(spf)));
}

/** Parse a BIMI record: v=BIMI1; l=<svg url>; a=<pem url>. */
export function parseBimi(record) {
  const { tags } = parseTags(record);
  const errors = [];
  if (!/^v=BIMI1\s*(;|$)/i.test(record.trim())) errors.push('record must start with v=BIMI1');
  if (tags.l === undefined) errors.push('missing l= (logo URL)');
  return { version: tags.v, logo: tags.l ?? null, authority: tags.a ?? null, errors };
}

export async function checkBimi(ctx, d) {
  const name = `default._bimi.${d.domain}`;
  const r = await ctx.resolver.query(name, 'TXT');
  if (['SERVFAIL', 'TIMEOUT', 'ERROR', 'REFUSED'].includes(r.status)) return ctx.error(d, `BIMI lookup failed: ${r.status}`);
  const recs = r.answers.filter((t) => /^v=BIMI1/i.test(t.trim()));
  d.summary.bimi = recs[0] ?? null;
  if (!recs.length) return;
  if (recs.length > 1) return ctx.add(d, 'bimi-invalid', name, `${recs.length} BIMI records at ${name}`, 'Publish exactly one v=BIMI1 record.', undefined, recs.join(' | '));
  const b = parseBimi(recs[0]);
  if (b.errors.length) return ctx.add(d, 'bimi-invalid', name, `BIMI record is invalid: ${b.errors.join('; ')}`, 'Use `v=BIMI1; l=https://…/logo.svg; a=https://…/vmc.pem`.', undefined, recs[0]);
  if (b.logo && !/^https:\/\/\S+\.svg(\?|$)/i.test(b.logo)) ctx.add(d, 'bimi-invalid', name, `BIMI logo must be an https:// SVG (Tiny PS) URL, got "${b.logo}"`, 'Host the SVG Tiny PS logo over HTTPS.', 'medium', recs[0]);
  if (b.authority && !/^https:\/\//i.test(b.authority)) ctx.add(d, 'bimi-invalid', name, `BIMI a= must be an https:// URL to the VMC/CMC certificate`, 'Point a= at the PEM over HTTPS.', 'medium', recs[0]);
  if (!b.authority) ctx.add(d, 'bimi-no-certificate', name, 'BIMI has no a= certificate (VMC/CMC); Gmail and Apple Mail will not show the logo', 'Obtain a Verified Mark Certificate (or Common Mark Certificate) and add a=https://…/vmc.pem.', undefined, recs[0]);
  const dm = d.summary.dmarc ? parseTags(d.summary.dmarc).tags : null;
  const p = dm?.p?.toLowerCase(); const pct = dm?.pct === undefined ? 100 : Number(dm.pct);
  if (!dm || !['quarantine', 'reject'].includes(p) || pct < 100) ctx.add(d, 'bimi-dmarc-not-enforced', name, `BIMI needs DMARC p=quarantine or p=reject at pct=100; ${dm ? `the policy is p=${p}${pct < 100 ? ` pct=${pct}` : ''}` : 'there is no DMARC record'}`, 'Enforce DMARC first, then BIMI logos can be shown.', undefined, recs[0]);
}

/**
 * Validate an ARC set from raw message headers (RFC 8617): every instance i=1..n must have
 * ARC-Seal, ARC-Message-Signature and ARC-Authentication-Results, and cv= must be none for i=1, pass after.
 * Returns { instances, valid, problems, cv }.
 */
export function checkArcHeaders(headers) {
  const text = String(headers).replace(/\r?\n[ \t]+/g, ' ');
  const sets = {};
  for (const m of text.matchAll(/^(ARC-Seal|ARC-Message-Signature|ARC-Authentication-Results):\s*(.*)$/gim)) {
    const i = /(?:^|;)\s*i\s*=\s*(\d+)/i.exec(m[2])?.[1]; if (!i) continue;
    const s = (sets[i] ||= {}); s[m[1].toLowerCase()] = m[2];
  }
  const ids = Object.keys(sets).map(Number).sort((a, b) => a - b); const problems = [];
  if (!ids.length) return { instances: 0, valid: null, problems: ['no ARC headers'], cv: null };
  ids.forEach((i, k) => { if (i !== k + 1) problems.push(`instance numbers are not contiguous (missing i=${k + 1})`); });
  if (ids.length > 50) problems.push('more than 50 ARC instances');
  let cv = null;
  for (const i of ids) {
    const s = sets[i];
    for (const h of ['arc-seal', 'arc-message-signature', 'arc-authentication-results']) if (!s[h]) problems.push(`i=${i} has no ${h.replace(/(^|-)(\w)/g, (_, a, b) => a + b.toUpperCase())}`);
    if (s['arc-seal']) {
      const { tags } = parseTags(s['arc-seal'].replace(/^\s*/, ''));
      cv = (tags.cv || '').toLowerCase();
      if (i === 1 && cv !== 'none') problems.push(`i=1 must have cv=none (got cv=${cv || 'missing'})`);
      if (i > 1 && cv !== 'pass') problems.push(`i=${i} has cv=${cv || 'missing'}: the chain ${cv === 'fail' ? 'is broken' : 'is invalid'}`);
      if (!tags.b) problems.push(`i=${i} ARC-Seal has no b= signature`);
      if (!tags.s || !tags.d) problems.push(`i=${i} ARC-Seal needs s= (selector) and d= (domain)`);
    }
  }
  return { instances: ids.length, valid: problems.length === 0, problems, cv, sealers: ids.map((i) => parseTags(sets[i]['arc-seal'] || '').tags.d).filter(Boolean) };
}
