import { createPublicKey } from 'node:crypto';
import { isIP } from 'node:net';
import { orgDomain, parseTags, withTimeout } from './util.js';
import { matchService } from './takeover.js';
import { attemptAxfr } from './resolvers.js';

const OK = (r) => r.status === 'NOERROR';
const FAILED = (r) => ['SERVFAIL', 'TIMEOUT', 'ERROR', 'REFUSED'].includes(r.status);

// ---------------- SPF ----------------
const SPF_LOOKUP_MECHS = new Set(['include', 'a', 'mx', 'ptr', 'exists']);
const SPF_MECHS = new Set(['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists']);

export function parseSpf(record) {
  const terms = record.trim().split(/\s+/).slice(1);
  const out = { mechanisms: [], modifiers: {}, errors: [] };
  for (const t of terms) {
    const mod = t.match(/^([a-z][a-z0-9_.-]*)=(.*)$/i);
    if (mod) { out.modifiers[mod[1].toLowerCase()] = mod[2]; continue; }
    const m = t.match(/^([+?~-]?)([a-z0-9]+)(?:[:/](.*))?$/i);
    if (!m || !SPF_MECHS.has(m[2].toLowerCase())) { out.errors.push(`Unknown term "${t}"`); continue; }
    const name = m[2].toLowerCase();
    const value = t.includes(':') ? t.slice(t.indexOf(':') + 1) : null;
    if ((name === 'include' || name === 'exists') && !value) out.errors.push(`"${t}" needs a domain`);
    if ((name === 'ip4' || name === 'ip6') && (!value || !isIP(value.split('/')[0]))) out.errors.push(`"${t}" is not a valid ${name} address`);
    out.mechanisms.push({ qualifier: m[1] || '+', name, value, raw: t });
  }
  return out;
}

async function spfRecords(ctx, domain) {
  const r = await ctx.resolver.query(domain, 'TXT');
  if (FAILED(r)) return { error: r.status };
  return { status: r.status, records: r.answers.filter((t) => /^v=spf1(\s|$)/i.test(t)) };
}

/** Count DNS-querying terms recursively (RFC 7208 §4.6.4). */
async function countLookups(ctx, domain, state, depth = 0) {
  if (state.visited.has(domain)) { state.problems.push(`include loop at ${domain}`); return; }
  state.visited.add(domain);
  const res = depth === 0 ? state.root : await spfRecords(ctx, domain);
  if (res.error) { state.problems.push(`lookup of ${domain} failed (${res.error})`); return; }
  if (depth > 0 && res.records.length === 0) { state.voids++; state.problems.push(`${domain} has no SPF record (include target → permerror)`); state.brokenIncludes.push(domain); return; }
  if (res.records.length !== 1) return;
  const spf = parseSpf(res.records[0]);
  for (const m of spf.mechanisms) {
    if (!SPF_LOOKUP_MECHS.has(m.name)) continue;
    state.lookups++;
    if (m.name === 'ptr') state.ptr.push(depth === 0 ? domain : `${domain} (via include)`);
    if (state.lookups > 10 + 5) return;
    if (m.name === 'include') await countLookups(ctx, m.value.toLowerCase(), state, depth + 1);
    else if (m.name === 'a' || m.name === 'mx' || m.name === 'exists') {
      const target = (m.value || domain).replace(/\/.*$/, '');
      if (target.includes('%{')) continue;
      const q = await ctx.resolver.query(target, m.name === 'mx' ? 'MX' : 'A');
      if (q.status === 'NXDOMAIN' || q.status === 'NODATA') state.voids++;
    }
  }
  if (spf.modifiers.redirect && !spf.mechanisms.some((m) => m.name === 'all')) { state.lookups++; await countLookups(ctx, spf.modifiers.redirect.toLowerCase(), state, depth + 1); }
}

export async function checkSpf(ctx, d) {
  const res = await spfRecords(ctx, d.domain);
  if (res.error) return ctx.error(d, `SPF lookup failed: ${res.error}`);
  d.summary.spf = res.records;
  const nonMail = d.nullMx || d.noMx;
  if (res.records.length === 0) {
    return ctx.add(d, 'spf-missing', d.domain, nonMail ? `${d.domain} has no SPF record; even domains that send no mail should say so, or spammers can spoof them` : `${d.domain} has no SPF record, so receivers cannot tell which servers may send its mail`,
      nonMail ? `Publish \`${d.domain}. TXT "v=spf1 -all"\` (this domain sends no mail).` : `Publish one TXT record listing your senders, e.g. \`v=spf1 include:_spf.google.com -all\`.`, nonMail ? 'medium' : undefined);
  }
  if (res.records.length > 1) {
    ctx.add(d, 'spf-multiple', d.domain, `${d.domain} has ${res.records.length} SPF records; receivers treat this as a permanent error and SPF fails`, 'Merge them into a single `v=spf1 … -all` TXT record.', undefined, res.records.join(' | '));
    return;
  }
  const rec = res.records[0];
  const spf = parseSpf(rec);
  if (spf.errors.length) ctx.add(d, 'spf-invalid', d.domain, `SPF syntax error: ${spf.errors.join('; ')}`, 'Fix the record syntax (RFC 7208); a syntax error is a permerror and SPF fails.', undefined, rec);
  const all = spf.mechanisms.find((m) => m.name === 'all');
  if (all) {
    if (all.qualifier === '+') ctx.add(d, 'spf-pass-all', d.domain, `SPF ends in "${all.raw}", authorising every server on the internet to send as ${d.domain}`, 'Change to `-all` (or `~all` while testing).', undefined, rec);
    else if (all.qualifier === '?') ctx.add(d, 'spf-neutral-all', d.domain, 'SPF ends in "?all" (neutral), which gives receivers no instruction about unlisted senders', 'Change to `-all` once all legitimate senders are listed (`~all` as an interim step).', undefined, rec);
    else if (all.qualifier === '~') ctx.add(d, 'spf-softfail-all', d.domain, 'SPF ends in "~all" (softfail). With an enforcing DMARC policy this is fine; otherwise -all is stronger', 'Consider `-all` once you are confident all senders are listed.', undefined, rec);
    const after = spf.mechanisms.slice(spf.mechanisms.indexOf(all) + 1);
    if (after.length) ctx.add(d, 'spf-invalid', d.domain, `Terms after "all" are never evaluated: ${after.map((m) => m.raw).join(' ')}`, 'Move them before the all mechanism.', 'low', rec);
  } else if (!spf.modifiers.redirect) ctx.add(d, 'spf-no-all', d.domain, 'SPF has no "all" mechanism or redirect, so unlisted senders get a neutral result', 'End the record with `-all`.', undefined, rec);
  const state = { lookups: 0, voids: 0, visited: new Set(), problems: [], ptr: [], brokenIncludes: [], root: res };
  await countLookups(ctx, d.domain, state);
  d.summary.spfLookups = state.lookups;
  if (state.lookups > 10) ctx.add(d, 'spf-too-many-lookups', d.domain, `SPF needs ${state.lookups > 15 ? 'more than 15' : state.lookups} DNS lookups (limit 10); receivers return permerror and SPF fails`, 'Remove unused includes, replace `a`/`mx` with `ip4:`/`ip6:` ranges, or flatten nested includes. Keep the total at 10 or fewer.', undefined, rec);
  if (state.voids > 2) ctx.add(d, 'spf-void-lookups', d.domain, `SPF has ${state.voids} void lookups (limit 2)`, 'Remove mechanisms that point to names with no records.', undefined, rec);
  if (state.ptr.length) ctx.add(d, 'spf-ptr', d.domain, `SPF uses the "ptr" mechanism (${state.ptr.join(', ')}), which is slow, unreliable and deprecated by RFC 7208`, 'Replace `ptr` with explicit `ip4:`/`ip6:` or `include:` terms.', undefined, rec);
  for (const b of state.brokenIncludes) ctx.add(d, 'spf-invalid', d.domain, `include:${b} has no SPF record, which is a permerror`, `Remove \`include:${b}\` or fix the provider record.`, undefined, rec);
  if (state.problems.some((p) => /loop/.test(p))) ctx.add(d, 'spf-invalid', d.domain, `SPF ${state.problems.find((p) => /loop/.test(p))}`, 'Remove the circular include.', undefined, rec);
  const spfAllows = spf.mechanisms.some((m) => m.name !== 'all' && m.qualifier === '+') || all?.qualifier === '+';
  if (d.nullMx && spfAllows) ctx.add(d, 'null-mx-spf', d.domain, `${d.domain} publishes a null MX (no mail) but its SPF authorises senders`, 'If the domain really sends no mail, use `v=spf1 -all`; otherwise remove the null MX.', undefined, rec);
}

// ---------------- DMARC ----------------
const STRENGTH = { none: 0, quarantine: 1, reject: 2 };
export async function checkDmarc(ctx, d) {
  const name = `_dmarc.${d.domain}`;
  const r = await ctx.resolver.query(name, 'TXT');
  if (FAILED(r)) return ctx.error(d, `DMARC lookup failed: ${r.status}`);
  let recs = r.answers.filter((t) => /^v=DMARC1\s*(;|$)/i.test(t.trim()));
  let source = name; let inherited = false;
  const org = orgDomain(d.domain);
  if (!recs.length && org !== d.domain) {
    const o = await ctx.resolver.query(`_dmarc.${org}`, 'TXT');
    const orecs = o.answers.filter((t) => /^v=DMARC1\s*(;|$)/i.test(t.trim()));
    if (orecs.length === 1) { recs = orecs; source = `_dmarc.${org}`; inherited = true; }
  }
  d.summary.dmarc = recs[0] ?? null;
  const nonMail = d.nullMx || d.noMx;
  if (!recs.length) return ctx.add(d, 'dmarc-missing', name, `${d.domain} has no DMARC record${org !== d.domain ? ` (nor does ${org})` : ''}, so spoofed mail is not rejected and you get no reports`,
    nonMail ? `Publish \`_dmarc.${d.domain}. TXT "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"\`.` : `Start with \`_dmarc.${d.domain}. TXT "v=DMARC1; p=none; rua=mailto:dmarc@${d.domain}"\`, review the reports, then move to p=quarantine and p=reject.`);
  if (recs.length > 1) return ctx.add(d, 'dmarc-multiple', name, `${recs.length} DMARC records at ${name}; receivers ignore DMARC entirely`, 'Keep exactly one `v=DMARC1` TXT record.', undefined, recs.join(' | '));
  const rec = recs[0];
  const { tags } = parseTags(rec);
  const p = tags.p?.toLowerCase();
  const effective = inherited ? (tags.sp?.toLowerCase() || p) : p;
  if (!(p in STRENGTH)) return ctx.add(d, 'dmarc-invalid', source, `DMARC record has ${p === undefined ? 'no p= tag' : `invalid p=${tags.p}`}${!rec.trim().match(/^v=DMARC1\s*;\s*p=/i) ? ' (p must directly follow v=DMARC1)' : ''}`, 'Use `v=DMARC1; p=none|quarantine|reject; rua=mailto:…`.', undefined, rec);
  const where = inherited ? ` (inherited from ${org} via sp=)` : '';
  if (effective === 'none') ctx.add(d, 'dmarc-policy-none', source, `DMARC policy is p=none${where}: spoofed mail is reported but still delivered`, 'Once reports show your legitimate mail passes, move to `p=quarantine` and then `p=reject`.', nonMail ? 'high' : undefined, rec);
  if (!tags.rua) ctx.add(d, 'dmarc-no-rua', source, `DMARC has no rua= address, so you receive no aggregate reports`, `Add \`rua=mailto:dmarc-reports@${org}\` (or a DMARC reporting service).`, undefined, rec);
  if (tags.pct !== undefined && Number(tags.pct) < 100 && effective !== 'none') ctx.add(d, 'dmarc-pct', source, `DMARC pct=${tags.pct}: the policy applies to only ${tags.pct}% of failing mail`, 'Raise to `pct=100` (or remove pct) once rollout is complete.', undefined, rec);
  if (!inherited && tags.sp && STRENGTH[tags.sp.toLowerCase()] !== undefined && STRENGTH[tags.sp.toLowerCase()] < STRENGTH[p]) ctx.add(d, 'dmarc-weak-subdomain', source, `DMARC sp=${tags.sp} is weaker than p=${p}, so attackers can spoof any subdomain`, `Set \`sp=${p}\` (or remove sp to inherit p).`, undefined, rec);
  if (tags.sp && STRENGTH[tags.sp.toLowerCase()] === undefined) ctx.add(d, 'dmarc-invalid', source, `Invalid sp=${tags.sp}`, 'Use sp=none, quarantine or reject.', 'medium', rec);
  if (tags.pct !== undefined && !/^\d+$/.test(tags.pct)) ctx.add(d, 'dmarc-invalid', source, `Invalid pct=${tags.pct}`, 'pct must be 0–100.', 'medium', rec);
}

// ---------------- DKIM ----------------
export const COMMON_SELECTORS = ['default', 'dkim', 'mail', 'selector1', 'selector2', 'google', 'k1', 'k2', 'k3', 's1', 's2', 'smtp', 'mx', 'fm1', 'fm2', 'fm3', 'protonmail', 'protonmail2', 'protonmail3', 'zoho', 'zmail', 'mandrill', 'mxvault', 'everlytickey1', 'everlytickey2', 'cm', 'sig1', 'mailjet', 'amazonses', 'dkim1', 'key1'];

export function dkimKeyBits(p, k = 'rsa') {
  if (k.toLowerCase() === 'ed25519') return { type: 'ed25519', bits: 256 };
  const der = Buffer.from(p.replace(/\s+/g, ''), 'base64');
  try { const key = createPublicKey({ key: der, format: 'der', type: 'spki' }); return { type: key.asymmetricKeyType, bits: key.asymmetricKeyDetails?.modulusLength }; } catch {}
  try { const key = createPublicKey({ key: der, format: 'der', type: 'pkcs1' }); return { type: key.asymmetricKeyType, bits: key.asymmetricKeyDetails?.modulusLength }; } catch {}
  return null;
}

export async function checkDkim(ctx, d) {
  const explicit = ctx.opts.dkimSelectors || [];
  const selectors = [...new Set([...explicit, ...(ctx.opts.dkimCommon ? COMMON_SELECTORS : [])])];
  d.summary.dkim = {};
  if (!selectors.length) { d.summary.dkim = null; return; }
  let found = 0;
  await Promise.all(selectors.map(async (sel) => {
    const name = `${sel}._domainkey.${d.domain}`;
    const r = await ctx.resolver.query(name, 'TXT');
    if (FAILED(r)) { ctx.error(d, `DKIM ${sel} lookup failed: ${r.status}`); return; }
    const recs = r.answers.filter((t) => /(^|;)\s*(v=DKIM1|p=|k=)/i.test(t));
    if (!recs.length) {
      d.summary.dkim[sel] = 'missing';
      if (explicit.includes(sel)) ctx.add(d, 'dkim-missing', name, `DKIM selector "${sel}" has no key at ${name}${r.cnames ? ` (CNAME → ${r.cnames.join(' → ')})` : ''}`, 'Publish the public key your mail provider gives you for this selector, or stop signing with it.');
      return;
    }
    found++;
    const rec = recs[0];
    const { tags } = parseTags(rec);
    if (tags.v && tags.v !== 'DKIM1') ctx.add(d, 'dkim-invalid', name, `DKIM record has v=${tags.v}`, 'Use v=DKIM1.', undefined, rec);
    if (tags.p === undefined) { ctx.add(d, 'dkim-invalid', name, `DKIM record for "${sel}" has no p= tag`, 'Publish `v=DKIM1; k=rsa; p=<base64 public key>`.', undefined, rec); d.summary.dkim[sel] = 'invalid'; return; }
    if (tags.p === '') { ctx.add(d, 'dkim-revoked', name, `DKIM selector "${sel}" is revoked (empty p=)`, 'Fine if the key was retired on purpose; make sure nothing still signs with it, and remove the record eventually.', undefined, rec); d.summary.dkim[sel] = 'revoked'; return; }
    const key = dkimKeyBits(tags.p, tags.k || 'rsa');
    if (!key) { ctx.add(d, 'dkim-invalid', name, `DKIM key for "${sel}" could not be parsed`, 'Check the record for truncation or stray characters (long keys must be split into several strings, not several records).', undefined, rec); d.summary.dkim[sel] = 'invalid'; return; }
    d.summary.dkim[sel] = `${key.type} ${key.bits}`;
    if (key.type === 'rsa' && key.bits < 1024) ctx.add(d, 'dkim-weak-key', name, `DKIM selector "${sel}" uses a ${key.bits}-bit RSA key, which can be factored; anyone could forge signed mail`, 'Rotate to a 2048-bit RSA (or Ed25519 alongside RSA) key now and revoke this selector.', 'critical', rec);
    else if (key.type === 'rsa' && key.bits < 2048) ctx.add(d, 'dkim-weak-key', name, `DKIM selector "${sel}" uses a ${key.bits}-bit RSA key (below the recommended 2048)`, 'Rotate to a 2048-bit RSA key with a new selector, then revoke this one.', 'medium', rec);
    if (/\by\b/.test(tags.t || '')) ctx.add(d, 'dkim-testing', name, `DKIM selector "${sel}" is in testing mode (t=y); receivers may ignore failures`, 'Remove `t=y` once signing is verified.', undefined, rec);
  }));
  if (!found && selectors.length && !explicit.length) ctx.add(d, 'dkim-not-found', `_domainkey.${d.domain}`, `No DKIM key found on ${selectors.length} common selectors`, 'Pass your real selector with --dkim-selector (find it in the s= tag of a DKIM-Signature header).');
}

// ---------------- MX, null MX, MTA-STS, TLS-RPT ----------------
export async function checkMx(ctx, d) {
  const r = d.mx;
  if (FAILED(r)) return ctx.error(d, `MX lookup failed: ${r.status}`);
  d.summary.mx = r.answers.map((m) => `${m.priority} ${m.exchange || '.'}`);
  if (!r.answers.length) {
    return ctx.add(d, 'mx-missing', d.domain, `${d.domain} has no MX record; mail falls back to the A record and the domain's mail intent is ambiguous`, `If the domain does not receive mail, publish a null MX (RFC 7505): \`${d.domain}. MX 0 .\`, plus \`v=spf1 -all\` and DMARC p=reject.`);
  }
  const nul = r.answers.filter((m) => m.exchange === '' || m.exchange === '.');
  if (nul.length && r.answers.length > nul.length) ctx.add(d, 'null-mx-misconfigured', d.domain, 'A null MX ("0 .") is published alongside real MX hosts; senders may refuse to deliver', 'Remove the null MX if the domain receives mail, or remove the other MX records if it does not.');
  for (const m of r.answers.filter((x) => x.exchange && x.exchange !== '.')) {
    if (isIP(m.exchange)) { ctx.add(d, 'mx-ip-literal', d.domain, `MX points to an IP address (${m.exchange}); MX must name a host`, `Create an A record (e.g. mx.${d.domain}) and point the MX at it.`); continue; }
    const [a, aaaa, c] = await Promise.all([ctx.resolver.query(m.exchange, 'A'), ctx.resolver.query(m.exchange, 'AAAA'), ctx.resolver.query(m.exchange, 'CNAME')]);
    if (OK(c) && c.answers.length) ctx.add(d, 'mx-cname', d.domain, `MX host ${m.exchange} is a CNAME (${c.answers[0]}); RFC 5321 requires an address record`, 'Point the MX at the canonical host name.');
    if (!OK(a) && !OK(aaaa) && !FAILED(a)) ctx.add(d, 'mx-dangling', d.domain, `MX host ${m.exchange} does not resolve (${a.status}); mail to ${d.domain} cannot be delivered${a.status === 'NXDOMAIN' && !m.exchange.endsWith(d.domain) ? ' and the name may be registrable by someone else' : ''}`, 'Fix or remove the MX record.', a.status === 'NXDOMAIN' ? 'high' : 'medium');
  }
}

export async function fetchText(ctx, url) {
  const f = ctx.fetch;
  const ctrl = new AbortController();
  const res = await withTimeout(f(url, { redirect: 'manual', signal: ctrl.signal, headers: { 'user-agent': 'dns-sentinel' } }), ctx.opts.timeout || 8000, `timeout fetching ${url}`).catch((e) => { ctrl.abort(); throw e; });
  const body = await withTimeout(res.text(), ctx.opts.timeout || 8000, 'timeout reading body');
  return { status: res.status, body };
}

export function parseStsPolicy(text) {
  const p = { mx: [] };
  for (const line of String(text).split(/\r?\n/)) {
    const m = line.match(/^\s*([a-z_]+)\s*:\s*(.*?)\s*$/i);
    if (!m) continue;
    const k = m[1].toLowerCase();
    if (k === 'mx') p.mx.push(m[2].toLowerCase()); else p[k] = m[2];
  }
  return p;
}
const stsMatch = (pattern, host) => (pattern.startsWith('*.') ? host.endsWith(pattern.slice(1)) && host.split('.').length === pattern.split('.').length : host === pattern);

export async function checkMtaSts(ctx, d) {
  if (d.nullMx || d.noMx) return;
  const name = `_mta-sts.${d.domain}`;
  const r = await ctx.resolver.query(name, 'TXT');
  if (FAILED(r)) return ctx.error(d, `MTA-STS lookup failed: ${r.status}`);
  const recs = r.answers.filter((t) => /^v=STSv1/i.test(t.trim()));
  d.summary.mtaSts = recs[0] ?? null;
  if (!recs.length) return ctx.add(d, 'mta-sts-missing', name, `${d.domain} has no MTA-STS, so inbound SMTP TLS can be downgraded by an attacker`, `Publish \`${name}. TXT "v=STSv1; id=20260101"\` and a policy at https://mta-sts.${d.domain}/.well-known/mta-sts.txt (start with mode: testing).`);
  if (recs.length > 1) return ctx.add(d, 'mta-sts-invalid', name, 'Multiple MTA-STS TXT records; senders will ignore MTA-STS', 'Keep exactly one record.');
  const { tags } = parseTags(recs[0]);
  if (!tags.id || !/^[A-Za-z0-9]{1,32}$/.test(tags.id)) ctx.add(d, 'mta-sts-invalid', name, `MTA-STS record has ${tags.id ? 'an invalid' : 'no'} id`, 'Use an id of 1–32 letters/digits and change it whenever the policy changes.', undefined, recs[0]);
  if (ctx.opts.http === false) return;
  const url = `https://mta-sts.${d.domain}/.well-known/mta-sts.txt`;
  let pol;
  try {
    const res = await fetchText(ctx, url);
    if (res.status !== 200) return ctx.add(d, 'mta-sts-invalid', url, `MTA-STS policy returned HTTP ${res.status}`, `Serve the policy at ${url} with a valid certificate and HTTP 200 (no redirects).`);
    pol = parseStsPolicy(res.body);
  } catch (e) { return ctx.add(d, 'mta-sts-invalid', url, `MTA-STS policy could not be fetched (${e.cause?.code || e.message})`, `Serve the policy at ${url} over HTTPS with a certificate valid for mta-sts.${d.domain}.`); }
  d.summary.mtaStsMode = pol.mode ?? null;
  if (pol.version !== 'STSv1' || !['enforce', 'testing', 'none'].includes(pol.mode) || !pol.max_age) return ctx.add(d, 'mta-sts-invalid', url, 'MTA-STS policy is missing version: STSv1, a valid mode or max_age', 'Policy must contain `version: STSv1`, `mode: enforce|testing|none`, `mx:` lines and `max_age:`.');
  if (pol.mode !== 'enforce') ctx.add(d, 'mta-sts-testing', url, `MTA-STS mode is "${pol.mode}", so TLS failures are not enforced`, 'Switch to `mode: enforce` once TLS-RPT reports are clean, and bump the id.');
  if (Number(pol.max_age) < 86400) ctx.add(d, 'mta-sts-testing', url, `MTA-STS max_age=${pol.max_age} is under a day`, 'Use max_age of at least 604800 (1 week) in enforce mode.', 'info');
  for (const m of (d.mx?.answers || []).filter((x) => x.exchange && x.exchange !== '.')) {
    if (!pol.mx.some((p) => stsMatch(p, m.exchange))) ctx.add(d, 'mta-sts-mx-mismatch', url, `MX host ${m.exchange} is not listed in the MTA-STS policy (mx: ${pol.mx.join(', ') || 'none'})`, `Add \`mx: ${m.exchange}\` (or a matching wildcard) to the policy; in enforce mode senders will refuse to deliver to it.`, pol.mode === 'enforce' ? 'high' : undefined);
  }
}

export async function checkTlsRpt(ctx, d) {
  if (d.nullMx || d.noMx) return;
  const name = `_smtp._tls.${d.domain}`;
  const r = await ctx.resolver.query(name, 'TXT');
  if (FAILED(r)) return ctx.error(d, `TLS-RPT lookup failed: ${r.status}`);
  const recs = r.answers.filter((t) => /^v=TLSRPTv1/i.test(t.trim()));
  d.summary.tlsRpt = recs[0] ?? null;
  if (!recs.length) return ctx.add(d, 'tlsrpt-missing', name, `${d.domain} has no TLS-RPT record, so you won't hear about SMTP TLS failures`, `Publish \`${name}. TXT "v=TLSRPTv1; rua=mailto:tls-reports@${d.domain}"\`.`);
  const { tags } = parseTags(recs[0]);
  if (recs.length > 1 || !tags.rua || !tags.rua.split(',').every((u) => /^(mailto:|https:)/i.test(u.trim()))) ctx.add(d, 'tlsrpt-invalid', name, recs.length > 1 ? 'Multiple TLS-RPT records' : 'TLS-RPT record needs rua=mailto:… or https:…', 'Publish one `v=TLSRPTv1; rua=mailto:…` record.', undefined, recs[0]);
}

// ---------------- CAA ----------------
const KNOWN_CAA_TAGS = new Set(['issue', 'issuewild', 'iodef', 'issuemail', 'issuevmc', 'contactemail', 'contactphone']);
export async function checkCaa(ctx, d) {
  let name = d.domain; let r;
  const labels = d.domain.split('.');
  for (let i = 0; i < labels.length - 1; i++) { // RFC 8659 tree climbing
    name = labels.slice(i).join('.');
    r = await ctx.resolver.query(name, 'CAA');
    if (FAILED(r)) return ctx.error(d, `CAA lookup failed: ${r.status}`);
    if (r.answers.length) break;
  }
  const recs = r.answers;
  d.summary.caa = recs.map((c) => `${c.critical ? 128 : 0} ${c.tag} "${c.value}"`);
  if (!recs.length) return ctx.add(d, 'caa-missing', d.domain, `No CAA records for ${d.domain} (or its parents), so any certificate authority may issue for it`, `Restrict issuance to your CAs, e.g. \`${d.domain}. CAA 0 issue "letsencrypt.org"\` and \`CAA 0 iodef "mailto:security@${orgDomain(d.domain)}"\`.`);
  const where = name !== d.domain ? ` (inherited from ${name})` : '';
  for (const c of recs) if (c.critical && !KNOWN_CAA_TAGS.has(String(c.tag).toLowerCase())) ctx.add(d, 'caa-critical-unknown', name, `CAA record "${c.tag}" has the critical flag but is not a known tag; CAs must refuse to issue${where}`, 'Remove the critical flag (use flags 0) or fix the tag name.');
  const ca = (v) => String(v).split(';')[0].trim().toLowerCase();
  const issue = recs.filter((c) => c.tag === 'issue').map((c) => ca(c.value)).filter(Boolean);
  const wild = recs.filter((c) => c.tag === 'issuewild').map((c) => ca(c.value)).filter(Boolean);
  const cas = new Set([...issue, ...wild]);
  if (!recs.some((c) => c.tag === 'issue' || c.tag === 'issuewild')) ctx.add(d, 'caa-permissive', name, `CAA records${where} contain no issue/issuewild tag, so they do not restrict any CA`, 'Add `CAA 0 issue "<your-ca>"`.');
  else if (cas.size > (ctx.opts.caaMaxIssuers ?? 3)) ctx.add(d, 'caa-permissive', name, `CAA${where} authorises ${cas.size} CAs (${[...cas].join(', ')})`, 'List only the CAs you actually use.');
  if (wild.length && issue.length === 0 && recs.some((c) => c.tag === 'issue')) {/* issue ";" with issuewild: fine */}
  if (!recs.some((c) => c.tag === 'iodef')) ctx.add(d, 'caa-no-iodef', name, 'CAA has no iodef tag, so CAs cannot report blocked requests', `Add \`CAA 0 iodef "mailto:security@${orgDomain(d.domain)}"\`.`);
}

// ---------------- DNSSEC ----------------
const WEAK_ALGS = { 1: 'RSAMD5', 3: 'DSA', 5: 'RSASHA1', 6: 'DSA-NSEC3-SHA1', 7: 'RSASHA1-NSEC3-SHA1', 12: 'ECC-GOST' };
export async function checkDnssec(ctx, d) {
  const r = ctx.dnssecResolver;
  const [ds, key, soa] = await Promise.all([r.query(d.domain, 'DS'), r.query(d.domain, 'DNSKEY'), r.query(d.domain, 'SOA')]);
  if ([ds, key, soa].every((x) => ['TIMEOUT', 'ERROR'].includes(x.status))) return ctx.error(d, `DNSSEC lookups failed via ${r.url || r.kind}: ${ds.error || ds.status}`);
  const hasDs = OK(ds) && ds.answers.length > 0; const hasKey = OK(key) && key.answers.length > 0;
  const validated = !!(soa.ad || ds.ad || key.ad);
  d.summary.dnssec = { ds: hasDs, dnskey: hasKey, validated, status: soa.status };
  if (soa.status === 'SERVFAIL' && (hasDs || ds.status === 'SERVFAIL')) return ctx.add(d, 'dnssec-broken', d.domain, `Validating resolvers return SERVFAIL for ${d.domain}${hasDs ? ' although a DS record exists' : ''}: the domain is unreachable for DNSSEC-validating users`, 'Check the DS at the registrar matches a current DNSKEY (key rollover gone wrong is the usual cause) and that signatures have not expired.');
  if (validated) {
    for (const k of key.answers) if (WEAK_ALGS[k.algorithm]) { ctx.add(d, 'dnssec-weak-algorithm', d.domain, `DNSKEY uses algorithm ${k.algorithm} (${WEAK_ALGS[k.algorithm]}), which is deprecated`, 'Roll the zone to algorithm 13 (ECDSAP256SHA256) or 8 (RSASHA256).'); break; }
    if (hasDs && ds.answers.every((x) => x.digestType === 1)) ctx.add(d, 'dnssec-weak-algorithm', d.domain, 'DS records use only SHA-1 digests (type 1)', 'Publish a DS with digest type 2 (SHA-256) and remove the SHA-1 one.', 'low');
    return;
  }
  if (hasDs) return ctx.add(d, 'dnssec-broken', d.domain, `${d.domain} has a DS record but the answer is not validated (AD flag unset)`, 'Check the DNSKEY/RRSIG records match the DS at the registrar.');
  if (hasKey) return ctx.add(d, 'dnssec-no-ds', d.domain, `${d.domain} is signed (DNSKEY present) but there is no DS at the parent, so nothing is validated`, 'Add the DS record at your registrar to complete the chain of trust.');
  ctx.add(d, 'dnssec-disabled', d.domain, `DNSSEC is not enabled for ${d.domain}; answers can be spoofed by cache poisoning`, 'Enable DNSSEC signing at your DNS provider and publish the DS record at your registrar.');
}

// ---------------- CNAMEs / takeover ----------------
async function cnameChain(ctx, name) {
  const chain = []; let cur = name;
  for (let i = 0; i < 10; i++) {
    const r = await ctx.resolver.query(cur, 'CNAME');
    if (FAILED(r)) return { chain, error: r.status, start: r };
    if (!r.answers.length) return { chain, terminal: cur, status: r.status };
    cur = String(r.answers[0]).toLowerCase().replace(/\.$/, '');
    chain.push(cur);
  }
  return { chain, terminal: cur, loop: true };
}

export async function fingerprint(ctx, host, svc) {
  if (ctx.opts.http === false || !svc.fingerprints.length) return null;
  for (const scheme of ['https', 'http']) {
    try {
      const res = await fetchText(ctx, `${scheme}://${host}/`);
      const hit = svc.fingerprints.find((f) => res.body.includes(f));
      if (hit) return { url: `${scheme}://${host}/`, fingerprint: hit, status: res.status };
      return null;
    } catch {}
  }
  return null;
}

export async function auditCname(ctx, d, sub, { wildcard = false } = {}) {
  const c = await cnameChain(ctx, sub);
  if (c.error) return ctx.error(d, `CNAME lookup for ${sub} failed: ${c.error}`);
  if (!c.chain.length) { if (!wildcard) d.summary.subdomains[sub] = c.status === 'NXDOMAIN' ? 'NXDOMAIN' : 'no CNAME'; return; }
  const target = c.chain[c.chain.length - 1];
  if (!wildcard) d.summary.subdomains[sub] = `CNAME → ${c.chain.join(' → ')}`;
  if (c.loop) return ctx.add(d, 'dangling-cname', sub, `${sub} has a CNAME loop or chain longer than 10`, 'Fix the CNAME chain.', 'medium');
  const svc = c.chain.map(matchService).find(Boolean);
  const [a, aaaa] = await Promise.all([ctx.resolver.query(target, 'A'), ctx.resolver.query(target, 'AAAA')]);
  const label = wildcard ? `Wildcard ${sub}` : sub;
  if (a.status === 'NXDOMAIN' && aaaa.status === 'NXDOMAIN') {
    if (svc) return ctx.add(d, 'subdomain-takeover', sub, `${label} points to ${target} (${svc.name}), which does not exist. Anyone can create it there and serve content on ${wildcard ? 'any subdomain' : sub}`, `Delete the CNAME${wildcard ? ' wildcard' : ''} now, or re-create the ${svc.name} resource and keep it.`);
    return ctx.add(d, 'dangling-cname', sub, `${label} points to ${target}, which does not exist (NXDOMAIN)${target.endsWith(orgDomain(d.domain)) ? '' : '. If that domain is unregistered, an attacker can register it'}`, 'Remove the stale CNAME or point it at a live host.');
  }
  if (!OK(a) && !OK(aaaa) && !FAILED(a)) {
    if (svc?.nxdomain) return ctx.add(d, 'subdomain-takeover', sub, `${label} points to ${target} (${svc.name}), which has no address records`, `Delete the CNAME or re-claim the ${svc.name} resource.`, 'high');
    return ctx.add(d, 'dangling-cname', sub, `${label} points to ${target}, which has no A/AAAA records`, 'Remove the stale CNAME or point it at a live host.', 'medium');
  }
  if (svc) {
    const fp = await fingerprint(ctx, sub.startsWith('*.') ? `dns-sentinel-${ctx.opts.randomLabel || 'probe'}.${sub.slice(2)}` : sub, svc);
    if (fp) return ctx.add(d, 'subdomain-takeover', sub, `${label} points to ${svc.name} (${target}) and ${fp.url} shows the unclaimed-resource page ("${fp.fingerprint}")`, `Remove the CNAME or claim the ${svc.name} resource for ${sub} immediately.`);
    ctx.add(d, 'takeover-prone-cname', sub, `${label} points to ${svc.name} (${target}); if that resource is ever deleted the subdomain can be taken over`, 'Keep an inventory of third-party CNAMEs and remove the DNS record before deleting the resource.');
  }
}

export async function checkCnames(ctx, d) {
  for (const s of d.subdomains) await auditCname(ctx, d, s);
}

// ---------------- wildcard ----------------
export async function checkWildcard(ctx, d) {
  const probe = `dns-sentinel-${ctx.opts.randomLabel || Math.random().toString(36).slice(2, 10)}.${d.domain}`;
  const [a, aaaa, cname, txt, mx] = await Promise.all(['A', 'AAAA', 'CNAME', 'TXT', 'MX'].map((t) => ctx.resolver.query(probe, t)));
  const uniq = cname.answers.length ? [['CNAME', cname]] : [['A', a], ['AAAA', aaaa], ['TXT', txt], ['MX', mx]].filter(([, r]) => OK(r) && r.answers.length);
  d.summary.wildcard = uniq.length ? uniq.map(([t, r]) => `${t} ${typeof r.answers[0] === 'object' ? JSON.stringify(r.answers[0]) : r.answers[0]}`) : null;
  if (!uniq.length) return;
  ctx.add(d, 'wildcard-record', `*.${d.domain}`, `${d.domain} has a wildcard record (${uniq.map(([t, r]) => `${t} ${typeof r.answers[0] === 'object' ? r.answers[0].exchange : r.answers[0]}`).join(', ')}): every possible subdomain resolves, which helps phishing and hides typos and dangling records`, 'Remove the wildcard and create explicit records, unless you need it (e.g. multi-tenant hosting).');
  if (cname.answers.length) await auditCname(ctx, d, `*.${d.domain}`, { wildcard: true }).catch(() => {});
}

// ---------------- AXFR ----------------
export async function checkAxfr(ctx, d) {
  const ns = await ctx.resolver.query(d.domain, 'NS');
  if (!OK(ns)) return;
  d.summary.axfr = {};
  for (const host of ns.answers) {
    let records = null;
    try {
      if (ctx.resolver.axfr) records = await ctx.resolver.axfr(d.domain, host);
      else {
        const a = await ctx.resolver.query(host, 'A');
        for (const ip of a.answers) { try { records = await attemptAxfr(ip, d.domain, { timeout: ctx.opts.timeout || 8000 }); } catch {} if (records) break; }
      }
    } catch {}
    d.summary.axfr[host] = records ? `ALLOWED (${records.length} records)` : 'refused or unreachable';
    if (records) ctx.add(d, 'zone-transfer', host, `Nameserver ${host} allows a full zone transfer (AXFR) of ${d.domain}: ${records.length} records exposed`, `Restrict AXFR on ${host} to your secondary nameservers (allow-transfer / TSIG).`);
  }
}
