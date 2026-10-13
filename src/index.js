import { SystemResolver, DohResolver, WireResolver, MockResolver, attemptAxfr, wireQuery } from './resolvers.js';
import { RULES, SEVERITIES, rank, CHECKS, DEFAULT_CHECKS } from './rules.js';
import { normalise, orgDomain, globRe, parseTags } from './util.js';
import * as C from './checks.js';
import { SERVICES, matchService } from './takeover.js';
export { encodeQuery, decodeMessage, encodeResponse, TYPES } from './wire.js';
export { formatText, formatJson, formatSarif, formatMarkdown } from './report.js';
export { SystemResolver, DohResolver, WireResolver, MockResolver, attemptAxfr, wireQuery, RULES, SEVERITIES, CHECKS, DEFAULT_CHECKS, orgDomain, parseTags, SERVICES, matchService };
export const { parseSpf, parseStsPolicy, dkimKeyBits, COMMON_SELECTORS } = C;
export const COMMON_SUBDOMAINS = ['www', 'mail', 'webmail', 'blog', 'shop', 'store', 'docs', 'help', 'support', 'status', 'app', 'api', 'dev', 'staging', 'test', 'beta', 'cdn', 'assets', 'static', 'media', 'files', 'images', 'portal', 'admin', 'login', 'auth', 'sso', 'vpn', 'remote', 'git', 'jobs', 'careers', 'news', 'events', 'community', 'forum', 'm', 'mobile', 'old', 'new'];

export class ConfigError extends Error {}

export function validateConfig(cfg = {}) {
  for (const [r, s] of Object.entries(cfg.severity || {})) {
    if (!RULES[r]) throw new ConfigError(`Unknown rule in "severity": ${r}`);
    if (s !== 'off' && !SEVERITIES.includes(s)) throw new ConfigError(`Invalid severity for ${r}: ${s}`);
  }
  for (const [i, a] of (cfg.allow || []).entries()) {
    if (!a || typeof a !== 'object' || !a.rule) throw new ConfigError(`allow[${i}] needs "rule"`);
    if (a.rule !== '*' && !a.rule.includes('*') && !RULES[a.rule]) throw new ConfigError(`allow[${i}]: unknown rule ${a.rule}`);
    if (!a.reason || !String(a.reason).trim()) throw new ConfigError(`allow[${i}] (${a.rule}) needs a "reason"`);
    if (a.expires && Number.isNaN(Date.parse(a.expires))) throw new ConfigError(`allow[${i}] (${a.rule}) has an invalid "expires" date`);
  }
  for (const c of cfg.checks || []) if (!CHECKS.includes(c)) throw new ConfigError(`Unknown check "${c}" (use ${CHECKS.join(', ')})`);
  return cfg;
}

export function makeResolvers(opts = {}) {
  const timeout = opts.timeout || 5000;
  const resolver = opts.resolver || (opts.doh ? new DohResolver(typeof opts.doh === 'string' ? opts.doh : undefined, { timeout, fetchImpl: opts.fetch }) : new SystemResolver(opts.servers || [], { timeout }));
  const dnssecResolver = opts.dnssecResolver || resolver.kind === 'doh' || resolver.kind === 'mock' ? (opts.dnssecResolver || resolver)
    : opts.dnssecDoh === false ? new WireResolver(resolver.servers, { timeout }) : new DohResolver(typeof opts.dnssecDoh === 'string' ? opts.dnssecDoh : undefined, { timeout, fetchImpl: opts.fetch });
  return { resolver, dnssecResolver };
}

/**
 * Audit one or more domains.
 * opts: { checks, dkimSelectors, dkimCommon, subdomains (per-domain relative or FQDN), commonSubdomains,
 *         resolver, servers, doh, dnssecDoh, fetch, http, timeout, severity, allow, now, randomLabel, caaMaxIssuers }
 */
export async function auditDomains(domains, opts = {}) {
  validateConfig(opts);
  const { resolver, dnssecResolver } = makeResolvers(opts);
  const checks = new Set(opts.checks || [...DEFAULT_CHECKS, ...(opts.axfr ? ['axfr'] : [])]);
  const now = opts.now ? new Date(opts.now) : new Date();
  const ctx = { resolver, dnssecResolver, opts, fetch: opts.fetch || globalThis.fetch };
  ctx.add = (d, rule, name, message, fix, severity, record) => d.raw.push({ rule, severity: severity || RULES[rule].severity, domain: d.domain, name, message, fix, ...(record ? { record } : {}) });
  ctx.error = (d, message) => { d.errors.push(message); };
  const results = [];
  for (const raw of [...new Set(domains.map(normalise).filter(Boolean))]) {
    const d = { domain: raw, summary: { subdomains: {} }, raw: [], errors: [], subdomains: [] };
    const subs = [...(opts.subdomains || []), ...(opts.commonSubdomains ? COMMON_SUBDOMAINS : [])];
    d.subdomains = [...new Set(subs.map((s) => normalise(s)).filter(Boolean).map((s) => (s === raw || s.endsWith('.' + raw) ? s : (s.includes('.') && !s.endsWith('.' + raw) && opts.subdomainsAreFqdn) ? s : `${s}.${raw}`)))];
    // base lookups
    d.mx = await resolver.query(raw, 'MX');
    const soa = await resolver.query(raw, 'SOA');
    if (['SERVFAIL', 'TIMEOUT', 'ERROR', 'REFUSED'].includes(d.mx.status) && ['SERVFAIL', 'TIMEOUT', 'ERROR', 'REFUSED'].includes(soa.status)) {
      d.errors.push(`DNS lookups for ${raw} failed (${d.mx.status}${d.mx.error ? `: ${d.mx.error}` : ''})`); d.fatal = true;
    } else if (d.mx.status === 'NXDOMAIN' && soa.status === 'NXDOMAIN') {
      d.errors.push(`${raw} does not exist (NXDOMAIN)`); d.fatal = true;
    } else {
      d.nullMx = d.mx.answers.length > 0 && d.mx.answers.every((m) => m.exchange === '' || m.exchange === '.');
      d.noMx = !d.mx.answers.length && !['SERVFAIL', 'TIMEOUT', 'ERROR'].includes(d.mx.status);
      const run = async (name, fn) => { if (!checks.has(name)) return; try { await fn(ctx, d); } catch (e) { d.errors.push(`${name}: ${e.message}`); } };
      await run('mx', C.checkMx);
      await run('spf', C.checkSpf);
      await run('dmarc', C.checkDmarc);
      await run('dkim', C.checkDkim);
      await run('mta-sts', C.checkMtaSts);
      await run('tls-rpt', C.checkTlsRpt);
      await run('caa', C.checkCaa);
      await run('dnssec', C.checkDnssec);
      await run('cname', C.checkCnames);
      await run('wildcard', C.checkWildcard);
      await run('axfr', C.checkAxfr);
    }
    results.push(d);
  }
  return buildReport(results, opts, now, { resolver: resolver.kind === 'doh' ? `DoH ${resolver.url}` : resolver.kind === 'system' ? `system (${resolver.servers.join(', ')})` : resolver.kind, dnssec: dnssecResolver.url ? `DoH ${dnssecResolver.url}` : dnssecResolver.kind, checks: [...checks] });
}

export function buildReport(results, opts, now, meta) {
  const today = now.toISOString().slice(0, 10);
  const allow = (opts.allow || []).map((a) => ({ ...a, used: false, expired: !!(a.expires && a.expires < today) }));
  const sev = opts.severity || {};
  const findings = []; const suppressed = [];
  for (const d of results) {
    d.findings = [];
    for (const f of d.raw) {
      if (sev[f.rule] === 'off') continue;
      const g = SEVERITIES.includes(sev[f.rule]) ? { ...f, severity: sev[f.rule] } : f;
      const a = allow.find((x) => globRe(x.rule).test(g.rule) && (!x.domain || globRe(x.domain).test(g.domain)) && (!x.name || globRe(x.name).test(g.name)));
      if (a && !a.expired) { a.used = true; suppressed.push({ ...g, allowedBy: { reason: a.reason, expires: a.expires } }); continue; }
      if (a && a.expired) { a.used = true; g.message += ` (allowlist entry expired ${a.expires})`; d.findings.push({ rule: 'allow-expired', severity: sev['allow-expired'] && sev['allow-expired'] !== 'off' ? sev['allow-expired'] : RULES['allow-expired'].severity, domain: d.domain, name: g.name, message: `Allowlist entry for ${a.rule}${a.domain ? ` on ${a.domain}` : ''} expired on ${a.expires} ("${a.reason}")`, fix: 'Re-review the finding and extend "expires", or fix the issue.' }); }
      d.findings.push(g);
    }
    d.findings.sort((x, y) => rank(x.severity) - rank(y.severity) || x.rule.localeCompare(y.rule));
    findings.push(...d.findings);
  }
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]));
  return {
    tool: 'dns-sentinel', generatedAt: now.toISOString(), resolver: meta.resolver, dnssecResolver: meta.dnssec, checks: meta.checks,
    domains: results.map((d) => ({ domain: d.domain, ...(d.fatal ? { fatal: true } : {}), summary: d.summary, findings: d.findings, errors: d.errors })),
    findings, suppressed, counts,
    errors: results.flatMap((d) => d.errors.map((e) => ({ domain: d.domain, error: e }))),
  };
}

export function exceeds(report, failOn = 'high') {
  if (failOn === 'none') return false;
  return report.findings.some((f) => rank(f.severity) <= rank(failOn));
}
