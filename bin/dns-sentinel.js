#!/usr/bin/env node
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { auditDomains, exceeds, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, RULES, CHECKS, ConfigError } from '../src/index.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const HELP = `dns-sentinel ${pkg.version} — DNS and email security auditor

Usage: dns-sentinel <domain...> [options]

Checks (default: all except axfr)
      --checks <list>        Comma-separated: ${CHECKS.join(', ')}
      --skip <list>          Checks to skip
      --dkim-selector <s>    DKIM selector to test (repeatable or comma-separated)
      --dkim-common          Also try ~30 common DKIM selectors
  -s, --subdomain <name>     Subdomain to test for dangling/takeover CNAMEs (repeatable; "www" or "www.example.com")
      --subdomains-file <f>  File with subdomains, one per line
      --common-subdomains    Also test ~40 common subdomain names
      --axfr                 Attempt a zone transfer against each nameserver (off by default)
      --no-http              Do not fetch MTA-STS policies or takeover fingerprints over HTTP
Resolver
  -r, --resolver <ip[:port]> DNS server(s) for node:dns (repeatable; default: system resolvers)
      --doh [url]            Use DNS-over-HTTPS for all lookups (default https://cloudflare-dns.com/dns-query)
      --dnssec-doh <url>     DoH endpoint for the DNSSEC/AD check (default Cloudflare)
      --no-dnssec-doh        Check DNSSEC with plain DNS to --resolver instead of DoH
      --timeout <ms>         Per-lookup timeout (default 5000)
Policy and output
  -c, --config <file>        JSON config (default .dns-sentinel.json if present)
  -f, --format <fmt>         text (default) | json | sarif | markdown
      --json/--sarif/--markdown <file>  Also write that format to a file
      --fail-on <sev>        critical | high (default) | medium | low | info | none
      --list-rules           Print rules and default severities
      --no-color
  -v, --version / -h, --help

Exit codes: 0 = passed, 1 = findings at or above --fail-on, 2 = usage error or a domain could not be checked.`;

const list = (v) => (v || []).flatMap((x) => String(x).split(',')).map((x) => x.trim()).filter(Boolean);
function usage(msg) { process.stderr.write(`dns-sentinel: ${msg}\nRun with --help for usage.\n`); return 2; }

async function main() {
  const argv = process.argv.slice(2);
  // allow bare --doh (no value)
  const di = argv.indexOf('--doh');
  if (di !== -1 && (argv[di + 1] === undefined || argv[di + 1].startsWith('-') || !/^https?:\/\//.test(argv[di + 1]))) argv.splice(di, 1, '--doh=default');
  let a;
  try {
    a = parseArgs({ args: argv, allowPositionals: true, options: {
      checks: { type: 'string' }, skip: { type: 'string' }, 'dkim-selector': { type: 'string', multiple: true }, 'dkim-common': { type: 'boolean' },
      subdomain: { type: 'string', short: 's', multiple: true }, 'subdomains-file': { type: 'string' }, 'common-subdomains': { type: 'boolean' },
      axfr: { type: 'boolean' }, 'no-http': { type: 'boolean' },
      resolver: { type: 'string', short: 'r', multiple: true }, doh: { type: 'string' }, 'dnssec-doh': { type: 'string' }, 'no-dnssec-doh': { type: 'boolean' }, timeout: { type: 'string' },
      config: { type: 'string', short: 'c' }, format: { type: 'string', short: 'f' }, json: { type: 'string' }, sarif: { type: 'string' }, markdown: { type: 'string' },
      'fail-on': { type: 'string' }, 'list-rules': { type: 'boolean' }, 'no-color': { type: 'boolean' }, version: { type: 'boolean', short: 'v' }, help: { type: 'boolean', short: 'h' },
    } });
  } catch (e) { return usage(e.message); }
  const { values: o, positionals } = a;
  if (o.help) { process.stdout.write(HELP + '\n'); return 0; }
  if (o.version) { process.stdout.write(pkg.version + '\n'); return 0; }
  if (o['list-rules']) { for (const [id, r] of Object.entries(RULES)) process.stdout.write(`${id.padEnd(24)} ${r.severity.padEnd(9)} ${r.group.padEnd(9)} ${r.title}\n`); return 0; }

  let cfg = {};
  const cfgPath = o.config || (existsSync('.dns-sentinel.json') ? '.dns-sentinel.json' : null);
  if (cfgPath) { try { cfg = JSON.parse(readFileSync(cfgPath, 'utf8')); } catch (e) { return usage(`Cannot read config ${cfgPath}: ${e.message}`); } }
  const domains = [...positionals, ...(cfg.domains || [])];
  if (!domains.length) return usage('No domain given');
  for (const d of domains) if (!/^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}\.?$/i.test(String(d).replace(/^https?:\/\//, '').replace(/\/.*$/, ''))) return usage(`Invalid domain: ${d}`);

  const opts = { ...cfg };
  let checks = o.checks ? list([o.checks]) : cfg.checks ? [...cfg.checks] : null;
  if (o.axfr || cfg.axfr) { checks ??= CHECKS.filter((c) => c !== 'axfr'); if (!checks.includes('axfr')) checks.push('axfr'); }
  if (o.skip) { checks ??= CHECKS.filter((c) => c !== 'axfr'); checks = checks.filter((c) => !list([o.skip]).includes(c)); }
  if (checks) opts.checks = checks;
  opts.dkimSelectors = [...(cfg.dkimSelectors || []), ...list(o['dkim-selector'])];
  if (o['dkim-common']) opts.dkimCommon = true;
  opts.subdomains = [...(cfg.subdomains || []), ...list(o.subdomain)];
  if (o['subdomains-file']) {
    try { opts.subdomains.push(...readFileSync(o['subdomains-file'] === '-' ? 0 : o['subdomains-file'], 'utf8').split(/\r?\n/).map((x) => x.trim()).filter((x) => x && !x.startsWith('#'))); } catch (e) { return usage(`Cannot read ${o['subdomains-file']}: ${e.message}`); }
  }
  if (o['common-subdomains']) opts.commonSubdomains = true;
  if (o['no-http']) opts.http = false;
  if (o.resolver) opts.servers = list(o.resolver);
  if (o.doh) opts.doh = o.doh === 'default' ? true : o.doh;
  if (o['dnssec-doh']) opts.dnssecDoh = o['dnssec-doh'];
  if (o['no-dnssec-doh']) opts.dnssecDoh = false;
  if (o.timeout) opts.timeout = Number(o.timeout);
  const failOn = o['fail-on'] || cfg.failOn || 'high';
  if (failOn !== 'none' && !SEVERITIES.includes(failOn)) return usage(`Invalid --fail-on: ${failOn}`);
  const format = o.format || 'text';
  if (!['text', 'json', 'sarif', 'markdown'].includes(format)) return usage(`Invalid --format: ${format}`);

  let report;
  try { report = await auditDomains(domains, opts); } catch (e) { return usage(e instanceof ConfigError ? `Config error: ${e.message}` : e.message); }
  const color = !o['no-color'] && process.stdout.isTTY && !process.env.NO_COLOR;
  const out = { text: () => formatText(report, { color, failOn }), json: () => formatJson(report), sarif: () => formatSarif(report, { version: pkg.version }), markdown: () => formatMarkdown(report, { failOn }) };
  process.stdout.write(out[format]());
  if (o.json) writeFileSync(o.json, formatJson(report));
  if (o.sarif) writeFileSync(o.sarif, formatSarif(report, { version: pkg.version }));
  if (o.markdown) writeFileSync(o.markdown, formatMarkdown(report, { failOn }));
  if (report.domains.some((d) => d.fatal)) return 2;
  return exceeds(report, failOn) ? 1 : 0;
}

main().then((c) => { process.exitCode = c; }, (e) => { process.stderr.write(`dns-sentinel: ${e.stack || e}\n`); process.exitCode = 2; });
