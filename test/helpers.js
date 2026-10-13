import { generateKeyPairSync } from 'node:crypto';
import { MockResolver, auditDomains } from '../src/index.js';

export const dkimKey = (bits) => generateKeyPairSync('rsa', { modulusLength: bits }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
export const NOW = '2026-10-13T12:00:00Z';

/** fetch mock: map of url -> { status, body } | Error */
export function mockFetch(routes = {}) {
  const calls = [];
  const f = async (url) => {
    calls.push(url);
    const r = routes[url];
    if (!r) throw Object.assign(new Error('fetch failed'), { cause: { code: 'ENOTFOUND' } });
    if (r instanceof Error) throw r;
    return { status: r.status ?? 200, text: async () => r.body ?? '' };
  };
  f.calls = calls;
  return f;
}

/** A well-configured domain. */
export function goodZone(domain = 'good.test', extra = {}) {
  return {
    [domain]: { MX: [{ exchange: `mx1.${domain}`, priority: 10 }], TXT: ['v=spf1 ip4:192.0.2.0/24 include:_spf.mail.test -all', 'google-site-verification=abc'], CAA: [{ critical: 0, tag: 'issue', value: 'letsencrypt.org' }, { critical: 0, tag: 'iodef', value: `mailto:sec@${domain}` }], DS: [{ keyTag: 1, algorithm: 13, digestType: 2, digest: 'aa' }], DNSKEY: [{ flags: 257, protocol: 3, algorithm: 13, key: 'AAAA' }], SOA: [{ nsname: `ns1.${domain}` }], NS: [`ns1.${domain}`], AD: true },
    [`mx1.${domain}`]: { A: ['192.0.2.10'] },
    [`ns1.${domain}`]: { A: ['192.0.2.53'] },
    '_spf.mail.test': { TXT: ['v=spf1 ip4:198.51.100.0/24 -all'] },
    [`_dmarc.${domain}`]: { TXT: [`v=DMARC1; p=reject; rua=mailto:d@${domain}`] },
    [`_mta-sts.${domain}`]: { TXT: ['v=STSv1; id=2026101301'] },
    [`_smtp._tls.${domain}`]: { TXT: [`v=TLSRPTv1; rua=mailto:tls@${domain}`] },
    [`www.${domain}`]: { A: ['192.0.2.80'] },
    ...extra,
  };
}
export const goodFetch = (domain = 'good.test') => ({ [`https://mta-sts.${domain}/.well-known/mta-sts.txt`]: { body: `version: STSv1\nmode: enforce\nmx: *.${domain}\nmax_age: 604800\n` } });

export async function run(zone, opts = {}, routes) {
  const resolver = new MockResolver(zone, { axfr: opts.axfrZones || {} });
  const r = await auditDomains(opts.domains || [Object.keys(zone)[0]], { resolver, fetch: mockFetch(routes ?? goodFetch(opts.domains?.[0] || Object.keys(zone)[0])), now: NOW, randomLabel: 'probe', ...opts });
  r.resolverLog = resolver.log;
  return r;
}
export const rules = (r) => r.findings.map((f) => f.rule).sort();
export const find = (r, rule, pred = () => true) => r.findings.find((f) => f.rule === rule && pred(f));
