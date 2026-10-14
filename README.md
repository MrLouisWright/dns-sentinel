# dns-sentinel

> Audit your domains' DNS and email security before attackers or spammers find the gaps.

`dns-sentinel` checks SPF, DMARC, DKIM, MX / null MX, MTA-STS, TLS-RPT, CAA and DNSSEC. It also finds dangling CNAMEs and subdomain takeovers, wildcard records and open zone transfers. Every finding comes with a severity and a **concrete fix**, usually the exact DNS record to publish.

CLI, library and GitHub Action. Node.js 18+, **zero runtime dependencies**. Lookups use `node:dns/promises` (system or chosen resolvers) by default. DNS-over-HTTPS is optional, and the DNSSEC check uses it by default to read the validating resolver's AD flag.

## Checks

| Area | Rules (default severity) |
|---|---|
| **SPF** | `spf-missing` (high; medium for non-mail domains), `spf-multiple` (high), `spf-too-many-lookups` (high; nested includes, `a`, `mx`, `exists`, `redirect` counted against the 10-lookup limit), `spf-void-lookups` (medium), `spf-pass-all` (critical, `+all`), `spf-neutral-all` (medium, `?all`), `spf-no-all` (medium), `spf-ptr` (medium, including via includes), `spf-invalid` (syntax errors, include targets without SPF, include loops, terms after `all`), `spf-softfail-all` (info) |
| **DMARC** | `dmarc-missing` (high), `dmarc-multiple` (high), `dmarc-invalid` (high), `dmarc-policy-none` (medium; high for non-mail domains), `dmarc-no-rua` (low), `dmarc-pct` (medium, pct < 100), `dmarc-weak-subdomain` (medium, `sp` weaker than `p`). Subdomains fall back to the organisational domain's record and its `sp` |
| **DKIM** | Selectors from `--dkim-selector`, plus ~30 common selectors with `--dkim-common`. `dkim-weak-key` (**critical** for RSA < 1024 bits, medium for < 2048), `dkim-revoked` (low, empty `p=`), `dkim-testing` (low, `t=y`), `dkim-missing` (medium), `dkim-invalid` (medium), `dkim-not-found` (low) |
| **MX** | `mx-missing` (recommends a null MX `MX 0 .` for domains that don't receive mail), `null-mx-misconfigured` (high), `null-mx-spf` (medium), `mx-dangling` (high), `mx-cname` (low), `mx-ip-literal` (medium) |
| **MTA-STS / TLS-RPT** | `mta-sts-missing` (low), `mta-sts-invalid` (medium: TXT id, policy fetch over HTTPS, policy syntax), `mta-sts-testing` (low), `mta-sts-mx-mismatch` (medium; high in enforce mode), `tlsrpt-missing` (low), `tlsrpt-invalid` (low) |
| **CAA** | Closest-ancestor lookup (RFC 8659). `caa-missing` (low), `caa-permissive` (low; no issue tags or > 3 CAs), `caa-critical-unknown` (high), `caa-no-iodef` (info) |
| **DNSSEC** | DS and DNSKEY presence plus the AD flag from a validating DoH resolver. `dnssec-disabled` (medium), `dnssec-no-ds` (medium), `dnssec-broken` (high: SERVFAIL, or DS without validation), `dnssec-weak-algorithm` (RSASHA1/DSA keys, SHA-1-only DS) |
| **Dangling CNAMEs** | For `--subdomain`, `--subdomains-file` or `--common-subdomains`: follows the CNAME chain and flags `dangling-cname` (high: target NXDOMAIN; medium: no addresses). `subdomain-takeover` (critical) when the target is a takeover-prone service and either doesn't exist or serves the service's "unclaimed" page (HTTP fingerprint). `takeover-prone-cname` (info) otherwise. Services include AWS S3 and Elastic Beanstalk, GitHub Pages, Heroku, Azure (App Service, Cloud Services, Traffic Manager, Blob, CDN, Front Door…), Shopify, Fastly, Pantheon, Tumblr, Ghost, Surge, Bitbucket, Netlify, Webflow, Zendesk, ReadMe, Unbounce, Help Scout, Strikingly, Fly.io, Agile CRM, Canny, Statuspage, WordPress.com and Google Cloud Storage |
| **Wildcards** | `wildcard-record` (low), plus takeover checks on wildcard CNAMEs |
| **Zone transfer** | `zone-transfer` (high). AXFR is attempted against every NS only with `--axfr` (off by default) |
| **Config** | `allow-expired` (medium) when an allowlist entry has passed its expiry date |

## Install and run

```bash
npx dns-sentinel example.com
npx dns-sentinel example.com example.org --dkim-selector google,s1 -s www -s docs -s status
npx dns-sentinel example.com --subdomains-file subdomains.txt --fail-on medium -f sarif > dns.sarif
npx dns-sentinel example.com --doh                        # all lookups over DNS-over-HTTPS (Cloudflare)
npx dns-sentinel example.com --resolver 9.9.9.9 --axfr    # pick a resolver; attempt zone transfers
npx dns-sentinel example.com --checks spf,dmarc,dkim --dkim-common
```

### Sample output

A live run against `louiswright.co.uk` (`--doh -s www -s mail --dkim-common --axfr`):

```text
dns-sentinel — 1 domain(s) · resolver: DoH https://cloudflare-dns.com/dns-query; DNSSEC: DoH https://cloudflare-dns.com/dns-query

louiswright.co.uk
  MX: 30 athena.hosts.co.uk, 30 hermes.hosts.co.uk
  SPF: v=spf1 include:stspg-customer.com include:spf.hosts.co.uk include:_spf.firebasemail.com ~all (7 lookups)
  DMARC: v=DMARC1; p=none;
  DKIM: no keys found
  MTA-STS: none
  TLS-RPT: none
  CAA: none
  DNSSEC: off
  Wildcard: CNAME s.multiscreensite.com
  www.louiswright.co.uk: CNAME → cname.vercel-dns.com
  mail.louiswright.co.uk: CNAME → s.multiscreensite.com → global.multiscreensite.com → a3c02b2530d6f27ca.awsglobalaccelerator.com
  AXFR ns1.phase8.net: refused or unreachable
  AXFR ns2.phase8.net: refused or unreachable
  AXFR ns0.phase8.net: refused or unreachable
  MEDIUM   DMARC policy is p=none: spoofed mail is reported but still delivered [dmarc-policy-none]
           ↳ fix: Once reports show your legitimate mail passes, move to `p=quarantine` and then `p=reject`.
  MEDIUM   DNSSEC is not enabled for louiswright.co.uk; answers can be spoofed by cache poisoning [dnssec-disabled]
           ↳ fix: Enable DNSSEC signing at your DNS provider and publish the DS record at your registrar.
  LOW      No CAA records for louiswright.co.uk (or its parents), so any certificate authority may issue for it [caa-missing]
           ↳ fix: Restrict issuance to your CAs, e.g. `louiswright.co.uk. CAA 0 issue "letsencrypt.org"` and `CAA 0 iodef "mailto:security@louiswright.co.uk"`.
  LOW      No DKIM key found on 31 common selectors [dkim-not-found]
           ↳ fix: Pass your real selector with --dkim-selector (find it in the s= tag of a DKIM-Signature header).
  LOW      DMARC has no rua= address, so you receive no aggregate reports [dmarc-no-rua]
           ↳ fix: Add `rua=mailto:dmarc-reports@louiswright.co.uk` (or a DMARC reporting service).
  LOW      louiswright.co.uk has no MTA-STS, so inbound SMTP TLS can be downgraded by an attacker [mta-sts-missing]
           ↳ fix: Publish `_mta-sts.louiswright.co.uk. TXT "v=STSv1; id=20260101"` and a policy at https://mta-sts.louiswright.co.uk/.well-known/mta-sts.txt (start with mode: testing).
  LOW      louiswright.co.uk has no TLS-RPT record, so you won't hear about SMTP TLS failures [tlsrpt-missing]
           ↳ fix: Publish `_smtp._tls.louiswright.co.uk. TXT "v=TLSRPTv1; rua=mailto:tls-reports@louiswright.co.uk"`.
  LOW      louiswright.co.uk has a wildcard record (CNAME s.multiscreensite.com): every possible subdomain resolves, which helps phishing and hides typos and dangling records [wildcard-record]
           ↳ fix: Remove the wildcard and create explicit records, unless you need it (e.g. multi-tenant hosting).
  INFO     SPF ends in "~all" (softfail). With an enforcing DMARC policy this is fine; otherwise -all is stronger [spf-softfail-all]
           ↳ fix: Consider `-all` once you are confident all senders are listed.

2 medium, 6 low, 1 info
✔ Passing (fail-on: high).
```

### Options

| Option | Description |
|---|---|
| `<domain…>` | One or more domains |
| `--checks <list>` / `--skip <list>` | Choose checks: `spf, dmarc, dkim, mx, mta-sts, tls-rpt, caa, dnssec, cname, wildcard, axfr` (default: all except `axfr`) |
| `--dkim-selector <s>` | DKIM selector(s) to test (repeatable or comma-separated) |
| `--dkim-common` | Also try ~30 common selectors (`google`, `selector1`, `k1`, `s1`, `default`, …) |
| `-s, --subdomain <name>` | Subdomain to check for dangling CNAMEs (`www` or `www.example.com`; repeatable) |
| `--subdomains-file <file>` | Subdomains, one per line (`-` for stdin) |
| `--common-subdomains` | Also check ~40 common names (`www`, `blog`, `docs`, `status`, `shop`, …) |
| `--axfr` | Attempt AXFR against each nameserver |
| `--no-http` | Skip HTTP: no MTA-STS policy fetch, no takeover fingerprints |
| `-r, --resolver <ip[:port]>` | DNS server(s) for `node:dns` (repeatable; default: system) |
| `--doh [url]` | Use DNS-over-HTTPS for every lookup (default `https://cloudflare-dns.com/dns-query`) |
| `--dnssec-doh <url>` / `--no-dnssec-doh` | DoH endpoint for the DNSSEC check, or check it with plain DNS to `--resolver` (AD bit) |
| `--timeout <ms>` | Per-lookup timeout (default 5000) |
| `-c, --config <file>` | JSON config (default `.dns-sentinel.json`) |
| `-f, --format` | `text` (default), `json`, `sarif`, `markdown` |
| `--json/--sarif/--markdown <file>` | Also write that format to a file |
| `--fail-on <sev>` | `critical`, `high` (default), `medium`, `low`, `info` or `none` |
| `--list-rules` | List rules, severities and groups |

**Exit codes:** `0` passed, `1` findings at or above `--fail-on`, `2` usage/config error or a domain could not be checked (NXDOMAIN, SERVFAIL, timeouts).

## Configuration

`.dns-sentinel.json`:

```json
{
  "domains": ["example.com", "example.org"],
  "dkimSelectors": ["google", "s1"],
  "subdomains": ["www", "docs", "status", "shop"],
  "failOn": "medium",
  "severity": { "caa-no-iodef": "off", "dnssec-disabled": "low" },
  "allow": [
    { "rule": "dmarc-policy-none", "domain": "example.org", "reason": "DMARC rollout, reviewing reports", "expires": "2026-12-31" },
    { "rule": "wildcard-record", "domain": "example.com", "reason": "Multi-tenant hosting" },
    { "rule": "takeover-prone-cname", "name": "docs.example.com", "reason": "GitHub Pages, owned by us" }
  ]
}
```

Allowlist entries match on `rule` (globs like `dnssec-*` allowed), and optionally `domain` and `name` (the DNS name the finding is about). Each needs a `reason`. After `expires` the entry stops applying, the finding comes back, and `allow-expired` is reported. Other keys: `checks`, `axfr`, `dkimCommon`, `commonSubdomains`, `servers`, `doh`, `dnssecDoh`, `timeout`, `http`, `caaMaxIssuers`.

## GitHub Action

```yaml
on:
  schedule: [{ cron: '0 6 * * 1' }]
permissions:
  contents: read
jobs:
  dns:
    runs-on: ubuntu-latest
    steps:
      - uses: MrLouisWright/dns-sentinel@<sha> # v1
        with:
          domains: example.com example.org
          subdomains: www docs status
          dkim-selectors: google,s1
          fail-on: medium
```

Inputs: `domains`, `subdomains`, `subdomains-file`, `dkim-selectors`, `checks`, `axfr`, `doh`, `fail-on`, `config`, `sarif`, `json`, `job-summary`, `args`.

## Library

```js
import { auditDomains, formatText, MockResolver } from 'dns-sentinel';

const report = await auditDomains(['example.com'], { dkimSelectors: ['google'], subdomains: ['www'], doh: true });
console.log(formatText(report, { failOn: 'high' }));

// Offline / tests: pass any resolver with query(name, type)
const resolver = new MockResolver({ 'example.com': { TXT: ['v=spf1 +all'], MX: [] } });
await auditDomains(['example.com'], { resolver, http: false });
```

`SystemResolver` (node:dns), `WireResolver` (UDP/TCP with DNSSEC bits), `DohResolver` (RFC 8484) and `MockResolver` are exported, as is the wire codec (`encodeQuery`, `decodeMessage`).

## Rules reference

```text
spf-missing              high      spf       No SPF record
spf-multiple             high      spf       Multiple SPF records (permerror)
spf-too-many-lookups     high      spf       SPF needs more than 10 DNS lookups (permerror)
spf-void-lookups         medium    spf       SPF has more than 2 void lookups
spf-pass-all             critical  spf       SPF +all lets anyone send as the domain
spf-neutral-all          medium    spf       SPF ?all (neutral) gives no protection
spf-no-all               medium    spf       SPF has no all mechanism or redirect
spf-softfail-all         info      spf       SPF ends in ~all (softfail)
spf-ptr                  medium    spf       SPF uses the deprecated ptr mechanism
spf-invalid              high      spf       SPF syntax error or broken include
dmarc-missing            high      dmarc     No DMARC record
dmarc-multiple           high      dmarc     Multiple DMARC records
dmarc-invalid            high      dmarc     Invalid DMARC record
dmarc-policy-none        medium    dmarc     DMARC p=none (monitoring only)
dmarc-no-rua             low       dmarc     DMARC without aggregate reports (rua)
dmarc-pct                medium    dmarc     DMARC pct below 100
dmarc-weak-subdomain     medium    dmarc     DMARC subdomain policy weaker than the domain policy
dkim-missing             medium    dkim      DKIM selector has no key
dkim-weak-key            medium    dkim      Weak DKIM key
dkim-revoked             low       dkim      Revoked DKIM key (empty p=)
dkim-testing             low       dkim      DKIM key in testing mode (t=y)
dkim-invalid             medium    dkim      Unparseable DKIM record
dkim-not-found           low       dkim      No DKIM key found on any checked selector
mx-missing               low       mx        No MX and no null MX
null-mx-misconfigured    high      mx        Null MX mixed with other MX records
null-mx-spf              medium    mx        Null MX but SPF authorises senders
mx-dangling              high      mx        MX host does not resolve
mx-cname                 low       mx        MX points to a CNAME
mx-ip-literal            medium    mx        MX is an IP address
mta-sts-missing          low       mta-sts   No MTA-STS
mta-sts-invalid          medium    mta-sts   Broken MTA-STS record or policy
mta-sts-testing          low       mta-sts   MTA-STS not enforcing
mta-sts-mx-mismatch      medium    mta-sts   MX host not covered by the MTA-STS policy
tlsrpt-missing           low       tls-rpt   No TLS-RPT record
tlsrpt-invalid           low       tls-rpt   Invalid TLS-RPT record
caa-missing              low       caa       No CAA records
caa-permissive           low       caa       Overly permissive CAA
caa-critical-unknown     high      caa       CAA critical flag on an unknown tag (blocks issuance)
caa-no-iodef             info      caa       CAA without iodef reporting
dnssec-disabled          medium    dnssec    DNSSEC not enabled
dnssec-no-ds             medium    dnssec    Zone signed but no DS at the parent
dnssec-broken            high      dnssec    DNSSEC validation fails
dnssec-weak-algorithm    medium    dnssec    Weak DNSSEC algorithm or digest
dangling-cname           high      cname     CNAME points to a name that does not exist
subdomain-takeover       critical  cname     Subdomain takeover possible
takeover-prone-cname     info      cname     CNAME to a takeover-prone service
wildcard-record          low       wildcard  Wildcard DNS record
zone-transfer            high      axfr      Zone transfer (AXFR) allowed
allow-expired            medium    config    Allowlist entry has expired
```

## Support

If this project is useful to you, you can support its development with a donation: [Buy me a coffee](https://donate.stripe.com/aFa00lek3cvX4Ds2Fk9EI0b). It helps keep these tools maintained, documented and free for everyone.

## License

MIT © Louis Wright ([Louis Wright](https://github.com/MrLouisWright))
