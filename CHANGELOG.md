# Changelog

## 1.0.0 (2026-10-15)

### Added before first publish

- BIMI check (`bimi`, on by default): `default._bimi` record syntax, an https SVG logo, the VMC/CMC certificate (`a=`), and DMARC enforcement at pct=100 (`bimi-invalid`, `bimi-no-certificate`, `bimi-dmarc-not-enforced`). Domains without BIMI are not flagged.
- DKIM selectors per provider: Google Workspace, Microsoft 365, Zoho, Fastmail, Proton, iCloud, Amazon SES, Mailchimp/Mandrill, SendGrid, Mailgun, Postmark, Brevo, Mailjet, HubSpot, Salesforce and Zendesk are detected from MX and SPF. `--dkim-providers` tries only their selectors, and `--dkim-common` now includes them as well.
- ARC: `checkArcHeaders(rawHeaders)` validates an ARC set offline (instances, all three headers, `cv=` chain, `s=`/`d=`/`b=`). ARC has no DNS record of its own, so this is a library helper.
- Change tracking: `--save-baseline <file>` writes a snapshot, and `--baseline <file>` reports `record-changed` (SPF, DMARC, MX, MTA-STS, TLS-RPT, CAA, DKIM, BIMI) and `spf-lookups-increased` when a provider's include grows. New `spf-lookups-near-limit` at 8–10 lookups.
- DMARC aggregate (RUA) reports: `dns-sentinel dmarc-report <file.xml|.xml.gz|.zip…>` and `parseDmarcReport()` / `summarizeDmarcReports()` give the pass rate and sources failing DMARC.
- Scope unchanged: no HSTS (header-sentinel) and no TLS handshake checks (tls-sentinel).

### Packaging

- Dual ESM + CommonJS: `import` loads `src/`, `require` loads a bundled `dist/index.cjs`, via package.json `exports`.
- TypeScript declarations are generated from the source (`dist/types`) instead of hand-written.
- CI runs build, tests and a require+import check on Node 18/20/22; releases use `npm publish --provenance`.

First release, by Louis Wright.

- SPF: missing/multiple records, recursive 10-lookup limit, void lookups, `+all`/`?all`/`~all`/no `all`, `ptr` (including via includes), syntax errors, broken includes and include loops.
- DMARC: missing/multiple/invalid, `p=none`, missing `rua`, `pct` below 100, weak `sp`, and fallback to the organisational domain.
- DKIM: chosen selectors, plus common selectors if you opt in. Flags weak RSA keys (critical < 1024, medium < 2048), revoked and testing keys, unparseable records.
- MX sanity, null MX (RFC 7505) recommendations and consistency, MTA-STS record + policy (mode, max_age, MX coverage), TLS-RPT.
- CAA with tree climbing: missing, permissive, unknown critical tags, no iodef.
- DNSSEC via DoH and the AD flag: disabled, signed without DS, broken validation, weak algorithms/digests.
- Dangling CNAMEs and subdomain takeover for ~25 services with HTTP fingerprints; wildcard records; opt-in AXFR.
- Resolvers: node:dns/promises (system or `--resolver`), DNS-over-HTTPS (`--doh`), raw UDP/TCP wire client, and a mock resolver for testing.
- Multiple domains, config allowlist with reason and expiry, per-rule severity, text/JSON/SARIF/Markdown, `--fail-on`, exit codes 0/1/2, composite GitHub Action.
