# Changelog

## 1.0.0 (2026-10-13)

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
