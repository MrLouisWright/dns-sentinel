export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Check = 'spf' | 'dmarc' | 'dkim' | 'mx' | 'mta-sts' | 'tls-rpt' | 'caa' | 'dnssec' | 'cname' | 'wildcard' | 'axfr';
export type Status = 'NOERROR' | 'NODATA' | 'NXDOMAIN' | 'SERVFAIL' | 'REFUSED' | 'TIMEOUT' | 'ERROR';
export interface QueryResult { status: Status; answers: any[]; records: any[]; ad?: boolean; cnames?: string[]; error?: string }
export interface DnsResolver { kind: string; query(name: string, type: string): Promise<QueryResult>; axfr?(zone: string, ns?: string): Promise<any[] | null> }

export interface AllowEntry { rule: string; domain?: string; name?: string; reason: string; expires?: string }
export interface Options {
  checks?: Check[]; axfr?: boolean; dkimSelectors?: string[]; dkimCommon?: boolean;
  subdomains?: string[]; commonSubdomains?: boolean; http?: boolean; timeout?: number;
  resolver?: DnsResolver; dnssecResolver?: DnsResolver; servers?: string[]; doh?: boolean | string; dnssecDoh?: boolean | string;
  fetch?: typeof fetch; severity?: Record<string, Severity | 'off'>; allow?: AllowEntry[]; caaMaxIssuers?: number; now?: string | number; randomLabel?: string;
}
export interface Finding { rule: string; severity: Severity; domain: string; name: string; message: string; fix: string; record?: string }
export interface DomainResult { domain: string; fatal?: boolean; summary: Record<string, any>; findings: Finding[]; errors: string[] }
export interface Report {
  tool: 'dns-sentinel'; generatedAt: string; resolver: string; dnssecResolver: string; checks: Check[];
  domains: DomainResult[]; findings: Finding[]; suppressed: Array<Finding & { allowedBy: { reason: string; expires?: string } }>;
  counts: Record<Severity, number>; errors: Array<{ domain: string; error: string }>;
}

export class ConfigError extends Error {}
export const RULES: Record<string, { severity: Severity; title: string; group: string }>;
export const SEVERITIES: Severity[];
export const CHECKS: Check[];
export const DEFAULT_CHECKS: Check[];
export const COMMON_SELECTORS: string[];
export const COMMON_SUBDOMAINS: string[];
export const SERVICES: Array<{ name: string; re: RegExp; fingerprints: string[]; nxdomain?: boolean }>;
export function auditDomains(domains: string[], opts?: Options): Promise<Report>;
export function exceeds(report: Report, failOn?: Severity | 'none'): boolean;
export function validateConfig(cfg: Options): Options;
export function makeResolvers(opts?: Options): { resolver: DnsResolver; dnssecResolver: DnsResolver };
export class SystemResolver implements DnsResolver { constructor(servers?: string[], opts?: { timeout?: number; tries?: number }); kind: string; servers: string[]; query(name: string, type: string): Promise<QueryResult> }
export class WireResolver implements DnsResolver { constructor(servers: string[], opts?: { timeout?: number }); kind: string; query(name: string, type: string): Promise<QueryResult> }
export class DohResolver implements DnsResolver { constructor(url?: string, opts?: { timeout?: number; fetchImpl?: typeof fetch }); kind: string; url: string; query(name: string, type: string): Promise<QueryResult> }
export class MockResolver implements DnsResolver { constructor(zone?: Record<string, any>, opts?: { axfr?: Record<string, any[]> }); kind: string; log: string[]; query(name: string, type: string): Promise<QueryResult>; axfr(zone: string): Promise<any[] | null> }
export function attemptAxfr(server: string, zone: string, opts?: { timeout?: number; port?: number }): Promise<any[] | null>;
export function encodeQuery(name: string, type: string | number, opts?: { id?: number; dnssec?: boolean; rd?: boolean; edns?: boolean }): Buffer;
export function decodeMessage(buf: Buffer): any;
export function encodeResponse(query: Buffer, opts?: { rcode?: number | string; ad?: boolean; aa?: boolean; answers?: any[]; authority?: any[] }): Buffer;
export function parseSpf(record: string): { mechanisms: Array<{ qualifier: string; name: string; value: string | null; raw: string }>; modifiers: Record<string, string>; errors: string[] };
export function parseStsPolicy(text: string): Record<string, any>;
export function dkimKeyBits(p: string, k?: string): { type: string; bits: number } | null;
export function orgDomain(domain: string): string;
export function matchService(host: string): { name: string; re: RegExp; fingerprints: string[]; nxdomain?: boolean } | null;
export function formatText(r: Report, o?: { color?: boolean; failOn?: string }): string;
export function formatJson(r: Report): string;
export function formatSarif(r: Report, o?: { version?: string }): string;
export function formatMarkdown(r: Report, o?: { failOn?: string }): string;
