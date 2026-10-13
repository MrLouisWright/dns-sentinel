// Small helpers: organisational domain (mini public-suffix list), tag parsing.
const MULTI_SUFFIXES = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'ltd.uk', 'plc.uk', 'me.uk', 'net.uk', 'sch.uk', 'nhs.uk', 'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'co.nz', 'org.nz', 'net.nz', 'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'com.br', 'net.br', 'org.br', 'co.in', 'net.in', 'org.in', 'co.za', 'org.za', 'com.cn', 'net.cn', 'org.cn', 'com.mx', 'com.ar', 'com.tr', 'co.kr', 'or.kr', 'com.sg', 'com.hk', 'co.il', 'com.my', 'co.id', 'com.ph', 'com.tw', 'com.ua', 'co.th', 'com.vn', 'com.pl', 'eu.com', 'uk.com', 'us.com', 'github.io', 'herokuapp.com', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev', 'blogspot.com', 'azurewebsites.net', 'cloudfront.net', 'appspot.com', 'firebaseapp.com', 'web.app', 'fly.dev']);

export function normalise(d) { return String(d).trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/\.$/, ''); }

export function orgDomain(domain) {
  const l = normalise(domain).split('.');
  for (let i = 0; i < l.length - 1; i++) if (MULTI_SUFFIXES.has(l.slice(i + 1).join('.'))) return l.slice(i).join('.');
  return l.slice(-2).join('.');
}

/** Parse "k=v; k2=v2" tag lists (DMARC, DKIM, TLS-RPT, MTA-STS TXT). */
export function parseTags(txt) {
  const tags = {}; const dupes = [];
  for (const part of String(txt).split(';')) {
    const i = part.indexOf('=');
    if (i === -1) { if (part.trim()) tags[part.trim().toLowerCase()] ??= ''; continue; }
    const k = part.slice(0, i).trim().toLowerCase(); const v = part.slice(i + 1).trim();
    if (!k) continue;
    if (k in tags) dupes.push(k);
    tags[k] = v;
  }
  return { tags, dupes };
}

export function globRe(p) { return new RegExp('^' + String(p).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i'); }

export function withTimeout(promise, ms, msg = 'timeout') {
  let t; return Promise.race([promise, new Promise((_, rej) => { t = setTimeout(() => rej(new Error(msg)), ms); })]).finally(() => clearTimeout(t));
}
