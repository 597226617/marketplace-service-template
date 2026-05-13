/**
 * Domain Intelligence API — WHOIS, DNS, and Domain Metadata
 * ──────────────────────────────────────────────────────
 * Endpoints:
 *   GET /api/whois       — Full WHOIS lookup for any domain
 *   GET /api/dns         — DNS record lookup (A, MX, NS, TXT, CNAME, SOA)
 *   GET /api/reverse      — Reverse IP lookup (domains sharing same IP)
 *   GET /api/batch        — Batch WHOIS for up to 10 domains
 */

import { Hono } from 'hono';
import { extractPayment, verifyPayment, build402Response } from './payment';

// ─── RE-EXPORT ENV TYPE FOR SERVICE ROUTER ──────────
type Env = {
  SERVICE_NAME?: string;
  WALLET_ADDRESS: string;
  WALLET_ADDRESS_BASE?: string;
  RATE_LIMIT?: string;
  SOLANA_RPC_URL?: string;
  BASE_RPC_URL?: string;
};

export const serviceRouter = new Hono<{ Bindings: Env }>();

// ─── CONFIG ─────────────────────────────────────────

const WHOIS_PRICE_USDC = 0.005;
const WHOIS_DESCRIPTION =
  'Domain WHOIS lookup: registrar, dates, nameservers, status codes, registrant (when available). Runs on Cloudflare edge network.';

const DNS_PRICE_USDC = 0.003;
const DNS_DESCRIPTION =
  'DNS record lookup: query A, MX, NS, TXT, CNAME, SOA records for any domain. Returns clean structured JSON.';

const REVERSE_PRICE_USDC = 0.005;
const REVERSE_DESCRIPTION =
  'Reverse IP lookup: discover all domains hosted on the same IP address.';

const BATCH_PRICE_USDC = 0.02;
const BATCH_DESCRIPTION =
  'Batch WHOIS lookup for up to 10 domains at once.';

// ─── RATE LIMIT ─────────────────────────────────────

const proxyRateLimits = new Map<string, { count: number; resetAt: number }>();
const PROXY_RATE_LIMIT = 20;

function checkProxyRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = proxyRateLimits.get(ip);
  if (!entry || now > entry.resetAt) {
    proxyRateLimits.set(ip, { count: 1, resetAt: now + 60_000 });
    return true;
  }
  entry.count++;
  return entry.count <= PROXY_RATE_LIMIT;
}

// ─── HELPERS ────────────────────────────────────────

const MAX_DOMAIN_LENGTH = 253;
const MAX_BATCH_SIZE = 10;
const MAX_TEXT_LENGTH = 10000;

function sanitizeDomain(raw: string): string | null {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim().toLowerCase();
  if (!trimmed || trimmed.length > MAX_DOMAIN_LENGTH) return null;
  const cleaned = trimmed.replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/.*$/, '');
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(cleaned)) {
    return null;
  }
  return cleaned;
}

function sanitizeText(value: unknown, maxLen: number): string {
  if (typeof value !== 'string') return '';
  return value.replace(/[\r\n\0]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, maxLen);
}

const VALID_DNS_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA'] as const;
type DnsRecordType = (typeof VALID_DNS_TYPES)[number];

function isValidDnsType(type: string): type is DnsRecordType {
  return (VALID_DNS_TYPES as readonly string[]).includes(type.toUpperCase());
}

function sanitizeIp(raw: string): string | null {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(trimmed)) {
    const parts = trimmed.split('.').map(Number);
    if (parts.every(p => p >= 0 && p <= 255)) return trimmed;
  }
  return null;
}

// ─── WHOIS PARSER ───────────────────────────────────

interface WhoisRecord {
  domain: string;
  registrar: string | null;
  creationDate: string | null;
  expirationDate: string | null;
  updatedDate: string | null;
  nameServers: string[];
  status: string[];
  registrant: {
    name: string | null;
    organization: string | null;
    email: string | null;
    country: string | null;
  };
  dnssec: boolean | null;
  rawText: string;
}

function parseWhoisRaw(text: string, domain: string): WhoisRecord {
  const record: WhoisRecord = {
    domain,
    registrar: null,
    creationDate: null,
    expirationDate: null,
    updatedDate: null,
    nameServers: [],
    status: [],
    registrant: { name: null, organization: null, email: null, country: null },
    dnssec: null,
    rawText: sanitizeText(text, MAX_TEXT_LENGTH),
  };

  const lines = text.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('%') || trimmed.startsWith('#') || trimmed.startsWith('//')) continue;

    const colonIdx = trimmed.indexOf(':');
    if (colonIdx === -1) continue;

    const key = trimmed.slice(0, colonIdx).trim().toLowerCase();
    const value = trimmed.slice(colonIdx + 1).trim();
    if (!value) continue;

    if (key.includes('registrar') && key !== 'registrar abuse contact email' && key !== 'registrar abuse contact phone' && !key.includes('url') && !key.includes('whois') && key !== 'registrar id' && key !== 'registrar iana id') {
      if (!record.registrar) record.registrar = value;
    }

    if ((key === 'creation date' || key === 'created' || key === 'created on' || key === 'registered on' || key === 'registration time' || key === 'domain registration date' || key === 'record created on' || key === 'created date' || key === 'domain date created' || key === 'registration-date') && !record.creationDate) {
      record.creationDate = value;
    }

    if ((key === 'registry expiry date' || key === 'expiration date' || key === 'expires on' || key === 'paid-till' || key === 'expiry date' || key === 'expires' || key === 'domain expiration date' || key === 'record expires on' || key === 'expiration-time' || key === 'expiry') && !record.expirationDate) {
      record.expirationDate = value;
    }

    if ((key === 'updated date' || key === 'last updated' || key === 'modified' || key === 'changed' || key === 'last modified on' || key === 'domain date updated' || key === 'updated' || key === 'last-modified' || key === 'up-date') && !record.updatedDate) {
      record.updatedDate = value;
    }

    if ((key === 'name server' || key === 'nserver' || key === 'nameserver' || key === 'dns')) {
      const ns = value.replace(/\.$/, '').toLowerCase();
      if (ns && !record.nameServers.includes(ns)) {
        record.nameServers.push(ns);
      }
    }

    if (key === 'status' || key === 'domain status' || key === 'statuses') {
      const statuses = value.split(/[,\s]+/).filter(Boolean);
      for (const s of statuses) {
        const clean = s.replace(/["']/g, '').trim();
        if (clean && !record.status.includes(clean)) {
          record.status.push(clean);
        }
      }
    }

    if (key.startsWith('registrant')) {
      if ((key === 'registrant name' || key === 'registrant' || key === 'registrant fullname') && !record.registrant.name) {
        record.registrant.name = value;
      }
      if ((key === 'registrant organization' || key === 'registrant org' || key === 'registrant organisation') && !record.registrant.organization) {
        record.registrant.organization = value;
      }
      if ((key === 'registrant email' || key === 'registrant e-mail') && !record.registrant.email) {
        record.registrant.email = value;
      }
      if ((key === 'registrant country' || key === 'registrantcountry') && !record.registrant.country) {
        record.registrant.country = value;
      }
    }
  }

  if (!record.registrant.email) {
    const emailMatch = text.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/);
    if (emailMatch) {
      record.registrant.email = emailMatch[0];
    }
  }

  if (text.toLowerCase().includes('dnssec: unsigned') || text.toLowerCase().includes('dnssec unsigned')) {
    record.dnssec = false;
  } else if (text.toLowerCase().includes('dnssec: signed') || text.toLowerCase().includes('dnssec signed')) {
    record.dnssec = true;
  }

  return record;
}

// ─── UPSTREAM FETCH (direct, no proxy on Workers) ──

async function fetchWithTimeout(url: string, options: RequestInit = {}, timeoutMs = 15_000): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    return resp;
  } finally {
    clearTimeout(timeout);
  }
}

async function readBodyWithLimit(response: Response, maxBytes: number): Promise<string> {
  const body = await response.arrayBuffer();
  if (body.byteLength > maxBytes) {
    throw new Error(`Upstream payload too large: ${body.byteLength} bytes`);
  }
  return new TextDecoder().decode(body);
}

async function fetchWhoisFromApi(domain: string): Promise<string> {
  const urls = [
    `https://whoisjson.com/api/v1/whois?domain=${encodeURIComponent(domain)}`,
    `https://whois-api.whoisxmlapi.com/api/v1?domainName=${encodeURIComponent(domain)}&outputFormat=JSON`,
  ];

  for (const url of urls) {
    try {
      const resp = await fetchWithTimeout(url, {
        headers: { Accept: 'application/json' },
      }, 15_000);
      if (resp.ok) {
        const json: any = await resp.json();
        if (json.rawText || json.raw_text) {
          return json.rawText || json.raw_text;
        }
        return jsonToWhoisText(json);
      }
    } catch {
      continue;
    }
  }

  throw new Error('All WHOIS lookup methods failed');
}

function jsonToWhoisText(json: any): string {
  const lines: string[] = [];

  if (json.registrar) lines.push(`Registrar: ${json.registrar}`);
  if (json.creationDate) lines.push(`Creation Date: ${json.creationDate}`);
  if (json.expirationDate) lines.push(`Expiration Date: ${json.expirationDate}`);
  if (json.updatedDate) lines.push(`Updated Date: ${json.updatedDate}`);

  if (json.nameServers) {
    const ns = Array.isArray(json.nameServers) ? json.nameServers : (json.nameServers.hosts || []);
    for (const n of ns) lines.push(`Name Server: ${typeof n === 'string' ? n : n.host || n.name || ''}`);
  }

  if (json.status) {
    const statuses = Array.isArray(json.status) ? json.status : [json.status];
    for (const s of statuses) lines.push(`Status: ${typeof s === 'string' ? s : s.status || ''}`);
  }

  if (json.registrant) {
    if (json.registrant.name) lines.push(`Registrant Name: ${json.registrant.name}`);
    if (json.registrant.organization) lines.push(`Registrant Organization: ${json.registrant.organization}`);
    if (json.registrant.email) lines.push(`Registrant Email: ${json.registrant.email}`);
    if (json.registrant.country) lines.push(`Registrant Country: ${json.registrant.country}`);
  }

  return lines.join('\n');
}

// ─── DNS LOOKUP ─────────────────────────────────────

interface DnsRecord {
  type: string;
  name: string;
  value: string;
  ttl: number | null;
}

async function fetchDnsRecords(domain: string, recordType: DnsRecordType): Promise<DnsRecord[]> {
  const dohUrls = [
    `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${recordType}`,
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${recordType}`,
  ];

  for (const url of dohUrls) {
    try {
      const resp = await fetchWithTimeout(url, {
        headers: { Accept: 'application/dns-json' },
      }, 10_000);

      if (!resp.ok) continue;

      const json: any = await resp.json();
      if (json.Status !== 0) continue;

      const answers: DnsRecord[] = (json.Answer || []).map((a: any) => ({
        type: recordType,
        name: a.name || domain,
        value: a.data || '',
        ttl: a.TTL || null,
      }));

      if (answers.length > 0) return answers;
    } catch {
      continue;
    }
  }

  return [];
}

// ─── REVERSE IP LOOKUP ──────────────────────────────

interface ReverseIpResult {
  ip: string;
  domains: string[];
  totalCount: number;
}

async function fetchReverseIp(ip: string): Promise<ReverseIpResult> {
  const apis = [
    { url: `https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(ip)}`, parse: parseHackerTarget },
    { url: `https://rapiddns.io/sameip/${encodeURIComponent(ip)}?full=1`, parse: parseRapidDns },
  ];

  for (const api of apis) {
    try {
      const resp = await fetchWithTimeout(api.url, {
        headers: { Accept: 'text/html,text/plain' },
      }, 15_000);

      if (!resp.ok) continue;

      const text = await readBodyWithLimit(resp, 500_000);
      const result = api.parse(text, ip);
      if (result.domains.length > 0) return result;
    } catch {
      continue;
    }
  }

  return { ip, domains: [], totalCount: 0 };
}

function parseHackerTarget(text: string, ip: string): ReverseIpResult {
  const domains = text
    .split('\n')
    .map(line => line.trim().toLowerCase())
    .filter(line => line && !line.includes('error') && !line.includes('API count exceeded') && /^[a-z0-9]/.test(line));

  return { ip, domains, totalCount: domains.length };
}

function parseRapidDns(text: string, ip: string): ReverseIpResult {
  const domains: string[] = [];
  const pattern = /<td[^>]*>([a-z0-9][a-z0-9.-]*\.[a-z]{2,})<\/td>/gi;
  let match;
  while ((match = pattern.exec(text)) !== null) {
    const d = match[1].toLowerCase();
    if (!domains.includes(d)) domains.push(d);
  }
  return { ip, domains, totalCount: domains.length };
}

// ─── ENDPOINTS ──────────────────────────────────────

// GET /api/whois?domain=example.com
serviceRouter.get('/whois', async (c) => {
  const walletAddress = c.env.WALLET_ADDRESS;
  const walletBase = c.env.WALLET_ADDRESS_BASE || walletAddress;
  const solanaRpc = c.env.SOLANA_RPC_URL;
  const baseRpc = c.env.BASE_RPC_URL;

  const payment = extractPayment(c);
  if (!payment) {
    return c.json(
      build402Response('/api/whois', WHOIS_DESCRIPTION, WHOIS_PRICE_USDC, walletAddress, walletBase, {
        input: { domain: 'string — Domain name (required)' },
        output: {
          domain: 'string',
          registrar: 'string | null',
          creationDate: 'string | null',
          expirationDate: 'string | null',
          nameServers: 'string[]',
          status: 'string[]',
          registrant: '{ name, organization, email, country }',
          dnssec: 'boolean | null',
          rawText: 'string',
          payment: '{ txHash, network, amount, settled }',
        },
      }),
      402,
    );
  }

  const verification = await verifyPayment(payment, walletAddress, WHOIS_PRICE_USDC, solanaRpc, baseRpc);
  if (!verification.valid) {
    return c.json({
      error: 'Payment verification failed',
      reason: verification.error,
      hint: 'Ensure the transaction is confirmed and sends the correct USDC amount to the recipient wallet.',
    }, 402);
  }

  const clientIp = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
  if (!checkProxyRateLimit(clientIp)) {
    c.header('Retry-After', '60');
    return c.json({ error: 'Rate limit exceeded. Max 20 requests/min.', retryAfter: 60 }, 429);
  }

  const rawDomain = c.req.query('domain');
  if (!rawDomain) {
    return c.json({ error: 'Missing required parameter: domain', hint: 'Example: /api/whois?domain=example.com' }, 400);
  }

  const domain = sanitizeDomain(rawDomain);
  if (!domain) {
    return c.json({ error: 'Invalid domain format', hint: 'Provide a valid domain like example.com' }, 400);
  }

  try {
    const whoisText = await fetchWhoisFromApi(domain);
    const record = parseWhoisRaw(whoisText, domain);

    c.header('X-Payment-Settled', 'true');
    c.header('X-Payment-TxHash', payment.txHash);

    return c.json({
      data: record,
      payment: {
        txHash: payment.txHash,
        network: payment.network,
        amount: verification.amount,
        settled: true,
      },
    });
  } catch (err: any) {
    return c.json({ error: 'WHOIS lookup failed', message: err.message }, 502);
  }
});

// GET /api/dns?domain=example.com&type=A
serviceRouter.get('/dns', async (c) => {
  const walletAddress = c.env.WALLET_ADDRESS;
  const walletBase = c.env.WALLET_ADDRESS_BASE || walletAddress;
  const solanaRpc = c.env.SOLANA_RPC_URL;
  const baseRpc = c.env.BASE_RPC_URL;

  const payment = extractPayment(c);
  if (!payment) {
    return c.json(
      build402Response('/api/dns', DNS_DESCRIPTION, DNS_PRICE_USDC, walletAddress, walletBase, {
        input: {
          domain: 'string — Domain name (required)',
          type: 'string — DNS record type: A, AAAA, MX, NS, TXT, CNAME, SOA, CAA (default: A)',
        },
        output: {
          domain: 'string',
          type: 'string',
          records: '[{ type, name, value, ttl }]',
          payment: '{ txHash, network, amount, settled }',
        },
      }),
      402,
    );
  }

  const verification = await verifyPayment(payment, walletAddress, DNS_PRICE_USDC, solanaRpc, baseRpc);
  if (!verification.valid) {
    return c.json({
      error: 'Payment verification failed',
      reason: verification.error,
    }, 402);
  }

  const clientIp = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
  if (!checkProxyRateLimit(clientIp)) {
    c.header('Retry-After', '60');
    return c.json({ error: 'Rate limit exceeded. Max 20 requests/min.', retryAfter: 60 }, 429);
  }

  const rawDomain = c.req.query('domain');
  if (!rawDomain) {
    return c.json({ error: 'Missing required parameter: domain', hint: 'Example: /api/dns?domain=example.com&type=MX' }, 400);
  }

  const domain = sanitizeDomain(rawDomain);
  if (!domain) {
    return c.json({ error: 'Invalid domain format' }, 400);
  }

  const typeParam = c.req.query('type') || 'A';
  if (!isValidDnsType(typeParam)) {
    return c.json({ error: `Invalid DNS record type: ${typeParam}`, hint: `Supported types: ${VALID_DNS_TYPES.join(', ')}` }, 400);
  }

  try {
    const records = await fetchDnsRecords(domain, typeParam);

    c.header('X-Payment-Settled', 'true');
    c.header('X-Payment-TxHash', payment.txHash);

    return c.json({
      data: { domain, type: typeParam, records },
      payment: {
        txHash: payment.txHash,
        network: payment.network,
        amount: verification.amount,
        settled: true,
      },
    });
  } catch (err: any) {
    return c.json({ error: 'DNS lookup failed', message: err.message }, 502);
  }
});

// GET /api/reverse?ip=1.2.3.4
serviceRouter.get('/reverse', async (c) => {
  const walletAddress = c.env.WALLET_ADDRESS;
  const walletBase = c.env.WALLET_ADDRESS_BASE || walletAddress;
  const solanaRpc = c.env.SOLANA_RPC_URL;
  const baseRpc = c.env.BASE_RPC_URL;

  const payment = extractPayment(c);
  if (!payment) {
    return c.json(
      build402Response('/api/reverse', REVERSE_DESCRIPTION, REVERSE_PRICE_USDC, walletAddress, walletBase, {
        input: { ip: 'string — IPv4 address (required)' },
        output: {
          ip: 'string',
          domains: 'string[]',
          totalCount: 'number',
          payment: '{ txHash, network, amount, settled }',
        },
      }),
      402,
    );
  }

  const verification = await verifyPayment(payment, walletAddress, REVERSE_PRICE_USDC, solanaRpc, baseRpc);
  if (!verification.valid) {
    return c.json({
      error: 'Payment verification failed',
      reason: verification.error,
    }, 402);
  }

  const clientIp = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
  if (!checkProxyRateLimit(clientIp)) {
    c.header('Retry-After', '60');
    return c.json({ error: 'Rate limit exceeded. Max 20 requests/min.', retryAfter: 60 }, 429);
  }

  const rawIp = c.req.query('ip');
  if (!rawIp) {
    return c.json({ error: 'Missing required parameter: ip', hint: 'Example: /api/reverse?ip=93.184.216.34' }, 400);
  }

  const ip = sanitizeIp(rawIp);
  if (!ip) {
    return c.json({ error: 'Invalid IPv4 address', hint: 'Provide a valid IPv4 address like 93.184.216.34' }, 400);
  }

  try {
    const result = await fetchReverseIp(ip);

    c.header('X-Payment-Settled', 'true');
    c.header('X-Payment-TxHash', payment.txHash);

    return c.json({
      data: result,
      payment: {
        txHash: payment.txHash,
        network: payment.network,
        amount: verification.amount,
        settled: true,
      },
    });
  } catch (err: any) {
    return c.json({ error: 'Reverse IP lookup failed', message: err.message }, 502);
  }
});

// GET /api/batch?domains=example.com,google.com,github.com
serviceRouter.get('/batch', async (c) => {
  const walletAddress = c.env.WALLET_ADDRESS;
  const walletBase = c.env.WALLET_ADDRESS_BASE || walletAddress;
  const solanaRpc = c.env.SOLANA_RPC_URL;
  const baseRpc = c.env.BASE_RPC_URL;

  const payment = extractPayment(c);
  if (!payment) {
    return c.json(
      build402Response('/api/batch', BATCH_DESCRIPTION, BATCH_PRICE_USDC, walletAddress, walletBase, {
        input: { domains: 'string — Comma-separated domain list (required, max 10)' },
        output: {
          results: '[{ domain, registrar, creationDate, expirationDate, nameServers, status, registrant, dnssec, error? }]',
          totalQueried: 'number',
          successful: 'number',
          payment: '{ txHash, network, amount, settled }',
        },
      }),
      402,
    );
  }

  const verification = await verifyPayment(payment, walletAddress, BATCH_PRICE_USDC, solanaRpc, baseRpc);
  if (!verification.valid) {
    return c.json({
      error: 'Payment verification failed',
      reason: verification.error,
    }, 402);
  }

  const clientIp = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
  if (!checkProxyRateLimit(clientIp)) {
    c.header('Retry-After', '60');
    return c.json({ error: 'Rate limit exceeded. Max 20 requests/min.', retryAfter: 60 }, 429);
  }

  const rawDomains = c.req.query('domains');
  if (!rawDomains) {
    return c.json({ error: 'Missing required parameter: domains', hint: 'Example: /api/batch?domains=example.com,google.com,github.com' }, 400);
  }

  const domainList = rawDomains.split(',').map(d => sanitizeDomain(d)).filter((d): d is string => d !== null);
  if (domainList.length === 0) {
    return c.json({ error: 'No valid domains provided' }, 400);
  }
  if (domainList.length > MAX_BATCH_SIZE) {
    return c.json({ error: `Too many domains. Maximum ${MAX_BATCH_SIZE} per request.`, provided: domainList.length }, 400);
  }

  try {
    const results = await Promise.allSettled(
      domainList.map(async (domain) => {
        const whoisText = await fetchWhoisFromApi(domain);
        return parseWhoisRaw(whoisText, domain);
      })
    );

    const mapped = results.map((r, i) => {
      if (r.status === 'fulfilled') return r.value;
      return { domain: domainList[i], error: r.reason?.message || 'Lookup failed' };
    });

    c.header('X-Payment-Settled', 'true');
    c.header('X-Payment-TxHash', payment.txHash);

    return c.json({
      data: {
        results: mapped,
        totalQueried: domainList.length,
        successful: results.filter(r => r.status === 'fulfilled').length,
      },
      payment: {
        txHash: payment.txHash,
        network: payment.network,
        amount: verification.amount,
        settled: true,
      },
    });
  } catch (err: any) {
    return c.json({ error: 'Batch WHOIS lookup failed', message: err.message }, 502);
  }
});
