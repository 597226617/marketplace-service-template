/**
 * Domain Intelligence API — Cloudflare Workers Entry Point
 * ──────────────────────────────────────────────────────
 * Mounts: /api/*
 * Endpoints: /api/whois, /api/dns, /api/reverse, /api/batch
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { serviceRouter } from './service';

// ─── WORKERS ENV BINDINGS ────────────────────────────

type Env = {
  SERVICE_NAME?: string;
  SERVICE_DESCRIPTION?: string;
  WALLET_ADDRESS: string;
  WALLET_ADDRESS_BASE?: string;
  RATE_LIMIT?: string;
  SOLANA_RPC_URL?: string;
  BASE_RPC_URL?: string;
};

const app = new Hono<{ Bindings: Env }>();

// ─── MIDDLEWARE ──────────────────────────────────────

app.use('*', logger());

app.use('*', cors({
  origin: '*',
  allowHeaders: ['Content-Type', 'Payment-Signature', 'X-Payment-Signature', 'X-Payment-Network'],
  exposeHeaders: ['X-Payment-Settled', 'X-Payment-TxHash', 'Retry-After'],
}));

// Security headers
app.use('*', async (c, next) => {
  await next();
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('Referrer-Policy', 'no-referrer');
});

// Rate limiting (per-IP, resets every minute)
// Note: In Workers this is per-isolate. For production, use a Durable Object or KV for global rate limiting.
const rateLimits = new Map<string, { count: number; resetAt: number }>();

app.use('*', async (c, next) => {
  const rateLimitMax = parseInt(c.env.RATE_LIMIT || '60');
  const ip = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
  const now = Date.now();
  const entry = rateLimits.get(ip);

  if (!entry || now > entry.resetAt) {
    rateLimits.set(ip, { count: 1, resetAt: now + 60_000 });
  } else {
    entry.count++;
    if (entry.count > rateLimitMax) {
      c.header('Retry-After', '60');
      return c.json({ error: 'Rate limit exceeded', retryAfter: 60 }, 429);
    }
  }

  await next();
});

// ─── X402 SERVICE DISCOVERY (/.well-known/x402-info) ──
app.get('/.well-known/x402-info', (c) => c.json({
  name: c.env.SERVICE_NAME || 'domain-intelligence-api',
  description: 'Domain Intelligence API: WHOIS lookup, DNS record queries, reverse IP lookup, and batch WHOIS. Pay-per-call via x402 micro-payments.',
  version: '1.0.0',
  pricing: {
    currency: 'USDC',
    defaultPrice: 3000,
    endpoints: [
      { path: '/api/whois', method: 'GET', price: 5000, description: 'Full WHOIS lookup: registrar, dates, nameservers, status, registrant info' },
      { path: '/api/dns', method: 'GET', price: 3000, description: 'DNS record lookup (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA)' },
      { path: '/api/reverse', method: 'GET', price: 5000, description: 'Reverse IP lookup — find all domains on the same IP' },
      { path: '/api/batch', method: 'GET', price: 20000, description: 'Batch WHOIS lookup for up to 10 domains' },
    ],
    freeEndpoints: ['/', '/health', '/.well-known/x402-info'],
  },
  capabilities: ['search', 'analyze', 'retrieve'],
  infrastructure: 'Cloudflare Workers edge network',
  links: {
    github: 'https://github.com/597226617/marketplace-service-template',
    x402: 'https://x402.org',
  },
}));

// ─── ROUTES ─────────────────────────────────────────

app.get('/health', (c) => c.json({
  status: 'healthy',
  service: c.env.SERVICE_NAME || 'domain-intelligence-api',
  version: '1.0.0',
  timestamp: new Date().toISOString(),
  endpoints: [
    '/api/whois',
    '/api/dns',
    '/api/reverse',
    '/api/batch',
  ],
}));

app.get('/', (c) => c.json({
  name: c.env.SERVICE_NAME || 'domain-intelligence-api',
  description: c.env.SERVICE_DESCRIPTION || 'Domain Intelligence API: WHOIS lookup, DNS record queries, reverse IP lookup, and batch WHOIS. Powered by Cloudflare Workers edge network.',
  version: '1.0.0',
  endpoints: [
    { method: 'GET', path: '/api/whois', description: 'Full WHOIS lookup: registrar, dates, nameservers, status, registrant info', price: '0.005 USDC' },
    { method: 'GET', path: '/api/dns', description: 'DNS record lookup (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA)', price: '0.003 USDC' },
    { method: 'GET', path: '/api/reverse', description: 'Reverse IP lookup — find all domains on the same IP', price: '0.005 USDC' },
    { method: 'GET', path: '/api/batch', description: 'Batch WHOIS lookup for up to 10 domains', price: '0.02 USDC' },
  ],
  pricing: {
    amount: '0.005',
    currency: 'USDC',
    networks: [
      {
        network: 'solana',
        chainId: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
        recipient: c.env.WALLET_ADDRESS,
        asset: 'USDC',
        assetAddress: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
        settlementTime: '~400ms',
      },
      {
        network: 'base',
        chainId: 'eip155:8453',
        recipient: c.env.WALLET_ADDRESS_BASE || c.env.WALLET_ADDRESS,
        asset: 'USDC',
        assetAddress: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        settlementTime: '~2s',
      },
    ],
  },
  infrastructure: 'Cloudflare Workers edge network',
  links: {
    github: 'https://github.com/597226617/marketplace-service-template',
  },
}));

app.route('/api', serviceRouter);

app.notFound((c) => c.json({
  error: 'Not found',
  endpoints: ['/', '/health', '/api/whois', '/api/dns', '/api/reverse', '/api/batch'],
}, 404));

app.onError((err, c) => {
  console.error(`[ERROR] ${err.message}`);
  return c.json({ error: 'Internal server error' }, 500);
});

// Workers export
export default app;
