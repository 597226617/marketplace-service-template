# Domain Intelligence API

Turn AI agent traffic into passive USDC income with domain intelligence services.

WHOIS lookups, DNS queries, reverse IP lookups, and batch processing — all behind x402 payment gates.

## Features

- **WHOIS Lookup** (`/api/whois`) — Registrar, dates, nameservers, status codes, registrant info ($0.005)
- **DNS Records** (`/api/dns`) — A, AAAA, MX, NS, TXT, CNAME, SOA, CAA ($0.003)
- **Reverse IP** (`/api/reverse`) — Find all domains on the same IP ($0.005)
- **Batch WHOIS** (`/api/batch`) — Up to 10 domains in one request ($0.02)

## How It Works

```
AI Agent → GET /api/whois?domain=example.com
         ← 402 Payment Required (price, wallet, networks)
AI Agent → Send USDC via Solana (~400ms) or Base (~2s)
AI Agent → GET /api/whois?domain=example.com + Payment-Signature header
         ← 200 { data: { ...whois record... } }
```

## Setup

```bash
git clone git@github.com:597226617/marketplace-service-template.git
cd marketplace-service-template

cp .env.example .env
# Edit .env: set WALLET_ADDRESS + PROXY_* credentials

bun install
bun run dev
```

## Test

```bash
curl http://localhost:3000/health
# → {"status":"healthy","service":"domain-intelligence-api",...}

curl http://localhost:3000/
# → Service discovery JSON (AI agents read this)

curl "http://localhost:3000/api/whois?domain=example.com"
# → 402 with payment instructions (this is correct!)
```

## Deploy

```bash
# Docker
docker build -t domain-intelligence-api .
docker run -p 3000:3000 --env-file .env domain-intelligence-api

# Any VPS with Bun
bun install --production && bun run start

# Railway / Fly.io / Render
# Just connect the repo — Dockerfile detected automatically
```

## Pricing

| Endpoint | Price | Avg Response Size | Est. Cost/Req |
|----------|-------|-------------------|---------------|
| WHOIS | $0.005 | ~2 KB | $0.00001 |
| DNS | $0.003 | ~1 KB | $0.000004 |
| Reverse IP | $0.005 | ~5 KB | $0.00004 |
| Batch WHOIS | $0.02 | ~20 KB | $0.00016 |

## Infrastructure

- **Proxies:** 148 mobile devices across DE, PL, US, FR, ES, GB via [Proxies.sx](https://proxies.sx)
- **Payment:** x402 protocol — Solana + Base USDC, on-chain verification
- **Security:** Replay prevention, SSRF protection, rate limiting, security headers

## Stack

- [Bun](https://bun.sh) — Fast TypeScript runtime
- [Hono](https://hono.dev) — Lightweight web framework
- x402 payment verification — Zero dependencies, public RPCs

## License

MIT — fork it, ship it, profit.
