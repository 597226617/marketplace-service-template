# CLAUDE.md — Domain Intelligence API

## Project Overview
This is a Domain Intelligence API that earns USDC via x402 protocol. AI agents pay for WHOIS lookups, DNS queries, reverse IP lookups, and batch processing.

## Architecture
- `src/index.ts` — Server entry point (DO NOT EDIT unless adding middleware/routes)
- `src/service.ts` — All API endpoint handlers and business logic
- `src/payment.ts` — x402 payment verification (DO NOT EDIT)
- `src/proxy.ts` — Mobile proxy helper with round-robin pool (DO NOT EDIT)

## Key Files to Edit
- `src/service.ts` — Add new endpoints or modify existing ones here

## Testing
```bash
bun install
bun run dev
curl http://localhost:3000/health
curl http://localhost:3000/
curl 'http://localhost:3000/api/whois?domain=example.com'  # Returns 402 (expected)
```

## Rules
- All code must be in English
- Git commits in English
- No Chinese text in code or commits
- Use proxyFetch() for all external requests (provides mobile IP rotation)
- Every endpoint must have x402 payment verification
- Return structured JSON responses
- Handle errors gracefully with descriptive messages
