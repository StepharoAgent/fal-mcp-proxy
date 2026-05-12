# fal-mcp-proxy

Tiny Cloudflare Worker that puts a query-param key in front of fal.ai's
official remote MCP server (`https://mcp.fal.ai/mcp`).

## Why

`mcp.fal.ai` requires `Authorization: Bearer <FAL_KEY>` on every request, but
many MCP clients (claude.ai custom connectors, ChatGPT custom apps, etc.) only
let you paste a URL. This proxy:

- Validates a shared secret passed as `?key=<PROXY_TOKEN>`.
- Strips the `key` parameter and forwards everything else to `mcp.fal.ai`,
  injecting the `FAL_KEY` server-side.
- Streams Streamable HTTP / SSE responses transparently.

The `FAL_KEY` never reaches the client — only the proxy holds it.

## Use

```
https://fal-mcp-proxy.<account>.workers.dev/mcp?key=<PROXY_TOKEN>
```

Drop that URL into any client that takes a remote MCP URL.

## Deploy

```bash
npm install
wrangler secret put FAL_KEY        # fal.ai API key
wrangler secret put PROXY_TOKEN    # any random string — your shared secret
wrangler deploy
```

## Endpoints

| Path        | Behavior |
|-------------|----------|
| `/`         | Tiny status page |
| `/healthz`  | `ok` (no auth) |
| `/mcp`      | Authenticated, proxied to `https://mcp.fal.ai/mcp` |
| anything else | Authenticated, proxied 1:1 to `https://mcp.fal.ai<path>` |

Authentication accepts either:
- `?key=<PROXY_TOKEN>` query parameter, or
- `Authorization: Bearer <PROXY_TOKEN>` header.

## Security notes

- Keep `PROXY_TOKEN` secret — anyone with the URL gets metered fal.ai access
  against your account.
- Rotate it with `wrangler secret put PROXY_TOKEN` whenever it leaks.
- Optional hardening you might want to add later: a Cloudflare WAF rate-limit
  rule on the route, IP allowlist via a `Cloudflare-Access` policy, or a
  per-tool spend cap by parsing the JSON-RPC body in the Worker.
