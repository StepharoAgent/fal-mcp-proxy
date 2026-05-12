/**
 * fal-mcp-proxy
 * ─────────────
 * Tiny Cloudflare Worker that fronts the official fal.ai remote MCP server
 * (https://mcp.fal.ai/mcp) and lets you use it from clients that only accept
 * a plain URL — e.g. claude.ai custom connectors, ChatGPT custom apps.
 *
 * Why it exists:
 *   - fal.ai's hosted MCP needs `Authorization: Bearer <FAL_KEY>` on every
 *     request, but claude.ai's "Add Custom Connector" dialog only has a URL
 *     field.
 *   - Bare-URL connectors are accepted by claude.ai when the server does NOT
 *     advertise OAuth metadata, so a simple gated reverse-proxy works.
 *
 * Auth model:
 *   - Client passes a shared secret as `?key=<PROXY_TOKEN>` on every request.
 *   - The Worker validates the token (constant-time compare) and, if good,
 *     strips it from the upstream URL and injects `Authorization: Bearer
 *     <FAL_KEY>` toward mcp.fal.ai.
 *   - Streamable HTTP (chunked + SSE-style) is forwarded transparently —
 *     `fetch()` already gives you a streaming body in both directions on
 *     Workers.
 *
 * Endpoints (everything passed through 1:1, only authorization changes):
 *   /mcp           → https://mcp.fal.ai/mcp
 *   /              → small status page
 *   /healthz       → "ok"
 *
 * Any path that doesn't match falls through to fal.ai as well, so future
 * upstream additions (e.g. /resources) keep working without redeploy.
 */

export interface Env {
  /** fal.ai API key — server-side only, never echoed back. */
  FAL_KEY: string;
  /** Shared secret the client must pass via ?key=<token>. */
  PROXY_TOKEN: string;
}

const UPSTREAM = "https://mcp.fal.ai";

/** Strip the proxy `key` query param and any other auth-ish ones before forwarding. */
function buildUpstreamUrl(req: Request): URL {
  const inUrl = new URL(req.url);
  const out = new URL(UPSTREAM + inUrl.pathname);
  for (const [k, v] of inUrl.searchParams) {
    if (k === "key") continue;
    out.searchParams.append(k, v);
  }
  return out;
}

/** Constant-time string compare to avoid timing oracles on PROXY_TOKEN. */
function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return mismatch === 0;
}

/** Pull the proxy token from ?key= OR from a Bearer header (so CLI clients work too). */
function extractProxyToken(req: Request): string | null {
  const fromQuery = new URL(req.url).searchParams.get("key");
  if (fromQuery) return fromQuery;
  const auth = req.headers.get("authorization");
  if (auth?.toLowerCase().startsWith("bearer ")) return auth.slice(7).trim();
  return null;
}

function unauthorized(): Response {
  return new Response(
    JSON.stringify({ error: "unauthorized", hint: "append ?key=<PROXY_TOKEN> to the URL" }),
    { status: 401, headers: { "content-type": "application/json" } },
  );
}

const STATUS_HTML = `<!doctype html>
<meta charset="utf-8">
<title>fal-mcp-proxy</title>
<style>
  body{font:14px/1.5 -apple-system,system-ui,sans-serif;max-width:640px;margin:48px auto;padding:0 16px;color:#222}
  code{background:#f3f3f3;padding:2px 6px;border-radius:4px}
  h1{font-size:18px;margin-bottom:4px}
  .muted{color:#777}
</style>
<h1>fal-mcp-proxy</h1>
<p class="muted">Gated reverse proxy for <code>https://mcp.fal.ai/mcp</code>.</p>
<p>Use this URL as a remote MCP server in clients that only accept a URL:</p>
<pre><code>&lt;this-host&gt;/mcp?key=&lt;PROXY_TOKEN&gt;</code></pre>
<p class="muted">Source: <a href="https://github.com/StepharoAgent/fal-mcp-proxy">github.com/StepharoAgent/fal-mcp-proxy</a></p>
`;

export default {
  async fetch(req: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);

    // Sanity: fail fast if the operator forgot a secret.
    if (!env.FAL_KEY || !env.PROXY_TOKEN) {
      return new Response("misconfigured: FAL_KEY and PROXY_TOKEN secrets required", {
        status: 500,
      });
    }

    // Public, unauthenticated routes.
    if (req.method === "GET" && url.pathname === "/healthz") {
      return new Response("ok\n", { headers: { "content-type": "text/plain" } });
    }
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "")) {
      return new Response(STATUS_HTML, { headers: { "content-type": "text/html; charset=utf-8" } });
    }

    // Gate everything else.
    const token = extractProxyToken(req);
    if (!token || !safeEqual(token, env.PROXY_TOKEN)) {
      return unauthorized();
    }

    // Build upstream request: drop ?key, rewrite Authorization to fal.ai bearer.
    const upstreamUrl = buildUpstreamUrl(req);
    const headers = new Headers(req.headers);
    headers.delete("host");
    headers.delete("cf-connecting-ip");
    headers.delete("cf-ray");
    headers.delete("cf-visitor");
    headers.delete("x-forwarded-for");
    headers.delete("x-forwarded-proto");
    headers.delete("x-real-ip");
    headers.set("authorization", `Bearer ${env.FAL_KEY}`);
    // fal.ai expects a plain User-Agent; some clients omit it.
    if (!headers.has("user-agent")) {
      headers.set("user-agent", "fal-mcp-proxy/0.1 (+https://github.com/StepharoAgent/fal-mcp-proxy)");
    }

    const init: RequestInit = {
      method: req.method,
      headers,
      // GET/HEAD must not have a body; everything else streams through.
      body: req.method === "GET" || req.method === "HEAD" ? undefined : req.body,
      redirect: "manual",
    };

    let upstream: Response;
    try {
      upstream = await fetch(upstreamUrl.toString(), init);
    } catch (err) {
      return new Response(
        JSON.stringify({ error: "upstream_fetch_failed", detail: String(err) }),
        { status: 502, headers: { "content-type": "application/json" } },
      );
    }

    // Pass the response through verbatim (status + headers + streaming body).
    // Strip hop-by-hop / Cloudflare-specific response headers so the client
    // gets a clean MCP response.
    const outHeaders = new Headers(upstream.headers);
    outHeaders.delete("transfer-encoding");
    outHeaders.delete("connection");
    outHeaders.delete("keep-alive");

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: outHeaders,
    });
  },
};
