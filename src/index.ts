/**
 * fal-mcp-proxy
 * ─────────────
 * Tiny Cloudflare Worker that fronts the official fal.ai remote MCP server
 * (https://mcp.fal.ai/mcp) and lets you use it from clients that only accept
 * a plain URL — e.g. claude.ai custom connectors, ChatGPT custom apps.
 *
 * Auth model:
 *   - Client passes a shared secret as `?key=<PROXY_TOKEN>` on every request,
 *     OR as `Authorization: Bearer <PROXY_TOKEN>` for CLI use.
 *   - The Worker strips it and injects `Authorization: Bearer <FAL_KEY>` toward
 *     mcp.fal.ai. The FAL_KEY never reaches the client.
 *
 * Browser-client niceties (required for claude.ai / ChatGPT web):
 *   - CORS preflight (OPTIONS) is always answered 204 with permissive headers.
 *   - All responses carry `Access-Control-Allow-Origin` + expose
 *     `mcp-session-id` so the MCP client can maintain its session.
 *   - OAuth discovery probes return 404 (not 401) so the client falls back to
 *     the URL-only / Bearer flow instead of starting an OAuth dance.
 */

export interface Env {
  FAL_KEY: string;
  PROXY_TOKEN: string;
}

const UPSTREAM = "https://mcp.fal.ai";

/* ─────────────── helpers ─────────────── */

function cors(req: Request): Record<string, string> {
  const origin = req.headers.get("origin") || "*";
  const reqHeaders =
    req.headers.get("access-control-request-headers") ||
    "content-type, authorization, mcp-protocol-version, mcp-session-id, x-requested-with";
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, POST, OPTIONS, DELETE",
    "access-control-allow-headers": reqHeaders,
    "access-control-expose-headers": "mcp-session-id, mcp-protocol-version",
    "access-control-max-age": "86400",
    "vary": "origin",
  };
}

function withCors(res: Response, req: Request): Response {
  const headers = new Headers(res.headers);
  for (const [k, v] of Object.entries(cors(req))) headers.set(k, v);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return mismatch === 0;
}

function extractProxyToken(req: Request): string | null {
  const fromQuery = new URL(req.url).searchParams.get("key");
  if (fromQuery) return fromQuery;
  const auth = req.headers.get("authorization");
  if (auth?.toLowerCase().startsWith("bearer ")) return auth.slice(7).trim();
  return null;
}

function buildUpstreamUrl(req: Request): URL {
  const inUrl = new URL(req.url);
  const out = new URL(UPSTREAM + inUrl.pathname);
  for (const [k, v] of inUrl.searchParams) {
    if (k === "key") continue;
    out.searchParams.append(k, v);
  }
  return out;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function unauthorized(): Response {
  // No WWW-Authenticate header — we don't want clients to start an OAuth flow.
  return jsonResponse({ error: "unauthorized", hint: "append ?key=<PROXY_TOKEN> to the URL" }, 401);
}

function notFound(): Response {
  return jsonResponse({ error: "not_found" }, 404);
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

/* ─────────────── worker ─────────────── */

export default {
  async fetch(req: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);

    if (!env.FAL_KEY || !env.PROXY_TOKEN) {
      return withCors(new Response("misconfigured: FAL_KEY and PROXY_TOKEN secrets required", { status: 500 }), req);
    }

    // CORS preflight — must always succeed without auth.
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors(req) });
    }

    // Public, unauthenticated routes.
    if (req.method === "GET" && url.pathname === "/healthz") {
      return withCors(new Response("ok\n", { headers: { "content-type": "text/plain" } }), req);
    }
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "")) {
      return withCors(new Response(STATUS_HTML, { headers: { "content-type": "text/html; charset=utf-8" } }), req);
    }

    // OAuth discovery probes — answer 404 (not 401) so the client doesn't start
    // an OAuth flow. Bare-URL connectors then fall through to the Bearer path.
    if (
      req.method === "GET" &&
      (url.pathname.startsWith("/.well-known/oauth-") ||
        url.pathname === "/.well-known/openid-configuration" ||
        url.pathname.startsWith("/.well-known/mcp"))
    ) {
      return withCors(notFound(), req);
    }

    // Gate.
    const token = extractProxyToken(req);
    if (!token || !safeEqual(token, env.PROXY_TOKEN)) {
      return withCors(unauthorized(), req);
    }

    // Proxy.
    const upstreamUrl = buildUpstreamUrl(req);
    const headers = new Headers(req.headers);
    headers.delete("host");
    headers.delete("cf-connecting-ip");
    headers.delete("cf-ray");
    headers.delete("cf-visitor");
    headers.delete("cf-ipcountry");
    headers.delete("x-forwarded-for");
    headers.delete("x-forwarded-proto");
    headers.delete("x-real-ip");
    headers.set("authorization", `Bearer ${env.FAL_KEY}`);
    if (!headers.has("user-agent")) {
      headers.set("user-agent", "fal-mcp-proxy/0.2 (+https://github.com/StepharoAgent/fal-mcp-proxy)");
    }

    const init: RequestInit = {
      method: req.method,
      headers,
      body: req.method === "GET" || req.method === "HEAD" ? undefined : req.body,
      redirect: "manual",
    };

    let upstream: Response;
    try {
      upstream = await fetch(upstreamUrl.toString(), init);
    } catch (err) {
      return withCors(jsonResponse({ error: "upstream_fetch_failed", detail: String(err) }, 502), req);
    }

    const outHeaders = new Headers(upstream.headers);
    outHeaders.delete("transfer-encoding");
    outHeaders.delete("connection");
    outHeaders.delete("keep-alive");
    // Add CORS to the upstream response too.
    for (const [k, v] of Object.entries(cors(req))) outHeaders.set(k, v);

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: outHeaders,
    });
  },
};
