/**
 * fal-mcp-proxy
 * ─────────────
 * Cloudflare Worker that fronts the official fal.ai remote MCP server
 * (https://mcp.fal.ai/mcp) and adds a minimal OAuth 2.1 + PKCE layer in front
 * of it so clients like claude.ai / ChatGPT custom connectors can connect.
 *
 * Why OAuth: claude.ai's Custom Connector flow ALWAYS attempts Dynamic Client
 * Registration (RFC 7591) and OAuth 2.1 authorization-code+PKCE. Without that
 * dance it gives up with "Couldn't reach the MCP server".
 *
 * fal.ai itself does NOT speak OAuth — it only takes `Authorization: Bearer
 * <FAL_KEY>` on a Streamable-HTTP endpoint. So this Worker:
 *
 *   1.  Speaks OAuth 2.1 to the client (claude.ai).
 *   2.  Authenticates the human owner via a single shared secret (PROXY_TOKEN)
 *       entered on a one-page consent form. No accounts, no database.
 *   3.  Issues stateless access tokens — HMAC-signed JSON payloads using
 *       PROXY_TOKEN as the signing key. No KV / DO needed.
 *   4.  On `/mcp*`, validates the bearer token, strips the client's auth, and
 *       forwards with `Authorization: Bearer <FAL_KEY>` to mcp.fal.ai. The
 *       fal.ai key never leaves the Worker.
 *
 * Endpoints:
 *
 *   GET  /                                         status page (no auth)
 *   GET  /healthz                                  ok
 *   GET  /.well-known/oauth-authorization-server   RFC 8414 metadata
 *   GET  /.well-known/oauth-protected-resource     RFC 9728 metadata
 *   POST /register                                 RFC 7591 dynamic registration
 *   GET  /authorize                                consent form
 *   POST /authorize                                consent submit → 302 with code
 *   POST /token                                    code → access_token
 *   *    /mcp[/anything]                           bearer-gated reverse proxy
 *
 * The proxy is stateless. State (consent decision, code, tokens) lives in
 * signed payloads — anything tampered fails HMAC verification.
 */

export interface Env {
  FAL_KEY: string;
  PROXY_TOKEN: string;
}

const UPSTREAM = "https://mcp.fal.ai";

const ACCESS_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 30; // 30d
const CODE_TTL_SECONDS = 300; // 5min
const SUPPORTED_SCOPES = ["mcp"];

/* ─────────────── tiny utils ─────────────── */

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64urlEncode(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

async function hmacSign(secret: string, payload: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
  return b64urlEncode(sig);
}
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let m = 0;
  for (let i = 0; i < a.length; i++) m |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return m === 0;
}

interface SignedToken {
  k: string; // kind: 'code' | 'access'
  exp: number; // epoch seconds
  [extra: string]: any;
}
async function sign(secret: string, body: SignedToken): Promise<string> {
  const payload = b64urlEncode(enc.encode(JSON.stringify(body)));
  const sig = await hmacSign(secret, payload);
  return `${payload}.${sig}`;
}
async function verify<T extends SignedToken = SignedToken>(secret: string, token: string): Promise<T | null> {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const expected = await hmacSign(secret, parts[0]);
  if (!timingSafeEqual(parts[1], expected)) return null;
  try {
    const body = JSON.parse(dec.decode(b64urlDecode(parts[0]))) as T;
    if (typeof body.exp !== "number" || body.exp < Math.floor(Date.now() / 1000)) return null;
    return body;
  } catch {
    return null;
  }
}

async function sha256(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return b64urlEncode(buf);
}

function htmlEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/* ─────────────── CORS ─────────────── */

function cors(req: Request): Record<string, string> {
  const origin = req.headers.get("origin") || "*";
  const reqHeaders =
    req.headers.get("access-control-request-headers") ||
    "content-type, authorization, mcp-protocol-version, mcp-session-id, x-requested-with";
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, POST, OPTIONS, DELETE",
    "access-control-allow-headers": reqHeaders,
    "access-control-expose-headers": "mcp-session-id, mcp-protocol-version, www-authenticate",
    "access-control-max-age": "86400",
    "vary": "origin",
  };
}
function withCors(res: Response, req: Request): Response {
  const headers = new Headers(res.headers);
  for (const [k, v] of Object.entries(cors(req))) headers.set(k, v);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

/* ─────────────── responses ─────────────── */

function jsonResponse(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...extra },
  });
}

function oauthError(error: string, description?: string, status = 400): Response {
  return jsonResponse(description ? { error, error_description: description } : { error }, status);
}

/* ─────────────── routes ─────────────── */

function originOf(req: Request): string {
  const u = new URL(req.url);
  return `${u.protocol}//${u.host}`;
}

function metadataAuthServer(req: Request): Response {
  const issuer = originOf(req);
  return jsonResponse({
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    registration_endpoint: `${issuer}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_basic", "client_secret_post"],
    scopes_supported: SUPPORTED_SCOPES,
  });
}
function metadataProtectedResource(req: Request): Response {
  const issuer = originOf(req);
  return jsonResponse({
    resource: `${issuer}/mcp`,
    authorization_servers: [issuer],
    bearer_methods_supported: ["header"],
    scopes_supported: SUPPORTED_SCOPES,
  });
}

async function handleRegister(req: Request): Promise<Response> {
  // RFC 7591 Dynamic Client Registration — open, no auth (per spec for public clients).
  let body: any = {};
  try {
    body = await req.json();
  } catch {
    /* empty body is fine */
  }
  const clientId = "client-" + b64urlEncode(crypto.getRandomValues(new Uint8Array(9)));
  return jsonResponse(
    {
      client_id: clientId,
      client_name: body.client_name || "MCP Client",
      redirect_uris: body.redirect_uris || [],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      scope: SUPPORTED_SCOPES.join(" "),
    },
    201,
  );
}

function renderConsentPage(params: URLSearchParams, error?: string): Response {
  const clientId = params.get("client_id") || "?";
  const redirectUri = params.get("redirect_uri") || "";
  const safeRedirect = htmlEscape(redirectUri);
  const html = `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>fal-mcp-proxy — Authorize</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.5 -apple-system, system-ui, sans-serif; max-width: 460px; margin: 56px auto; padding: 0 20px; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .muted { color: #777; font-size: 13px; }
  code { background: #f3f3f3; padding: 1px 5px; border-radius: 4px; font-size: 13px; }
  @media (prefers-color-scheme: dark) { code { background: #2a2a2a; } }
  form { margin-top: 24px; display: grid; gap: 12px; }
  label { font-weight: 600; }
  input[type=password] { padding: 10px 12px; font-size: 15px; border: 1px solid #ccc; border-radius: 6px; font-family: ui-monospace, monospace; }
  button { padding: 10px 14px; font-size: 15px; font-weight: 600; border-radius: 6px; border: 0; background: #2563eb; color: white; cursor: pointer; }
  button:hover { background: #1d4ed8; }
  .err { color: #b00020; font-size: 13px; }
  .meta { margin-top: 28px; font-size: 12px; color: #888; word-break: break-all; }
</style>
<h1>fal-mcp-proxy</h1>
<p class="muted">Approve <code>${htmlEscape(clientId)}</code> to use this proxy to call the fal.ai MCP on your behalf.</p>
${error ? `<p class="err">${htmlEscape(error)}</p>` : ""}
<form method="POST" action="/authorize">
  <input type="hidden" name="_params" value="${htmlEscape(params.toString())}">
  <label for="token">Proxy token</label>
  <input id="token" name="proxy_token" type="password" required autocomplete="off" autofocus
         placeholder="the PROXY_TOKEN this proxy was deployed with">
  <button type="submit">Authorize</button>
</form>
<div class="meta">
  Redirect: <code>${safeRedirect}</code>
</div>`;
  return new Response(html, {
    status: error ? 400 : 200,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
}

async function handleAuthorizeGet(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  const required = ["client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method"];
  for (const k of required) {
    if (!url.searchParams.get(k)) return oauthError("invalid_request", `missing ${k}`);
  }
  if (url.searchParams.get("response_type") !== "code") return oauthError("unsupported_response_type");
  if (url.searchParams.get("code_challenge_method") !== "S256") return oauthError("invalid_request", "S256 required");

  // Auto-approve shortcut: if token was passed via ?proxy_token=… in the URL
  // (advanced use, scriptable), validate immediately and redirect.
  const inlineToken = url.searchParams.get("proxy_token");
  if (inlineToken && timingSafeEqual(inlineToken, env.PROXY_TOKEN)) {
    return await issueCodeAndRedirect(url.searchParams, env);
  }

  return renderConsentPage(url.searchParams);
}

async function issueCodeAndRedirect(params: URLSearchParams, env: Env): Promise<Response> {
  const redirectUri = params.get("redirect_uri")!;
  const code = await sign(env.PROXY_TOKEN, {
    k: "code",
    exp: Math.floor(Date.now() / 1000) + CODE_TTL_SECONDS,
    cid: params.get("client_id"),
    ru: redirectUri,
    cc: params.get("code_challenge"),
    s: params.get("scope") || SUPPORTED_SCOPES.join(" "),
  });
  const u = new URL(redirectUri);
  u.searchParams.set("code", code);
  const state = params.get("state");
  if (state) u.searchParams.set("state", state);
  return new Response(null, { status: 302, headers: { location: u.toString() } });
}

async function handleAuthorizePost(req: Request, env: Env): Promise<Response> {
  const form = await req.formData();
  const submittedToken = String(form.get("proxy_token") || "");
  const paramsStr = String(form.get("_params") || "");
  const params = new URLSearchParams(paramsStr);
  if (!params.get("redirect_uri")) return oauthError("invalid_request", "missing _params");

  if (!submittedToken || !timingSafeEqual(submittedToken, env.PROXY_TOKEN)) {
    return renderConsentPage(params, "Wrong proxy token.");
  }
  return await issueCodeAndRedirect(params, env);
}

async function handleToken(req: Request, env: Env): Promise<Response> {
  const ct = (req.headers.get("content-type") || "").toLowerCase();
  let form: URLSearchParams;
  if (ct.includes("application/x-www-form-urlencoded")) {
    form = new URLSearchParams(await req.text());
  } else if (ct.includes("application/json")) {
    const j = (await req.json()) as Record<string, string>;
    form = new URLSearchParams(j);
  } else {
    form = new URLSearchParams(await req.text());
  }

  const grant = form.get("grant_type");

  if (grant === "authorization_code") {
    const code = form.get("code");
    const verifier = form.get("code_verifier");
    const redirectUri = form.get("redirect_uri");
    if (!code || !verifier || !redirectUri) return oauthError("invalid_request");
    const decoded = await verify(env.PROXY_TOKEN, code);
    if (!decoded || decoded.k !== "code") return oauthError("invalid_grant", "bad/expired code");
    if (decoded.ru !== redirectUri) return oauthError("invalid_grant", "redirect_uri mismatch");
    const challengeFromVerifier = await sha256(verifier);
    if (decoded.cc !== challengeFromVerifier) return oauthError("invalid_grant", "PKCE verifier mismatch");
    return await issueTokens(env, decoded.s as string | undefined);
  }

  if (grant === "refresh_token") {
    const rt = form.get("refresh_token");
    if (!rt) return oauthError("invalid_request");
    const decoded = await verify(env.PROXY_TOKEN, rt);
    if (!decoded || decoded.k !== "refresh") return oauthError("invalid_grant");
    return await issueTokens(env, decoded.s as string | undefined);
  }

  return oauthError("unsupported_grant_type");
}

async function issueTokens(env: Env, scope?: string): Promise<Response> {
  const now = Math.floor(Date.now() / 1000);
  const access = await sign(env.PROXY_TOKEN, { k: "access", exp: now + ACCESS_TOKEN_TTL_SECONDS, s: scope });
  const refresh = await sign(env.PROXY_TOKEN, { k: "refresh", exp: now + ACCESS_TOKEN_TTL_SECONDS * 6, s: scope });
  return jsonResponse({
    access_token: access,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    refresh_token: refresh,
    scope: scope || SUPPORTED_SCOPES.join(" "),
  });
}

/* ─────────────── MCP proxy ─────────────── */

function unauthorizedMcp(req: Request): Response {
  // Per RFC 9728: point clients at the protected-resource metadata via
  // WWW-Authenticate, so they discover our OAuth flow.
  const issuer = originOf(req);
  return new Response(JSON.stringify({ error: "unauthorized" }), {
    status: 401,
    headers: {
      "content-type": "application/json",
      "www-authenticate": `Bearer resource_metadata="${issuer}/.well-known/oauth-protected-resource"`,
    },
  });
}

async function handleMcp(req: Request, env: Env): Promise<Response> {
  // Accept either a real OAuth access token (claude.ai/ChatGPT) OR the raw
  // PROXY_TOKEN (CLI / curl use). Both validated cheaply.
  const auth = req.headers.get("authorization");
  let authorized = false;
  if (auth?.toLowerCase().startsWith("bearer ")) {
    const bearer = auth.slice(7).trim();
    if (timingSafeEqual(bearer, env.PROXY_TOKEN)) {
      authorized = true;
    } else {
      const decoded = await verify(env.PROXY_TOKEN, bearer);
      if (decoded && decoded.k === "access") authorized = true;
    }
  }
  // Legacy: ?key=<PROXY_TOKEN> still accepted so curl tests keep working.
  if (!authorized) {
    const fromQuery = new URL(req.url).searchParams.get("key");
    if (fromQuery && timingSafeEqual(fromQuery, env.PROXY_TOKEN)) authorized = true;
  }
  if (!authorized) return unauthorizedMcp(req);

  // Proxy.
  const inUrl = new URL(req.url);
  const out = new URL(UPSTREAM + inUrl.pathname);
  for (const [k, v] of inUrl.searchParams) {
    if (k === "key") continue;
    out.searchParams.append(k, v);
  }

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
    headers.set("user-agent", "fal-mcp-proxy/0.3 (+https://github.com/StepharoAgent/fal-mcp-proxy)");
  }

  const init: RequestInit = {
    method: req.method,
    headers,
    body: req.method === "GET" || req.method === "HEAD" ? undefined : req.body,
    redirect: "manual",
  };
  let upstream: Response;
  try {
    upstream = await fetch(out.toString(), init);
  } catch (err) {
    return jsonResponse({ error: "upstream_fetch_failed", detail: String(err) }, 502);
  }
  const outHeaders = new Headers(upstream.headers);
  outHeaders.delete("transfer-encoding");
  outHeaders.delete("connection");
  outHeaders.delete("keep-alive");
  return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: outHeaders });
}

/* ─────────────── status page ─────────────── */

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
<p class="muted">OAuth-fronted reverse proxy for <code>https://mcp.fal.ai/mcp</code>.</p>
<p>For URL-only custom connector dialogs, paste:</p>
<pre><code>https://&lt;this-host&gt;/mcp</code></pre>
<p>The client will run an OAuth flow; approve it with your <code>PROXY_TOKEN</code>.</p>
<p class="muted">CLI/curl users can still pass <code>?key=&lt;PROXY_TOKEN&gt;</code> or <code>Authorization: Bearer &lt;PROXY_TOKEN&gt;</code> directly.</p>
<p class="muted">Source: <a href="https://github.com/StepharoAgent/fal-mcp-proxy">github.com/StepharoAgent/fal-mcp-proxy</a></p>
`;

/* ─────────────── entry ─────────────── */

export default {
  async fetch(req: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);

    if (!env.FAL_KEY || !env.PROXY_TOKEN) {
      return withCors(new Response("misconfigured: FAL_KEY and PROXY_TOKEN secrets required", { status: 500 }), req);
    }

    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors(req) });
    }

    try {
      // Public/discovery routes.
      if (req.method === "GET" && (url.pathname === "/" || url.pathname === "")) {
        return withCors(
          new Response(STATUS_HTML, { headers: { "content-type": "text/html; charset=utf-8" } }),
          req,
        );
      }
      if (req.method === "GET" && url.pathname === "/healthz") {
        return withCors(new Response("ok\n", { headers: { "content-type": "text/plain" } }), req);
      }
      if (
        req.method === "GET" &&
        (url.pathname === "/.well-known/oauth-authorization-server" ||
          url.pathname === "/.well-known/oauth-authorization-server/mcp")
      ) {
        return withCors(metadataAuthServer(req), req);
      }
      if (
        req.method === "GET" &&
        (url.pathname === "/.well-known/oauth-protected-resource" ||
          url.pathname === "/.well-known/oauth-protected-resource/mcp")
      ) {
        return withCors(metadataProtectedResource(req), req);
      }

      // OAuth endpoints.
      if (req.method === "POST" && url.pathname === "/register") {
        return withCors(await handleRegister(req), req);
      }
      if (req.method === "GET" && url.pathname === "/authorize") {
        return withCors(await handleAuthorizeGet(req, env), req);
      }
      if (req.method === "POST" && url.pathname === "/authorize") {
        return withCors(await handleAuthorizePost(req, env), req);
      }
      if (req.method === "POST" && url.pathname === "/token") {
        return withCors(await handleToken(req, env), req);
      }

      // MCP proxy — catch /mcp and anything underneath, plus the legacy ?key flow.
      if (url.pathname === "/mcp" || url.pathname.startsWith("/mcp/")) {
        return withCors(await handleMcp(req, env), req);
      }

      // Any other path: assume it's something fal.ai exposes that we should pass through,
      // BUT only after auth — otherwise we leak surface area.
      const fromQuery = url.searchParams.get("key");
      const auth = req.headers.get("authorization");
      const tokenOK =
        (fromQuery && timingSafeEqual(fromQuery, env.PROXY_TOKEN)) ||
        (auth?.toLowerCase().startsWith("bearer ") && timingSafeEqual(auth.slice(7).trim(), env.PROXY_TOKEN));
      if (tokenOK) return withCors(await handleMcp(req, env), req);

      return withCors(jsonResponse({ error: "not_found" }, 404), req);
    } catch (err) {
      return withCors(jsonResponse({ error: "internal", detail: String(err) }, 500), req);
    }
  },
};
