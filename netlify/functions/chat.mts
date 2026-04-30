import type { Context } from "@netlify/functions";

const SITEVERIFY_URL =
  "https://challenges.cloudflare.com/turnstile/v0/siteverify";

interface SiteverifyResponse {
  success: boolean;
  "error-codes"?: string[];
}

/**
 * Parse a comma-separated "id=value" env var into an ID→value map.
 * Format: "id1=value1,id2=value2"
 */
function parseEnvMap(raw: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const entry of raw.split(",")) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) {
      console.warn(`Env map: skipping malformed entry (no '='): "${trimmed}"`);
      continue;
    }
    const id = trimmed.slice(0, eqIdx).trim();
    const value = trimmed.slice(eqIdx + 1).trim();
    if (!id || !value) {
      console.warn(`Env map: skipping entry with empty id or value: "${trimmed}"`);
      continue;
    }
    map.set(id, value);
  }
  return map;
}

/**
 * Parse ALLOWED_BACKENDS env var into an ID→URL map.
 * Format: "id1=https://url1,id2=https://url2"
 * The client sends the ID; the server resolves it to a URL.
 * This prevents SSRF — the client never controls the target URL.
 */
function getBackendMap(): Map<string, string> {
  return parseEnvMap(process.env.ALLOWED_BACKENDS ?? "");
}

/**
 * Parse RAG_BACKENDS env var into a Set of backend IDs whose JSON responses
 * should be augmented with rating-eligible metadata.
 *
 * RAG-only backends return plain `{ "response": "..." }` JSON without the
 * `metadata.is_final_response` / `metadata.rating_target` fields that
 * qa-bot-core gates rating UI on. Listing a backend here causes the proxy
 * to inject those fields so the bot renders thumbs-up/down on answers.
 *
 * Format: "id1,id2" (comma-separated). Whitespace is tolerated.
 * Example: RAG_BACKENDS="nairr,access"
 */
function getRagBackends(): Set<string> {
  return new Set(
    (process.env.RAG_BACKENDS ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
  );
}

/**
 * Per-backend Turnstile configuration.
 *
 * Each backend can have its own Turnstile widget (different Cloudflare
 * site key + secret key). This allows ACCESS and NAIRR to use separate
 * Turnstile widgets with different domain allowlists.
 *
 * Env vars (set both maps together — each backend ID in ALLOWED_BACKENDS
 * should have a matching entry in both TURNSTILE_*_KEYS):
 *   TURNSTILE_SITE_KEYS="access=0x...,nairr=0x..."
 *   TURNSTILE_SECRET_KEYS="access=secret1,nairr=secret2"
 *
 * Falls back to the single-key env vars (TURNSTILE_SITE_KEY,
 * TURNSTILE_SECRET_KEY) for backwards compatibility or when all
 * backends share one widget.
 */
function getTurnstileKeys(backendId: string): { siteKey?: string; secretKey?: string } {
  const siteKeys = parseEnvMap(process.env.TURNSTILE_SITE_KEYS ?? "");
  const secretKeys = parseEnvMap(process.env.TURNSTILE_SECRET_KEYS ?? "");

  const perBackendSite = siteKeys.get(backendId);
  const perBackendSecret = secretKeys.get(backendId);

  const siteKey = perBackendSite ?? process.env.TURNSTILE_SITE_KEY;
  const secretKey = perBackendSecret ?? process.env.TURNSTILE_SECRET_KEY;

  // Warn if one side is per-backend and the other is global — likely misconfiguration
  if ((perBackendSite && !perBackendSecret) || (!perBackendSite && perBackendSecret)) {
    console.warn(
      `Turnstile config for "${backendId}": mixing per-backend and global keys. ` +
      `Set both TURNSTILE_SITE_KEYS and TURNSTILE_SECRET_KEYS for each backend.`
    );
  }

  return { siteKey, secretKey };
}

// --- Verified-session cookie ---
// After a successful Turnstile validation, we set a signed cookie so
// subsequent requests from the same browser skip Turnstile entirely.
// Turnstile tokens are single-use (consumed by siteverify), so without
// this cookie every request would require a fresh token — but
// turnstile.reset() is async with no completion signal, causing a race
// condition where the next request fires before a fresh token is ready.

const VERIFIED_COOKIE = "qa-verified";

/** How long a verified session lasts before re-verification is required.
 *  Set VERIFIED_SESSION_TTL env var to override (in seconds). Default: 300 (5 min). */
function getVerifiedTtl(): number {
  const raw = process.env.VERIFIED_SESSION_TTL;
  if (!raw) return 300;
  const n = parseInt(raw, 10);
  return Number.isNaN(n) || n < 0 ? 300 : n;
}

async function hmacSign(data: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

async function hmacVerify(data: string, signature: string, secret: string): Promise<boolean> {
  const expected = await hmacSign(data, secret);
  return expected === signature;
}

/** Check if the request has a valid verified-session cookie for this backend. */
async function isSessionVerified(
  request: Request,
  backendId: string,
  secret: string
): Promise<boolean> {
  const cookieHeader = request.headers.get("cookie");
  if (!cookieHeader) return false;

  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${VERIFIED_COOKIE}=([^;]+)`));
  if (!match) return false;

  const raw = match[1];
  const dotIdx = raw.lastIndexOf(".");
  if (dotIdx === -1) return false;

  const payload = raw.slice(0, dotIdx);
  const sig = raw.slice(dotIdx + 1);

  if (!await hmacVerify(payload, sig, secret)) return false;

  try {
    const data = JSON.parse(atob(payload));
    if (data.backend !== backendId) return false;
    if (Date.now() - data.ts > getVerifiedTtl() * 1000) return false;
    return true;
  } catch {
    return false;
  }
}

/** Build a signed Set-Cookie header value for the verified session. */
async function buildVerifiedCookie(
  backendId: string,
  secret: string
): Promise<string> {
  const payload = btoa(JSON.stringify({ backend: backendId, ts: Date.now() }));
  const sig = await hmacSign(payload, secret);
  return `${VERIFIED_COOKIE}=${payload}.${sig}; Path=/; Max-Age=${getVerifiedTtl()}; SameSite=None; Secure; HttpOnly`;
}

async function validateTurnstile(
  token: string,
  secretKey: string,
  remoteIp?: string
): Promise<SiteverifyResponse> {
  const formData = new URLSearchParams();
  formData.append("secret", secretKey);
  formData.append("response", token);
  if (remoteIp) formData.append("remoteip", remoteIp);

  const res = await fetch(SITEVERIFY_URL, {
    method: "POST",
    body: formData,
  });

  const contentType = res.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    throw new Error(`Turnstile returned non-JSON response: ${res.status} ${contentType}`);
  }

  return res.json() as Promise<SiteverifyResponse>;
}

function getCorsHeaders(request: Request): Record<string, string> {
  const origin = request.headers.get("Origin") || "*";
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-API-KEY, X-Session-ID, X-Query-ID, X-Origin",
    "Access-Control-Allow-Credentials": "true",
  };
}

function jsonResponse(data: object, status: number, cors: Record<string, string>): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...cors },
  });
}

export default async function handler(
  request: Request,
  context: Context
): Promise<Response> {
  const cors = getCorsHeaders(request);

  // Handle CORS preflight
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }

  if (request.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, 405, cors);
  }

  const backendMap = getBackendMap();
  if (backendMap.size === 0) {
    console.error("ALLOWED_BACKENDS not configured");
    return jsonResponse({ error: "Server misconfigured" }, 500, cors);
  }

  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON body" }, 400, cors);
  }

  // Resolve backend ID to URL — client never sends a URL
  const backendId = body._backend as string | undefined;
  if (!backendId) {
    return jsonResponse({ error: "Missing _backend" }, 403, cors);
  }
  const targetUrl = backendMap.get(backendId);
  if (!targetUrl) {
    return jsonResponse({ error: "Unknown backend: " + backendId }, 403, cors);
  }

  // --- Turnstile validation (with verified-session cookie) ---
  // Resolve per-backend Turnstile keys. Each backend can have its own
  // Cloudflare widget so that ACCESS and NAIRR use separate domain
  // allowlists. Falls back to the global TURNSTILE_* env vars.
  const { siteKey, secretKey } = getTurnstileKeys(backendId);

  if (!secretKey) {
    console.error(`No Turnstile secret key for backend "${backendId}"`);
    return jsonResponse({ error: "Server misconfigured" }, 500, cors);
  }

  // Check if this session was already verified via a signed cookie.
  // This avoids re-challenging on every request (Turnstile tokens are
  // single-use, and turnstile.reset() is async with no completion signal).
  let verifiedCookieValue: string | null = null;
  const alreadyVerified = await isSessionVerified(request, backendId, secretKey);

  if (!alreadyVerified) {
    const turnstileToken = body.turnstile_token as string | undefined;

    if (!turnstileToken) {
      if (siteKey) {
        return jsonResponse({ requires_turnstile: true, site_key: siteKey }, 200, cors);
      }
      return jsonResponse({ error: "Missing turnstile_token" }, 403, cors);
    }

    let verification: SiteverifyResponse;
    try {
      verification = await validateTurnstile(
        turnstileToken,
        secretKey,
        context.ip
      );
    } catch (err) {
      console.error("Turnstile siteverify request failed:", err);
      return jsonResponse({ error: "Turnstile service unavailable" }, 502, cors);
    }

    if (!verification.success) {
      console.warn(
        "Turnstile validation failed:",
        verification["error-codes"]
      );
      if (siteKey) {
        return jsonResponse({ requires_turnstile: true, site_key: siteKey }, 200, cors);
      }
      return jsonResponse({ error: "Turnstile verification failed" }, 403, cors);
    }

    // Turnstile passed — set verified cookie so subsequent requests skip validation
    verifiedCookieValue = await buildVerifiedCookie(backendId, secretKey);
  }

  // Strip proxy-only fields before forwarding
  const { turnstile_token, _backend, ...forwardBody } = body;

  // Forward safe headers to backend.
  const forwardHeaders: Record<string, string> = {
    "Content-Type": "application/json",
  };
  for (const key of ["x-api-key", "x-session-id", "x-query-id", "x-origin", "cookie"]) {
    const val = request.headers.get(key);
    if (val) forwardHeaders[key] = val;
  }

  let backendResponse: Response;
  try {
    backendResponse = await fetch(targetUrl, {
      method: "POST",
      headers: forwardHeaders,
      body: JSON.stringify(forwardBody),
    });
  } catch (err) {
    console.error("Backend request failed:", err);
    // Still emit the verified cookie if Turnstile just succeeded — the token
    // was already consumed by siteverify, so without the cookie the user
    // would have to re-challenge after a transient backend outage.
    const errRes = jsonResponse({ error: "Failed to reach backend" }, 502, cors);
    if (verifiedCookieValue) {
      errRes.headers.append("set-cookie", verifiedCookieValue);
    }
    return errRes;
  }

  // Build response headers — pass through content type and cookies.
  // Use Headers object to support multiple Set-Cookie lines (a plain
  // object can only hold one value per key).
  const resHeaders = new Headers({
    "Content-Type":
      backendResponse.headers.get("Content-Type") ?? "application/json",
    "Cache-Control": "no-cache",
    ...cors,
  });
  const backendSetCookie = backendResponse.headers.get("set-cookie");
  if (backendSetCookie) resHeaders.append("set-cookie", backendSetCookie);
  if (verifiedCookieValue) resHeaders.append("set-cookie", verifiedCookieValue);

  // For RAG-only backends, qa-bot-core gates the rating UI on the response
  // including `metadata.is_final_response: true` and `metadata.rating_target`.
  // Plain RAG services don't emit those fields, so inject them here. SSE
  // streams and non-RAG backends fall through unchanged.
  const upstreamContentType =
    backendResponse.headers.get("Content-Type") ?? "";
  const isJsonResponse = upstreamContentType.includes("application/json");
  const isRagBackend = getRagBackends().has(backendId);

  if (isJsonResponse && isRagBackend && backendResponse.ok) {
    // Read as text first so we can fall back to passing the raw body through
    // if it doesn't parse as JSON. Calling .json() and failing leaves the
    // body stream locked, which would prevent any fallback.
    const rawBody = await backendResponse.text();
    let parsed: Record<string, unknown> | null = null;
    try {
      parsed = JSON.parse(rawBody) as Record<string, unknown>;
    } catch (err) {
      console.warn(
        `RAG metadata injection: upstream "${backendId}" returned JSON ` +
          `Content-Type but unparseable body; passing through.`,
        err
      );
    }

    if (parsed && typeof parsed === "object") {
      const existingMetadata =
        (parsed.metadata as Record<string, unknown> | undefined) ?? {};
      parsed.metadata = {
        is_final_response: true,
        rating_target: "qa",
        ...existingMetadata,
      };
      return new Response(JSON.stringify(parsed), {
        status: backendResponse.status,
        headers: resHeaders,
      });
    }

    return new Response(rawBody, {
      status: backendResponse.status,
      headers: resHeaders,
    });
  }

  return new Response(backendResponse.body, {
    status: backendResponse.status,
    headers: resHeaders,
  });
}
