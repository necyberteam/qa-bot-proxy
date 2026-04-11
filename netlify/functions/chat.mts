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

  // --- Turnstile validation ---
  // Resolve per-backend Turnstile keys. Each backend can have its own
  // Cloudflare widget so that ACCESS and NAIRR use separate domain
  // allowlists. Falls back to the global TURNSTILE_* env vars.
  const { siteKey, secretKey } = getTurnstileKeys(backendId);

  if (!secretKey) {
    console.error(`No Turnstile secret key for backend "${backendId}"`);
    return jsonResponse({ error: "Server misconfigured" }, 500, cors);
  }

  // When token is missing or invalid, return a challenge response that
  // qa-bot-core already understands (qa-flow.tsx), triggering the
  // visible Turnstile widget as fallback.
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
    // Return challenge so user can retry with visible widget
    if (siteKey) {
      return jsonResponse({ requires_turnstile: true, site_key: siteKey }, 200, cors);
    }
    return jsonResponse({ error: "Turnstile verification failed" }, 403, cors);
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
    return jsonResponse({ error: "Failed to reach backend" }, 502, cors);
  }

  // Build response headers — pass through content type and cookies
  const responseHeaders: Record<string, string> = {
    "Content-Type":
      backendResponse.headers.get("Content-Type") ?? "application/json",
    "Cache-Control": "no-cache",
    ...cors,
  };
  const setCookie = backendResponse.headers.get("set-cookie");
  if (setCookie) {
    responseHeaders["set-cookie"] = setCookie;
  }

  return new Response(backendResponse.body, {
    status: backendResponse.status,
    headers: responseHeaders,
  });
}
