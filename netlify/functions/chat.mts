import type { Context } from "@netlify/functions";

const SITEVERIFY_URL =
  "https://challenges.cloudflare.com/turnstile/v0/siteverify";

interface SiteverifyResponse {
  success: boolean;
  "error-codes"?: string[];
}

/**
 * Parse ALLOWED_BACKENDS env var into an ID→URL map.
 * Format: "id1=https://url1,id2=https://url2"
 * The client sends the ID; the server resolves it to a URL.
 * This prevents SSRF — the client never controls the target URL.
 */
function getBackendMap(): Map<string, string> {
  const raw = process.env.ALLOWED_BACKENDS ?? "";
  const map = new Map<string, string>();
  for (const entry of raw.split(",")) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) {
      console.warn(`ALLOWED_BACKENDS: skipping malformed entry (no '='): "${trimmed}"`);
      continue;
    }
    const id = trimmed.slice(0, eqIdx).trim();
    const url = trimmed.slice(eqIdx + 1).trim();
    if (!id || !url) {
      console.warn(`ALLOWED_BACKENDS: skipping entry with empty id or url: "${trimmed}"`);
      continue;
    }
    map.set(id, url);
  }
  return map;
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

function jsonError(message: string, status: number): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-API-KEY, X-Session-ID, X-Query-ID",
};

function withCors(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(CORS_HEADERS)) {
    headers.set(key, value);
  }
  return new Response(response.body, {
    status: response.status,
    headers,
  });
}

export default async function handler(
  request: Request,
  context: Context
): Promise<Response> {
  // Handle CORS preflight
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  if (request.method !== "POST") {
    return withCors(jsonError("Method not allowed", 405));
  }

  const secretKey = process.env.TURNSTILE_SECRET_KEY;
  if (!secretKey) {
    console.error("TURNSTILE_SECRET_KEY not configured");
    return jsonError("Server misconfigured", 500);
  }

  // TURNSTILE_SITE_KEY is the public site key — used in challenge responses
  // so qa-bot-core can show the visible Turnstile widget as a fallback.
  const siteKey = process.env.TURNSTILE_SITE_KEY;

  const backendMap = getBackendMap();
  if (backendMap.size === 0) {
    console.error("ALLOWED_BACKENDS not configured");
    return jsonError("Server misconfigured", 500);
  }

  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return jsonError("Invalid JSON body", 400);
  }

  // Resolve backend ID to URL — client never sends a URL
  const backendId = body._backend as string | undefined;
  if (!backendId) {
    return jsonError("Missing _backend", 403);
  }
  const targetUrl = backendMap.get(backendId);
  if (!targetUrl) {
    return jsonError("Unknown backend: " + backendId, 403);
  }

  // --- Turnstile validation ---
  // When token is missing or invalid, return a challenge response that
  // qa-bot-core already understands (qa-flow.tsx:626), triggering the
  // visible Turnstile widget. This is the fallback when silent
  // verification hasn't produced a token yet.

  const turnstileToken = body.turnstile_token as string | undefined;

  if (!turnstileToken) {
    if (siteKey) {
      return new Response(
        JSON.stringify({ requires_turnstile: true, site_key: siteKey }),
        { status: 200, headers: { "Content-Type": "application/json", ...CORS_HEADERS } }
      );
    }
    return jsonError("Missing turnstile_token", 403);
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
    return jsonError("Turnstile service unavailable", 502);
  }

  if (!verification.success) {
    console.warn(
      "Turnstile validation failed:",
      verification["error-codes"]
    );
    // Return challenge so user can retry with visible widget
    if (siteKey) {
      return new Response(
        JSON.stringify({ requires_turnstile: true, site_key: siteKey }),
        { status: 200, headers: { "Content-Type": "application/json", ...CORS_HEADERS } }
      );
    }
    return jsonError("Turnstile verification failed", 403);
  }

  // Strip proxy-only fields before forwarding
  const { turnstile_token, _backend, ...forwardBody } = body;

  // Forward safe headers to backend.
  // Currently whitelists the headers qa-bot-core sends today.
  // If backends start requiring additional headers (Authorization,
  // custom x-* headers), expand this list or switch to forwarding
  // all headers except hop-by-hop ones (connection, keep-alive,
  // transfer-encoding, etc.).
  const forwardHeaders: Record<string, string> = {
    "Content-Type": "application/json",
  };
  for (const key of ["x-api-key", "x-session-id", "x-query-id", "cookie"]) {
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
    return jsonError("Failed to reach backend", 502);
  }

  // Build response headers — pass through content type and cookies
  const responseHeaders: Record<string, string> = {
    "Content-Type":
      backendResponse.headers.get("Content-Type") ?? "application/json",
    "Cache-Control": "no-cache",
  };
  const setCookie = backendResponse.headers.get("set-cookie");
  if (setCookie) {
    responseHeaders["set-cookie"] = setCookie;
  }

  return new Response(backendResponse.body, {
    status: backendResponse.status,
    headers: { ...responseHeaders, ...CORS_HEADERS },
  });
}
