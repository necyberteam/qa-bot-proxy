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

function getCorsHeaders(request: Request): Record<string, string> {
  const origin = request.headers.get("Origin") || "*";
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-API-KEY, X-Session-ID, X-Query-ID",
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

  const secretKey = process.env.TURNSTILE_SECRET_KEY;
  if (!secretKey) {
    console.error("TURNSTILE_SECRET_KEY not configured");
    return jsonResponse({ error: "Server misconfigured" }, 500, cors);
  }

  // TURNSTILE_SITE_KEY is the public site key — used in challenge responses
  // so qa-bot-core can show the visible Turnstile widget as a fallback.
  const siteKey = process.env.TURNSTILE_SITE_KEY;

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
  // When token is missing or invalid, return a challenge response that
  // qa-bot-core already understands (qa-flow.tsx:626), triggering the
  // visible Turnstile widget. This is the fallback when silent
  // verification hasn't produced a token yet.

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
