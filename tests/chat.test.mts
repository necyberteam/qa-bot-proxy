import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// --- Helpers to build Request/Response-like objects for testing ---

function makeRequest(
  method: string,
  body?: Record<string, unknown>,
  headers?: Record<string, string>
): Request {
  const h = new Headers({ "Content-Type": "application/json", ...headers });
  return new Request("https://example.com/api/chat", {
    method,
    headers: h,
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
}

const fakeContext = { ip: "1.2.3.4" } as any;

// We'll dynamically import the handler after setting env vars
async function loadHandler() {
  // Clear module cache so env vars are re-read
  vi.resetModules();
  const mod = await import("../netlify/functions/chat.mts");
  return mod.default;
}

describe("chat proxy function", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = {
      ...originalEnv,
      // Per-backend Turnstile keys
      TURNSTILE_SECRET_KEYS: "nairr=nairr-secret,other=other-secret",
      TURNSTILE_SITE_KEYS: "nairr=nairr-site-key,other=other-site-key",
      ALLOWED_BACKENDS: "nairr=https://api.example.com/nairr/chat/,other=https://api.other.com/chat/",
    };
    // Mock global fetch for Turnstile siteverify and backend calls
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.restoreAllMocks();
  });

  it("rejects non-POST requests with 405", async () => {
    const handler = await loadHandler();
    const req = new Request("https://example.com/api/chat", { method: "GET" });
    const res = await handler(req, fakeContext);
    expect(res.status).toBe(405);
  });

  it("returns 500 when no Turnstile secret key exists for backend", async () => {
    delete process.env.TURNSTILE_SECRET_KEYS;
    delete process.env.TURNSTILE_SECRET_KEY;
    const handler = await loadHandler();
    const req = makeRequest("POST", { _backend: "nairr", turnstile_token: "tok" });
    const res = await handler(req, fakeContext);
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toContain("misconfigured");
  });

  it("returns 500 when ALLOWED_BACKENDS is missing", async () => {
    delete process.env.ALLOWED_BACKENDS;
    const handler = await loadHandler();
    const req = makeRequest("POST", { _backend: "nairr", turnstile_token: "tok" });
    const res = await handler(req, fakeContext);
    expect(res.status).toBe(500);
  });

  it("returns 400 for invalid JSON body", async () => {
    const handler = await loadHandler();
    const req = new Request("https://example.com/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not json",
    });
    const res = await handler(req, fakeContext);
    expect(res.status).toBe(400);
  });

  it("returns 403 when _backend ID is missing", async () => {
    const handler = await loadHandler();
    const req = makeRequest("POST", { turnstile_token: "tok", query: "hi" });
    const res = await handler(req, fakeContext);
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toContain("backend");
  });

  it("returns 403 when _backend ID is not in allowlist", async () => {
    const handler = await loadHandler();
    const req = makeRequest("POST", { _backend: "evil", turnstile_token: "tok" });
    const res = await handler(req, fakeContext);
    expect(res.status).toBe(403);
  });

  it("returns requires_turnstile challenge with per-backend site key when token is missing", async () => {
    const handler = await loadHandler();
    const req = makeRequest("POST", { _backend: "nairr", query: "hi" });
    const res = await handler(req, fakeContext);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.requires_turnstile).toBe(true);
    expect(body.site_key).toBe("nairr-site-key");
  });

  it("returns requires_turnstile challenge with per-backend site key when verification fails", async () => {
    const mockFetch = vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ success: false, "error-codes": ["invalid-input-response"] }), {
        headers: { "Content-Type": "application/json" },
      })
    );
    vi.stubGlobal("fetch", mockFetch);

    const handler = await loadHandler();
    const req = makeRequest("POST", {
      _backend: "nairr",
      turnstile_token: "bad-token",
      query: "hi",
    });
    const res = await handler(req, fakeContext);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.requires_turnstile).toBe(true);
    expect(body.site_key).toBe("nairr-site-key");
  });

  it("falls back to global TURNSTILE_SECRET_KEY when per-backend key is missing", async () => {
    // Remove per-backend keys, set global fallback
    process.env.TURNSTILE_SECRET_KEYS = "";
    process.env.TURNSTILE_SECRET_KEY = "global-secret";
    process.env.TURNSTILE_SITE_KEYS = "";
    process.env.TURNSTILE_SITE_KEY = "global-site-key";

    const mockFetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ success: true }), {
        headers: { "Content-Type": "application/json" },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ response: "ok" }), {
        headers: { "Content-Type": "application/json" },
      }));
    vi.stubGlobal("fetch", mockFetch);

    const handler = await loadHandler();
    const req = makeRequest("POST", {
      _backend: "nairr",
      turnstile_token: "tok",
      query: "hi",
    });
    const res = await handler(req, fakeContext);
    expect(res.status).toBe(200);

    // Verify global secret was used for validation
    const siteverifyBody = new URLSearchParams(mockFetch.mock.calls[0][1].body.toString());
    expect(siteverifyBody.get("secret")).toBe("global-secret");
  });

  it("uses different Turnstile keys for different backends", async () => {
    const handler = await loadHandler();

    // Request with no token for "nairr" should get nairr's site key
    const nairrReq = makeRequest("POST", { _backend: "nairr", query: "hi" });
    const nairrRes = await handler(nairrReq, fakeContext);
    const nairrBody = await nairrRes.json();
    expect(nairrBody.site_key).toBe("nairr-site-key");

    // Request with no token for "other" should get other's site key
    const otherReq = makeRequest("POST", { _backend: "other", query: "hi" });
    const otherRes = await handler(otherReq, fakeContext);
    const otherBody = await otherRes.json();
    expect(otherBody.site_key).toBe("other-site-key");
  });

  it("returns hard 403 when no site key exists for backend and token fails", async () => {
    delete process.env.TURNSTILE_SITE_KEYS;
    delete process.env.TURNSTILE_SITE_KEY;
    const mockFetch = vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ success: false, "error-codes": ["invalid-input-response"] }), {
        headers: { "Content-Type": "application/json" },
      })
    );
    vi.stubGlobal("fetch", mockFetch);

    const handler = await loadHandler();
    const req = makeRequest("POST", {
      _backend: "nairr",
      turnstile_token: "bad-token",
      query: "hi",
    });
    const res = await handler(req, fakeContext);
    expect(res.status).toBe(403);
  });

  it("proxies to correct backend URL on success and strips _backend and turnstile_token", async () => {
    const mockFetch = vi.fn()
      // First call: Turnstile siteverify
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json" },
        })
      )
      // Second call: backend proxy
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ response: "NAIRR is great" }), {
          headers: { "Content-Type": "application/json" },
        })
      );
    vi.stubGlobal("fetch", mockFetch);

    const handler = await loadHandler();
    const req = makeRequest(
      "POST",
      {
        _backend: "nairr",
        turnstile_token: "good-token",
        query: "What is NAIRR?",
        session_id: "sess-1",
      },
      { "x-api-key": "my-api-key" }
    );
    const res = await handler(req, fakeContext);
    expect(res.status).toBe(200);

    // Verify siteverify was called correctly
    const siteverifyCall = mockFetch.mock.calls[0];
    expect(siteverifyCall[0]).toBe("https://challenges.cloudflare.com/turnstile/v0/siteverify");
    const siteverifyBody = new URLSearchParams(siteverifyCall[1].body.toString());
    expect(siteverifyBody.get("secret")).toBe("nairr-secret");
    expect(siteverifyBody.get("response")).toBe("good-token");
    expect(siteverifyBody.get("remoteip")).toBe("1.2.3.4");

    // Verify backend was called with correct URL and cleaned body
    const backendCall = mockFetch.mock.calls[1];
    expect(backendCall[0]).toBe("https://api.example.com/nairr/chat/");
    const backendBody = JSON.parse(backendCall[1].body);
    expect(backendBody.query).toBe("What is NAIRR?");
    expect(backendBody.session_id).toBe("sess-1");
    expect(backendBody._backend).toBeUndefined();
    expect(backendBody.turnstile_token).toBeUndefined();

    // Verify API key header was forwarded
    expect(backendCall[1].headers["x-api-key"]).toBe("my-api-key");
  });

  it("resolves the 'other' backend ID correctly", async () => {
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json" },
        }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ response: "ok" }), {
          headers: { "Content-Type": "application/json" },
        })
      );
    vi.stubGlobal("fetch", mockFetch);

    const handler = await loadHandler();
    const req = makeRequest("POST", {
      _backend: "other",
      turnstile_token: "tok",
      query: "hi",
    });
    const res = await handler(req, fakeContext);
    expect(res.status).toBe(200);
    expect(mockFetch.mock.calls[1][0]).toBe("https://api.other.com/chat/");
  });

  it("returns 502 when Turnstile siteverify returns non-JSON", async () => {
    const mockFetch = vi.fn().mockResolvedValueOnce(
      new Response("<!DOCTYPE html><html>error page</html>", {
        headers: { "Content-Type": "text/html" },
      })
    );
    vi.stubGlobal("fetch", mockFetch);

    const handler = await loadHandler();
    const req = makeRequest("POST", {
      _backend: "nairr",
      turnstile_token: "tok",
      query: "hi",
    });
    const res = await handler(req, fakeContext);
    expect(res.status).toBe(502);
    const body = await res.json();
    expect(body.error).toContain("Turnstile");
  });

  it("returns 502 when Turnstile siteverify fetch fails", async () => {
    const mockFetch = vi.fn().mockRejectedValueOnce(new Error("Network error"));
    vi.stubGlobal("fetch", mockFetch);

    const handler = await loadHandler();
    const req = makeRequest("POST", {
      _backend: "nairr",
      turnstile_token: "tok",
      query: "hi",
    });
    const res = await handler(req, fakeContext);
    expect(res.status).toBe(502);
    const body = await res.json();
    expect(body.error).toContain("Turnstile");
  });

  it("returns 502 when backend fetch fails", async () => {
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json" },
        }))
      .mockRejectedValueOnce(new Error("Connection refused"));
    vi.stubGlobal("fetch", mockFetch);

    const handler = await loadHandler();
    const req = makeRequest("POST", {
      _backend: "nairr",
      turnstile_token: "tok",
      query: "hi",
    });
    const res = await handler(req, fakeContext);
    expect(res.status).toBe(502);
    const body = await res.json();
    expect(body.error).toContain("backend");
  });

  it("forwards cookies to backend and returns set-cookie from backend", async () => {
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json" },
        }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ response: "ok" }), {
          headers: {
            "Content-Type": "application/json",
            "Set-Cookie": "session=abc123; Path=/; HttpOnly",
          },
        })
      );
    vi.stubGlobal("fetch", mockFetch);

    const handler = await loadHandler();
    const req = makeRequest(
      "POST",
      { _backend: "nairr", turnstile_token: "tok", query: "hi" },
      { cookie: "existing=val" }
    );
    const res = await handler(req, fakeContext);
    expect(res.status).toBe(200);

    // Verify cookie was forwarded to backend
    const backendCall = mockFetch.mock.calls[1];
    expect(backendCall[1].headers["cookie"]).toBe("existing=val");

    // Verify set-cookie was passed back to client
    expect(res.headers.get("set-cookie")).toBe("session=abc123; Path=/; HttpOnly");
  });

  it("streams SSE responses through", async () => {
    const sseBody = "event: token\ndata: {\"content\":\"Hello\"}\n\nevent: done\ndata: {}\n\n";
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json" },
        }))
      .mockResolvedValueOnce(
        new Response(sseBody, {
          headers: { "Content-Type": "text/event-stream" },
        })
      );
    vi.stubGlobal("fetch", mockFetch);

    const handler = await loadHandler();
    const req = makeRequest("POST", {
      _backend: "nairr",
      turnstile_token: "tok",
      query: "hi",
    });
    const res = await handler(req, fakeContext);
    expect(res.headers.get("Content-Type")).toBe("text/event-stream");
    const text = await res.text();
    expect(text).toContain("event: token");
  });
});
