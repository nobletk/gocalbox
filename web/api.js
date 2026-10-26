export class ApiError extends Error {
  constructor(status, body, headers) {
    const e = body && body.error;
    super((e && e.message) || `Request failed (${status})`);
    this.status = status;
    this.code = (e && e.code) || (status === 0 ? "network" : "unknown");
    this.body = body || {};
    this.retryAfter = retryAfterSeconds(headers && headers.get ? headers.get("Retry-After") : null);
  }
}

export function retryAfterSeconds(v) {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  if (Number.isFinite(n) && n >= 0) return n;
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : Math.max(0, (t - Date.now()) / 1000);
}

const listeners = { unauthenticated: new Set(), paused: new Set() };

export function on(event, fn) {
  listeners[event].add(fn);
  return () => listeners[event].delete(fn);
}

export function emit(event, detail) {
  for (const fn of listeners[event]) fn(detail);
}

export async function request(method, path, body, { signal, quiet = false } = {}) {
  const init = { method, headers: {}, credentials: "same-origin", signal };
  if (body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  let resp;
  try {
    resp = await fetch(path, init);
  } catch (err) {
    if (err && err.name === "AbortError") throw err;
    throw new ApiError(0, { error: { code: "network", message: "The server can't be reached" } });
  }
  let data = null;
  if (resp.status !== 204) {
    const text = await resp.text();
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = null;
      }
    }
  }
  if (!resp.ok) {
    const err = new ApiError(resp.status, data, resp.headers);
    if (!quiet && err.code === "unauthenticated") emit("unauthenticated", err);
    if (!quiet && err.code === "changes_paused") emit("paused", true);
    throw err;
  }
  return data;
}

export const get = (path, opts) => request("GET", path, undefined, opts);
export const post = (path, body = {}, opts) => request("POST", path, body, opts);

// withReauth runs an admin change; when the server asks for the password
// again, it asks for it through confirmPassword and tries once more.
export async function withReauth(fn, confirmPassword) {
  try {
    return await fn();
  } catch (err) {
    if (!(err instanceof ApiError) || err.code !== "reauth_required") throw err;
    const ok = await confirmPassword();
    if (!ok) throw err;
    return fn();
  }
}

export function files(dir) {
  return get(`/api/files?path=${encodeURIComponent(dir)}`);
}
