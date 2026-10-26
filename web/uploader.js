// The resumable upload client. It has no DOM of its own: requests go
// through a transport, so it runs in a browser with xhrTransport and in
// tests with a fake one.

export const states = {
  queued: "queued",
  preparing: "preparing",
  uploading: "uploading",
  waiting: "waiting",
  completing: "completing",
  paused: "paused",
  done: "done",
  failed: "failed",
  canceled: "canceled",
};

const finalStates = new Set([states.done, states.failed, states.canceled]);

export class TransportError extends Error {
  constructor(message) {
    super(message);
    this.name = "TransportError";
  }
}

// A response the client reads; data is the parsed JSON body, or null.
export class Response {
  constructor(status, data, retryAfter = null) {
    this.status = status;
    this.data = data;
    this.retryAfter = retryAfter;
  }
  get code() {
    return (this.data && this.data.error && this.data.error.code) || "";
  }
  get message() {
    return (this.data && this.data.error && this.data.error.message) || `The server answered ${this.status}`;
  }
}

export function xhrTransport({ method, url, body, headers = {}, signal, onProgress }) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open(method, url);
    for (const [k, v] of Object.entries(headers)) xhr.setRequestHeader(k, v);
    if (onProgress) xhr.upload.onprogress = (ev) => onProgress(ev.loaded);
    xhr.onload = () => {
      let data = null;
      try {
        data = xhr.responseText ? JSON.parse(xhr.responseText) : null;
      } catch {
        data = null;
      }
      const ra = xhr.getResponseHeader("Retry-After");
      resolve(new Response(xhr.status, data, ra === null ? null : Number(ra)));
    };
    xhr.onerror = () => reject(new TransportError("The connection to the server failed"));
    xhr.ontimeout = xhr.onerror;
    xhr.onabort = () => reject(abortError());
    if (signal) {
      if (signal.aborted) {
        reject(abortError());
        return;
      }
      signal.addEventListener("abort", () => xhr.abort(), { once: true });
    }
    xhr.send(body === undefined ? null : body);
  });
}

function abortError() {
  const e = new Error("aborted");
  e.name = "AbortError";
  return e;
}

export function hex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

export async function clientKey(dir, file) {
  return hex(await sha256(new TextEncoder().encode(`${dir}\n${file.name}\n${file.size}\n${file.lastModified}`)));
}

// Part numbers are 1-based; ranges are inclusive [first, last] pairs.
export function receivedParts(ranges) {
  const out = [];
  for (const [a, b] of ranges || []) for (let n = a; n <= b; n++) out.push(n);
  return out;
}

export function missingParts(partCount, ranges) {
  const have = new Set(receivedParts(ranges));
  const out = [];
  for (let n = 1; n <= partCount; n++) if (!have.has(n)) out.push(n);
  return out;
}

export function composite(hashes) {
  const all = new Uint8Array(hashes.length * 32);
  hashes.forEach((h, i) => all.set(h, i * 32));
  return sha256(all).then(hex);
}

export function backoff(attempt, retryAfter, base = 500, max = 30000, random = Math.random) {
  if (retryAfter !== null && retryAfter !== undefined && Number.isFinite(retryAfter)) {
    return Math.min(max, retryAfter * 1000) + random() * 250;
  }
  const ceiling = Math.min(max, base * 2 ** attempt);
  return ceiling / 2 + random() * (ceiling / 2);
}

// spread is d times a random factor from 0.5 to 1.5, so that clients
// refused at the same moment don't all come back together.
export function spread(ms, random = Math.random) {
  return ms * (0.5 + random());
}

// PartPool bounds the parts in flight of a tab's uploads. It shrinks by one
// when the server refuses a part for its load, at most once per window (the
// parts sent since the last drop), and grows back by one after as many
// parts in a row as it holds, of those sent in the current window, were
// accepted. A part sent again after a refusal goes before parts not yet
// sent.
export class PartPool {
  constructor(cap) {
    this.cap = cap;
    this.limit = cap;
    this.inUse = 0;
    this.ahead = 0;
    this.drops = 0;
    this.run = 0;
    this.waiters = new Set();
  }

  wake() {
    for (const w of [...this.waiters]) w();
  }

  async acquire(signal, again = false) {
    if (again) this.ahead++;
    try {
      while (this.inUse >= this.limit || (!again && this.ahead > 0)) {
        if (signal && signal.aborted) throw abortError();
        await new Promise((resolve) => {
          const done = () => {
            this.waiters.delete(done);
            if (signal) signal.removeEventListener("abort", done);
            resolve();
          };
          this.waiters.add(done);
          if (signal) signal.addEventListener("abort", done, { once: true });
        });
      }
      if (signal && signal.aborted) throw abortError();
      this.inUse++;
      return this.drops;
    } finally {
      if (again) {
        this.ahead--;
        this.wake();
      }
    }
  }

  // release gives a place back; accepted says whether the server took the
  // part, and refused whether it refused it for its load.
  release(window, accepted, refused) {
    this.inUse--;
    if (refused) {
      this.run = 0;
      if (window === this.drops) {
        this.limit = Math.max(1, this.limit - 1);
        this.drops++;
      }
    } else if (accepted && window === this.drops) {
      if (++this.run >= this.limit && this.limit < this.cap) {
        this.limit++;
        this.run = 0;
      }
    }
    this.wake();
  }
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) return reject(abortError());
    const t = setTimeout(resolve, ms);
    if (signal) signal.addEventListener("abort", () => {
      clearTimeout(t);
      reject(abortError());
    }, { once: true });
  });
}

// Stop ends a run with a state and a message the user sees.
class Stop extends Error {
  constructor(state, message, { canDiscard = false } = {}) {
    super(message);
    this.state = state;
    this.canDiscard = canDiscard;
  }
}

class Restart extends Error {}

const retryable = new Set(["busy", "unavailable", "too_many_requests", "part_aborted", "network"]);
const loadRefusals = new Set(["busy", "too_many_requests", "too_many_uploads"]);

let nextID = 1;

export class Upload {
  // session, when given, is an unfinished upload from /api/upload/list to
  // go on with, instead of looking one up by the file's key.
  // pool is shared by a tab's uploads; locks is the browser's Web Locks,
  // through which its tabs share maxParallel slots.
  constructor(file, dir, { transport = xhrTransport, session = null, waitForLogin, onChange, onPaused, maxRestarts = 2, timing = {}, pool = null, locks } = {}) {
    this.id = nextID++;
    this.file = file;
    this.dir = dir;
    this.name = session ? session.name : file.name;
    this.size = file.size;
    this.transport = transport;
    this.waitForLogin = waitForLogin || (() => Promise.reject(new Stop(states.paused, "Log in again to go on.")));
    this.onChange = onChange || (() => {});
    this.onPaused = onPaused || (() => {});
    this.state = states.queued;
    this.message = "";
    this.warning = "";
    this.canDiscard = false;
    this.resumable = true;
    this.session = session ? { ...session, maxParallel: 4 } : null;
    this.hashes = [];
    this.doneBytes = 0;
    this.inflight = new Map();
    this.result = null;
    this.restarts = 0;
    this.maxRestarts = maxRestarts;
    this.timing = { base: 500, max: 30000, wait: 1000, refused: 1000, createMax: 8000, ...timing };
    this.pool = pool;
    this.locks = locks !== undefined ? locks : (typeof navigator !== "undefined" && navigator.locks) || null;
    this.rate = 0;
    this.controller = null;
    this.running = null;
  }

  get sent() {
    let n = this.doneBytes;
    for (const v of this.inflight.values()) n += v;
    return Math.min(n, this.size);
  }

  get finished() {
    return finalStates.has(this.state);
  }

  set(state, message = "") {
    this.state = state;
    this.message = message;
    if (state !== states.waiting) this.phase = state;
    this.onChange(this);
  }

  start() {
    if (this.running) return this.running;
    if (this.finished) return Promise.resolve();
    this.running = this.run().finally(() => {
      this.running = null;
    });
    return this.running;
  }

  pause() {
    if (this.finished || this.state === states.paused) return;
    this.pausing = true;
    if (this.controller) this.controller.abort();
    if (!this.running) this.set(states.paused);
  }

  async cancel() {
    if (this.finished) return;
    this.canceling = true;
    if (this.controller) this.controller.abort();
    if (this.running) await this.running.catch(() => {});
    if (this.session) await this.abortSession();
    this.inflight.clear();
    this.set(states.canceled);
  }

  // discard ends a failed upload that left its parts on the server.
  async discard() {
    if (this.running) return;
    await this.abortSession();
    this.set(states.canceled);
  }

  async run() {
    this.pausing = false;
    this.controller = new AbortController();
    // The file is read again on every run: parts sent before a pause may
    // have changed since.
    this.hashes = [];
    this.samples = [];
    try {
      for (;;) {
        try {
          await this.attempt();
          return;
        } catch (err) {
          if (!(err instanceof Restart)) throw err;
          if (this.pausing || this.canceling) throw abortError();
          if (++this.restarts > this.maxRestarts) throw new Stop(states.failed, "The file kept changing while it was uploaded.");
          await this.abortSession();
          if (this.pausing || this.canceling) {
            this.session = null;
            throw abortError();
          }
          this.session = null;
          this.hashes = [];
          this.doneBytes = 0;
          this.controller = new AbortController();
        }
      }
    } catch (err) {
      this.inflight.clear();
      if (this.canceling) return;
      if (err && err.name === "AbortError" && this.pausing) {
        this.set(states.paused);
        return;
      }
      if (err instanceof Stop) {
        this.canDiscard = err.canDiscard;
        this.set(err.state, err.message);
        return;
      }
      this.set(states.failed, err && err.message ? err.message : String(err));
    }
  }

  async attempt() {
    this.set(states.preparing);
    let fresh = false;
    if (!this.session) {
      const created = await this.create();
      if (created === null) return this.single();
      fresh = created;
    }
    const s = this.session;
    if (this.size !== s.size) throw new Stop(states.failed, "This file's size differs from the unfinished upload's.");
    if (!fresh) await this.refresh();
    this.doneBytes = receivedParts(s.received).reduce((sum, n) => sum + this.partLength(n), 0);
    this.set(states.uploading);
    await this.sendAll(missingParts(s.partCount, s.received));
    await this.finish();
  }

  async create() {
    const key = await clientKey(this.dir, this.file);
    for (let refusals = 0; ; refusals++) {
      // The request isn't cancelled with the run: a session the server
      // made must be known, so that a cancel can abort it.
      const res = await this.call("POST", "/api/upload/create", { dir: this.dir, name: this.file.name, size: this.size, clientKey: key }, { refusals: true, abortable: false });
      if (res.status === 200 || res.status === 201) {
        this.session = { ...res.data, dir: this.dir, name: this.file.name, size: this.size };
        if (this.controller.signal.aborted) throw abortError();
        return res.status === 201;
      }
      if (res.code === "cross_device" || res.code === "uploads_unavailable") return null;
      if (loadRefusals.has(res.code)) {
        const first = res.retryAfter !== null && Number.isFinite(res.retryAfter) ? res.retryAfter * 1000 : this.timing.refused;
        this.set(states.waiting, res.code === "too_many_uploads"
          ? "You have too many uploads open; waiting for one to end. Unfinished uploads can be discarded below."
          : "The server is busy; waiting.");
        await sleep(spread(Math.min(this.timing.createMax, first * 2 ** Math.min(refusals, 10))), this.controller.signal);
        continue;
      }
      throw new Stop(states.failed, res.message);
    }
  }

  // refresh reads which parts the server has, and checks the first and last
  // of them against the file, which may have changed since they were sent.
  async refresh() {
    const s = this.session;
    const have = receivedParts(s.received);
    const probe = have.length ? [...new Set([have[0], have[have.length - 1]])] : [];
    const res = await this.call("POST", "/api/upload/status", { uploadId: s.uploadId, hashes: probe });
    if (res.status !== 200) {
      if (res.code === "upload_not_found") throw new Restart();
      if (res.code === "upload_closed") return this.closed(res);
      throw new Stop(states.failed, res.message);
    }
    s.received = res.data.received || [];
    s.partSize = res.data.partSize;
    s.partCount = res.data.partCount;
    for (const n of probe) {
      const theirs = res.data.hashes && res.data.hashes[String(n)];
      if (!theirs) continue;
      if (hex(await this.digestPart(n)) !== theirs) throw new Restart();
    }
  }

  partLength(n) {
    const s = this.session;
    return Math.min(s.partSize, this.size - (n - 1) * s.partSize);
  }

  async digestPart(n) {
    const s = this.session;
    const start = (n - 1) * s.partSize;
    const h = await sha256(await this.file.slice(start, start + this.partLength(n)).arrayBuffer());
    this.hashes[n - 1] = h;
    return h;
  }

  // sendAll sends the parts lowest first, each once the pool has a place.
  async sendAll(todo) {
    const queue = [...todo].sort((a, b) => a - b);
    if (!this.pool) this.pool = new PartPool(this.session.maxParallel || 4);
    const pool = this.pool;
    const signal = this.controller.signal;
    let failure = null;
    const fail = (err) => {
      if (!failure) {
        failure = err;
        this.controller.abort();
      }
    };
    const tasks = [];
    for (const n of queue) {
      let window;
      try {
        window = await pool.acquire(signal);
      } catch (err) {
        fail(err);
        break;
      }
      if (failure) {
        pool.release(window, false, false);
        break;
      }
      tasks.push(this.partTask(n, window, pool).catch(fail));
    }
    await Promise.all(tasks);
    if (failure) throw failure;
  }

  // partTask sends one part, again after each refusal for the server's
  // load, holding no place in the pool while it waits.
  async partTask(n, window, pool) {
    for (;;) {
      let outcome;
      try {
        outcome = await this.sendPart(n);
      } catch (err) {
        pool.release(window, false, false);
        throw err;
      }
      if (outcome === true) {
        pool.release(window, true, false);
        return;
      }
      pool.release(window, false, true);
      this.set(states.waiting, "The server is busy; parts wait their turn.");
      const after = outcome.retryAfter !== null && Number.isFinite(outcome.retryAfter) ? outcome.retryAfter * 1000 : this.timing.refused;
      await sleep(spread(after), this.controller.signal);
      window = await pool.acquire(this.controller.signal, true);
    }
  }

  // sendPart returns true once the part is accepted, or the refusal's
  // Retry-After when the server refused it for its load.
  async sendPart(n) {
    const s = this.session;
    let mismatches = 0;
    for (;;) {
      const start = (n - 1) * s.partSize;
      const buf = await this.file.slice(start, start + this.partLength(n)).arrayBuffer();
      const h = await sha256(buf);
      this.hashes[n - 1] = h;
      this.inflight.set(n, 0);
      const res = await this.call("POST", `/api/upload/part?id=${encodeURIComponent(s.uploadId)}&n=${n}`, buf, {
        headers: { "Content-Type": "application/octet-stream", "Upload-Part-SHA256": hex(h) },
        onProgress: (loaded) => {
          this.inflight.set(n, loaded);
          this.tick();
        },
        waitOn: ["part_in_progress"],
        refusals: true,
        slot: s.maxParallel || 4,
      });
      this.inflight.delete(n);
      if (res.status === 200) {
        this.doneBytes += buf.byteLength;
        this.tick();
        return true;
      }
      if (res.code === "busy" || res.code === "too_many_requests") return { retryAfter: res.retryAfter };
      switch (res.code) {
        case "checksum_mismatch":
          if (++mismatches > 3) throw new Stop(states.failed, "The file couldn't be read consistently.");
          continue;
        case "part_conflict":
        case "upload_not_found":
          throw new Restart();
        case "upload_closed":
          return this.closed(res);
        case "forbidden":
        case "parent_not_found":
          throw new Stop(states.failed, "You may no longer upload to this folder.", { canDiscard: true });
        case "too_large_for_volume":
          await this.abortSession();
          throw new Stop(states.failed, "The disk of this folder can't hold a file this large.");
        default:
          throw new Stop(states.failed, res.message, { canDiscard: true });
      }
    }
  }

  async finish() {
    const s = this.session;
    this.set(states.completing);
    for (let n = 1; n <= s.partCount; n++) if (!this.hashes[n - 1]) await this.digestPart(n);
    const sum = await composite(this.hashes.slice(0, s.partCount));
    for (;;) {
      const res = await this.call("POST", "/api/upload/complete", { uploadId: s.uploadId, compositeSha256: sum }, {
        waitOn: ["parts_in_flight", "upload_completing", "already_exists"],
        retryOn: ["internal"],
      });
      if (res.status === 201) {
        this.done(res.data);
        return;
      }
      switch (res.code) {
        case "parts_missing": {
          this.set(states.uploading);
          const missing = receivedParts(res.data.missing);
          for (const n of missing) this.doneBytes -= Math.min(this.doneBytes, this.partLength(n));
          await this.sendAll(missing);
          this.set(states.completing);
          continue;
        }
        case "not_recorded":
        case "not_confirmed":
          this.warning = "The file is uploaded, but it isn't in the audit log yet.";
          this.done(res.data.result);
          return;
        case "checksum_mismatch":
          throw new Restart();
        case "upload_closed":
          return this.closed(res);
        case "cross_device":
        case "parent_not_found":
        case "reserved_path":
        case "permission_denied":
        case "forbidden":
          await this.abortSession();
          throw new Stop(states.failed, "The folder changed during the upload. Upload the file again, to this or another folder.");
        case "upload_not_found":
          throw new Stop(states.failed, `The upload may have finished already: look for ${this.name} in the folder before uploading it again.`);
        default:
          throw new Stop(states.failed, res.message, { canDiscard: true });
      }
    }
  }

  done(result) {
    this.result = result || null;
    this.doneBytes = this.size;
    this.inflight.clear();
    this.set(states.done, result && result.name && result.name !== this.name ? `Saved as ${result.name}` : "");
  }

  // closed handles an upload that has ended: completed by another tab, or
  // aborted, expired or failed, which means starting again.
  async closed(res) {
    const st = await this.call("POST", "/api/upload/status", { uploadId: this.session.uploadId, hashes: [] });
    if (st.status === 200 && st.data.result) {
      this.done(st.data.result);
      throw new Stop(states.done, this.message);
    }
    this.session = null;
    throw new Restart(res.message);
  }

  async abortSession() {
    if (!this.session || !this.session.uploadId) return;
    try {
      await this.transport({
        method: "POST", url: "/api/upload/abort", body: JSON.stringify({ uploadId: this.session.uploadId }),
        headers: { "Content-Type": "application/json" },
      });
    } catch {
      // The session expires by itself.
    }
  }

  // single sends the whole file in one request, which can't resume, for a
  // folder the engine can't take uploads into.
  async single() {
    this.resumable = false;
    this.set(states.uploading, "This upload can't resume if it is interrupted.");
    const form = new FormData();
    form.append("myFile", this.file);
    const url = this.dir ? `/api/upload?path=${encodeURIComponent(this.dir)}` : "/api/upload";
    const res = await this.call("POST", url, form, {
      onProgress: (loaded) => {
        this.inflight.set(0, loaded);
        this.tick();
      },
      retryOn: ["upload_aborted"],
      slot: 4,
    });
    this.inflight.clear();
    if (res.status === 201) {
      this.done(res.data);
      this.message = this.message || "Sent in one request, which couldn't have resumed.";
      return this.onChange(this);
    }
    if (res.status === 500 && res.data && res.data.result) {
      this.warning = "The file is uploaded, but it isn't in the audit log yet.";
      return this.done(res.data.result);
    }
    throw new Stop(states.failed, res.message);
  }

  // withSlot runs a request holding one of the max slots the browser's tabs
  // share, so that together they never send more than max bodies at once.
  async withSlot(max, signal, request) {
    const locks = this.locks;
    if (!locks) return request();
    for (let i = 0; i < max; i++) {
      const r = await locks.request(`gocalbox-upload-${i}`, { ifAvailable: true }, async (lock) => lock && { response: await request() });
      if (r) return r.response;
    }
    return locks.request(`gocalbox-upload-${Math.floor(Math.random() * max)}`, { signal }, request);
  }

  // call sends one request and retries what the protocol says to retry;
  // any other answer is returned for the caller to handle.
  // With refusals, a refusal for the server's load is returned too; with
  // slot, the request holds one of the browser's shared slots while it runs.
  async call(method, url, body, { headers, onProgress, waitOn = [], retryOn = [], refusals = false, slot = 0, abortable = true } = {}) {
    const isJSON = body !== undefined && body !== null && Object.getPrototypeOf(body) === Object.prototype;
    for (let attempt = 0; ; attempt++) {
      const signal = this.controller.signal;
      if (signal.aborted) throw abortError();
      let res;
      try {
        const send = () => this.transport({
          method, url, onProgress,
          signal: abortable ? signal : undefined,
          body: isJSON ? JSON.stringify(body) : body,
          headers: isJSON ? { "Content-Type": "application/json" } : headers,
        });
        res = slot ? await this.withSlot(slot, signal, send) : await send();
      } catch (err) {
        if (err.name === "AbortError") throw err;
        res = new Response(0, { error: { code: "network", message: err.message } });
      }
      if (res.status >= 200 && res.status < 300) {
        if (this.state === states.waiting) this.set(this.phase);
        return res;
      }
      const code = res.status === 0 ? "network" : res.code;
      if (refusals && loadRefusals.has(code)) return res;
      if (code === "unauthenticated") {
        this.set(states.waiting, "Waiting for you to log in again.");
        await this.waitForLogin();
        this.set(this.phase);
        continue;
      }
      if (code === "changes_paused") {
        this.onPaused();
        this.set(states.waiting, "The server has paused changes; waiting for it.");
        await sleep(backoff(Math.min(attempt, 6), res.retryAfter, this.timing.base, this.timing.max), signal);
        continue;
      }
      if (code === "insufficient_storage") {
        throw new Stop(states.paused, "The server is out of space. Resume once space is freed.");
      }
      if (waitOn.includes(code)) {
        await sleep(this.timing.wait, signal);
        continue;
      }
      if (retryable.has(code) || retryOn.includes(code) || res.status === 429 && code !== "too_many_uploads") {
        if (attempt > 0) this.set(states.waiting, res.status === 0 ? "The server can't be reached; retrying." : "The server is busy; retrying.");
        await sleep(backoff(Math.min(attempt, 8), res.retryAfter, this.timing.base, this.timing.max), signal);
        continue;
      }
      return res;
    }
  }

  tick() {
    const now = Date.now();
    const sent = this.sent;
    this.samples.push([now, sent]);
    while (this.samples.length > 2 && now - this.samples[0][0] > 5000) this.samples.shift();
    const [t0, b0] = this.samples[0];
    this.rate = now > t0 ? ((sent - b0) * 1000) / (now - t0) : 0;
    this.onChange(this);
  }
}
