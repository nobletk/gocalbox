// Unit tests of the upload client against a fake server: node --test web/test
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { Upload, PartPool, Response, TransportError, states, missingParts, receivedParts, backoff, composite } from "../uploader.js";

const MiB = 1 << 20;

function fileOf(size, name = "f.bin", seed = 1) {
  const data = new Uint8Array(size);
  let x = seed;
  for (let i = 0; i < size; i++) {
    x = (x * 1103515245 + 12345) >>> 0;
    data[i] = x >>> 24;
  }
  return new File([data], name, { lastModified: 1700000000000 });
}

const sha = (buf) => createHash("sha256").update(Buffer.from(buf)).digest();

// FakeServer keeps sessions the way the engine does, and lets a test
// answer chosen calls differently through script(call) returning a
// Response, or undefined for the normal answer.
class FakeServer {
  constructor({ partSize = MiB, maxParallel = 4 } = {}) {
    this.partSize = partSize;
    this.maxParallel = maxParallel;
    this.sessions = new Map();
    this.calls = [];
    this.inflight = 0;
    this.peak = 0;
    this.next = 1;
    this.script = () => undefined;
    this.transport = this.transport.bind(this);
  }

  session(size, received = [], dataFrom = null) {
    const id = `u${this.next++}`;
    const partCount = Math.ceil(size / this.partSize);
    const s = { id, size, partCount, parts: new Map(), state: "receiving", key: null };
    for (const n of receivedParts(received)) {
      const start = (n - 1) * this.partSize;
      s.parts.set(n, sha(dataFrom.slice(start, Math.min(size, start + this.partSize))));
    }
    this.sessions.set(id, s);
    return s;
  }

  ranges(s) {
    const have = [...s.parts.keys()].sort((a, b) => a - b);
    const out = [];
    for (const n of have) {
      if (out.length && out[out.length - 1][1] === n - 1) out[out.length - 1][1] = n;
      else out.push([n, n]);
    }
    return out;
  }

  async transport(req) {
    const path = req.url.split("?")[0];
    const query = new URLSearchParams(req.url.split("?")[1] || "");
    const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
    const call = { path, query, body, headers: req.headers || {}, n: this.calls.length };
    this.calls.push(call);
    if (req.signal && req.signal.aborted) throw Object.assign(new Error("aborted"), { name: "AbortError" });
    const scripted = await this.script(call);
    if (scripted instanceof Error) throw scripted;
    if (scripted) return scripted;
    switch (path) {
      case "/api/upload/create": {
        for (const s of this.sessions.values()) {
          if (s.key === body.clientKey && s.state === "receiving") return new Response(200, this.created(s, true));
        }
        const s = this.session(body.size);
        s.key = body.clientKey;
        // The server made the session even if the client stopped waiting.
        if (req.signal && req.signal.aborted) throw Object.assign(new Error("aborted"), { name: "AbortError" });
        return new Response(201, this.created(s, false));
      }
      case "/api/upload/part": {
        const s = this.sessions.get(query.get("id"));
        if (!s) return err(404, "upload_not_found");
        const n = Number(query.get("n"));
        this.inflight++;
        this.peak = Math.max(this.peak, this.inflight);
        await new Promise((r) => setTimeout(r, 2));
        this.inflight--;
        if (req.signal && req.signal.aborted) throw Object.assign(new Error("aborted"), { name: "AbortError" });
        const h = sha(body);
        if (h.toString("hex") !== req.headers["Upload-Part-SHA256"]) return err(400, "checksum_mismatch");
        if (req.onProgress) req.onProgress(body.byteLength);
        s.parts.set(n, h);
        return new Response(200, { part: n, received: s.parts.size, partCount: s.partCount });
      }
      case "/api/upload/status": {
        const s = this.sessions.get(body.uploadId);
        if (!s) return err(404, "upload_not_found");
        const hashes = {};
        for (const n of body.hashes || []) hashes[String(n)] = s.parts.has(n) ? s.parts.get(n).toString("hex") : null;
        return new Response(200, { uploadId: s.id, state: s.state, size: s.size, partSize: this.partSize, partCount: s.partCount, received: this.ranges(s), hashes, result: s.result });
      }
      case "/api/upload/complete": {
        const s = this.sessions.get(body.uploadId);
        if (!s) return err(404, "upload_not_found");
        const missing = [];
        for (let n = 1; n <= s.partCount; n++) if (!s.parts.has(n)) missing.push(n);
        if (missing.length) return new Response(409, { error: { code: "parts_missing", message: "parts are missing" }, missing: missing.map((n) => [n, n]) });
        const all = Buffer.concat([...Array(s.partCount).keys()].map((i) => s.parts.get(i + 1)));
        if (sha(all).toString("hex") !== body.compositeSha256) return err(400, "checksum_mismatch");
        s.state = "completed";
        s.result = { path: "f.bin", name: "f.bin", size: s.size, compositeSha256: body.compositeSha256 };
        return new Response(201, s.result);
      }
      case "/api/upload/abort": {
        const s = this.sessions.get(body.uploadId);
        if (s) s.state = "aborted";
        return new Response(200, { uploadId: body.uploadId, state: "aborted" });
      }
      case "/api/upload":
        return new Response(201, { path: "f.bin", name: "f.bin", size: body.get("myFile").size });
      default:
        return err(404, "not_found");
    }
  }

  created(s, resumed) {
    return { uploadId: s.id, partSize: this.partSize, partCount: s.partCount, maxParallel: this.maxParallel, resumed, received: this.ranges(s) };
  }

  parts(id) {
    return this.calls.filter((c) => c.path === "/api/upload/part" && (!id || c.query.get("id") === id)).map((c) => Number(c.query.get("n")));
  }

  count(path) {
    return this.calls.filter((c) => c.path === path).length;
  }
}

function err(status, code, extra = {}, retryAfter = null) {
  return new Response(status, { error: { code, message: `${code} message` }, ...extra }, retryAfter);
}

const fast = { base: 1, max: 5, wait: 1, refused: 2, createMax: 5 };

function upload(server, file, opts = {}) {
  return new Upload(file, "dir", { transport: server.transport, timing: fast, ...opts });
}

test("a new upload sends every part in parallel and completes", async () => {
  const srv = new FakeServer();
  const u = upload(srv, fileOf(10 * MiB + 5));
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.deepEqual(srv.parts().sort((a, b) => a - b), [...Array(11).keys()].map((i) => i + 1));
  assert.ok(srv.peak > 1 && srv.peak <= 4, `peak ${srv.peak}`);
  assert.equal(u.sent, u.size);
  assert.equal(srv.count("/api/upload/status"), 0);
});

test("the parts go lowest first", async () => {
  const srv = new FakeServer({ maxParallel: 1 });
  await upload(srv, fileOf(4 * MiB)).start();
  assert.deepEqual(srv.parts(), [1, 2, 3, 4]);
});

test("an empty file completes with no parts", async () => {
  const srv = new FakeServer();
  const u = upload(srv, fileOf(0));
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.equal(srv.parts().length, 0);
});

test("a resumed upload checks what was sent and sends only the rest", async () => {
  const srv = new FakeServer();
  const file = fileOf(6 * MiB);
  const data = new Uint8Array(await file.arrayBuffer());
  const first = upload(srv, file);
  srv.script = (c) => (c.path === "/api/upload/part" && Number(c.query.get("n")) > 3 ? new TransportError("cut") : undefined);
  first.timing = { base: 1, max: 1, wait: 1 };
  const run = first.start();
  await new Promise((r) => setTimeout(r, 50));
  first.pause();
  await run;
  assert.equal(first.state, states.paused);
  srv.script = () => undefined;
  const id = [...srv.sessions.keys()][0];
  assert.ok(srv.sessions.get(id).parts.size >= 3);
  srv.calls = [];
  const again = upload(srv, file);
  await again.start();
  assert.equal(again.state, states.done, again.message);
  assert.deepEqual(srv.parts().sort(), [4, 5, 6]);
  const probe = srv.calls.find((c) => c.path === "/api/upload/status");
  assert.deepEqual(probe.body.hashes, [1, 3]);
  assert.ok(data.length);
});

test("a changed file starts over in a new session", async () => {
  const srv = new FakeServer();
  const file = fileOf(4 * MiB, "f.bin", 1);
  const other = fileOf(4 * MiB, "f.bin", 2);
  const s = srv.session(4 * MiB, [[1, 2]], new Uint8Array(await other.arrayBuffer()));
  const u = upload(srv, file, { session: { uploadId: s.id, dir: "dir", name: "f.bin", size: 4 * MiB, partSize: MiB, partCount: 4, received: [[1, 2]] } });
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.equal(s.state, "aborted");
  const fresh = [...srv.sessions.values()].find((x) => x.id !== s.id);
  assert.equal(fresh.state, "completed");
  assert.deepEqual(srv.parts(fresh.id).sort(), [1, 2, 3, 4]);
});

test("a chosen file of another size is refused", async () => {
  const srv = new FakeServer();
  const u = upload(srv, fileOf(3 * MiB), { session: { uploadId: "x", dir: "dir", name: "f.bin", size: 4 * MiB, partSize: MiB, partCount: 4, received: [] } });
  await u.start();
  assert.equal(u.state, states.failed);
  assert.equal(srv.calls.length, 0);
});

test("busy, too many requests and network errors are retried", async () => {
  const srv = new FakeServer();
  let left = 6;
  srv.script = (c) => {
    if (c.path !== "/api/upload/part" || left <= 0) return undefined;
    left--;
    return [err(503, "busy", {}, 0), err(429, "too_many_requests", {}, 0), new TransportError("reset")][left % 3];
  };
  const u = upload(srv, fileOf(2 * MiB));
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.equal(left, 0);
});

test("Retry-After sets the wait", () => {
  assert.equal(Math.floor(backoff(0, 2, 500, 30000, () => 0)), 2000);
  assert.equal(Math.floor(backoff(0, 100, 500, 30000, () => 0)), 30000);
  const d = backoff(3, null, 500, 30000, () => 1);
  assert.equal(d, 4000);
  assert.equal(backoff(20, null, 500, 30000, () => 0), 15000);
});

test("a session that ended asks for a login once and goes on", async () => {
  const srv = new FakeServer();
  let loggedIn = false;
  let asked = 0;
  srv.script = (c) => (c.path === "/api/upload/part" && !loggedIn ? err(401, "unauthenticated") : undefined);
  const u = upload(srv, fileOf(4 * MiB), {
    waitForLogin: () => {
      asked++;
      loggedIn = true;
      return Promise.resolve();
    },
  });
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.ok(asked >= 1);
});

test("a login refused pauses the upload", async () => {
  const srv = new FakeServer();
  srv.script = (c) => (c.path === "/api/upload/part" ? err(401, "unauthenticated") : undefined);
  const u = upload(srv, fileOf(MiB), {
    waitForLogin: () => {
      u.pause();
      return Promise.reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
    },
  });
  await u.start();
  assert.equal(u.state, states.paused);
});

test("a part whose data didn't match is read and sent again, at most 3 times", async () => {
  const srv = new FakeServer();
  let bad = 3;
  srv.script = (c) => (c.path === "/api/upload/part" && bad-- > 0 ? err(400, "checksum_mismatch") : undefined);
  const ok = upload(srv, fileOf(MiB));
  await ok.start();
  assert.equal(ok.state, states.done, ok.message);

  const srv2 = new FakeServer();
  srv2.script = (c) => (c.path === "/api/upload/part" ? err(400, "checksum_mismatch") : undefined);
  const no = upload(srv2, fileOf(MiB));
  await no.start();
  assert.equal(no.state, states.failed);
  assert.equal(srv2.parts().length, 4);
});

test("a part in progress elsewhere is waited for", async () => {
  const srv = new FakeServer();
  let busy = 2;
  srv.script = (c) => (c.path === "/api/upload/part" && busy-- > 0 ? err(409, "part_in_progress") : undefined);
  const u = upload(srv, fileOf(MiB));
  await u.start();
  assert.equal(u.state, states.done, u.message);
});

test("a part conflict starts the upload over", async () => {
  const srv = new FakeServer();
  let once = true;
  srv.script = (c) => {
    if (c.path === "/api/upload/part" && once) {
      once = false;
      return err(409, "part_conflict");
    }
    return undefined;
  };
  const u = upload(srv, fileOf(2 * MiB));
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.equal(srv.sessions.size, 2);
  assert.equal([...srv.sessions.values()][0].state, "aborted");
});

test("a file that keeps changing fails after the restarts", async () => {
  const srv = new FakeServer();
  srv.script = (c) => (c.path === "/api/upload/part" ? err(409, "part_conflict") : undefined);
  const u = upload(srv, fileOf(MiB));
  await u.start();
  assert.equal(u.state, states.failed);
  assert.equal(srv.sessions.size, 3);
});

test("parts the server lacks at completion are sent again", async () => {
  const srv = new FakeServer();
  let dropped = false;
  srv.script = (c) => {
    if (c.path === "/api/upload/complete" && !dropped) {
      dropped = true;
      [...srv.sessions.values()][0].parts.delete(2);
    }
    return undefined;
  };
  const u = upload(srv, fileOf(3 * MiB));
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.equal(srv.parts().filter((n) => n === 2).length, 2);
  assert.equal(u.sent, u.size);
});

test("completion waits for parts in flight and another tab's call", async () => {
  const srv = new FakeServer();
  let waits = 2;
  srv.script = (c) => (c.path === "/api/upload/complete" && waits-- > 0 ? err(409, waits ? "parts_in_flight" : "upload_completing") : undefined);
  const u = upload(srv, fileOf(MiB));
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.equal(srv.count("/api/upload/complete"), 3);
});

test("an unrecorded completion is done, with a warning, and not repeated", async () => {
  const srv = new FakeServer();
  srv.script = (c) => (c.path === "/api/upload/complete" ? err(500, "not_recorded", { result: { name: "f.bin", path: "dir/f.bin", size: MiB } }) : undefined);
  const u = upload(srv, fileOf(MiB));
  await u.start();
  assert.equal(u.state, states.done);
  assert.match(u.warning, /audit log/);
  assert.equal(srv.count("/api/upload/complete"), 1);
});

test("an internal error at completion is retried", async () => {
  const srv = new FakeServer();
  let once = true;
  srv.script = (c) => {
    if (c.path === "/api/upload/complete" && once) {
      once = false;
      return err(500, "internal");
    }
    return undefined;
  };
  const u = upload(srv, fileOf(MiB));
  await u.start();
  assert.equal(u.state, states.done, u.message);
});

test("an upload another tab completed is done", async () => {
  const srv = new FakeServer();
  srv.script = (c) => {
    if (c.path === "/api/upload/complete") {
      const s = [...srv.sessions.values()][0];
      s.state = "completed";
      s.result = { name: "f (1).bin", path: "dir/f (1).bin", size: MiB };
      return err(409, "upload_closed", { state: "completed" });
    }
    return undefined;
  };
  const u = upload(srv, fileOf(MiB));
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.equal(u.result.name, "f (1).bin");
});

test("an expired upload starts again", async () => {
  const srv = new FakeServer();
  let once = true;
  srv.script = (c) => {
    if (c.path === "/api/upload/part" && once) {
      once = false;
      [...srv.sessions.values()][0].state = "expired";
      return err(409, "upload_closed", { state: "expired" });
    }
    return undefined;
  };
  const u = upload(srv, fileOf(2 * MiB));
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.equal(srv.sessions.size, 2);
});

test("a session the server lost starts again", async () => {
  const srv = new FakeServer();
  let once = true;
  srv.script = (c) => {
    if (c.path === "/api/upload/part" && once) {
      once = false;
      return err(404, "upload_not_found");
    }
    return undefined;
  };
  const u = upload(srv, fileOf(MiB));
  await u.start();
  assert.equal(u.state, states.done, u.message);
});

test("a folder on another disk falls back to the single request", async () => {
  const srv = new FakeServer();
  srv.script = (c) => (c.path === "/api/upload/create" ? err(409, "cross_device") : undefined);
  const u = upload(srv, fileOf(MiB));
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.equal(u.resumable, false);
  const single = srv.calls.find((c) => c.path === "/api/upload");
  assert.equal(single.query.get("path"), "dir");
});

test("uploads turned off fall back to the single request", async () => {
  const srv = new FakeServer();
  srv.script = (c) => (c.path === "/api/upload/create" ? err(503, "uploads_unavailable") : undefined);
  const u = upload(srv, fileOf(10));
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.equal(srv.count("/api/upload"), 1);
});

test("a full disk pauses the upload", async () => {
  const srv = new FakeServer();
  srv.script = (c) => (c.path === "/api/upload/part" ? err(507, "insufficient_storage") : undefined);
  const u = upload(srv, fileOf(MiB));
  await u.start();
  assert.equal(u.state, states.paused);
  assert.match(u.message, /space/);
});

test("losing the right to upload fails the upload, which can then be discarded", async () => {
  const srv = new FakeServer();
  srv.script = (c) => (c.path === "/api/upload/part" ? err(403, "forbidden") : undefined);
  const u = upload(srv, fileOf(MiB));
  await u.start();
  assert.equal(u.state, states.failed);
  assert.ok(u.canDiscard);
  srv.script = () => undefined;
  await u.discard();
  assert.equal(u.state, states.canceled);
  assert.equal([...srv.sessions.values()][0].state, "aborted");
});

test("a folder that changed at completion aborts the session", async () => {
  for (const code of ["parent_not_found", "cross_device", "reserved_path", "permission_denied"]) {
    const srv = new FakeServer();
    srv.script = (c) => (c.path === "/api/upload/complete" ? err(409, code) : undefined);
    const u = upload(srv, fileOf(MiB));
    await u.start();
    assert.equal(u.state, states.failed, code);
    assert.match(u.message, /folder changed/);
    assert.equal([...srv.sessions.values()][0].state, "aborted", code);
  }
});

test("a lost session at completion asks the user to look before uploading again", async () => {
  const srv = new FakeServer();
  srv.script = (c) => (c.path === "/api/upload/complete" ? err(404, "upload_not_found") : undefined);
  const u = upload(srv, fileOf(MiB));
  await u.start();
  assert.equal(u.state, states.failed);
  assert.match(u.message, /look for f.bin/);
  assert.equal(srv.count("/api/upload/create"), 1);
});

test("too large for the folder's disk aborts", async () => {
  const srv = new FakeServer();
  srv.script = (c) => (c.path === "/api/upload/part" ? err(413, "too_large_for_volume") : undefined);
  const u = upload(srv, fileOf(MiB));
  await u.start();
  assert.equal(u.state, states.failed);
  assert.equal([...srv.sessions.values()][0].state, "aborted");
});

test("create waits out busy and too many uploads, doubling up to the cap", async () => {
  const srv = new FakeServer();
  let left = 4;
  const at = [];
  srv.script = (c) => {
    if (c.path !== "/api/upload/create") return undefined;
    at.push(Date.now());
    if (left-- <= 0) return undefined;
    return left % 2 ? err(429, "too_many_uploads") : err(503, "busy", {}, 0.01);
  };
  const seen = [];
  const u = new Upload(fileOf(MiB), "dir", { transport: srv.transport, timing: { ...fast, refused: 20, createMax: 60 }, onChange: (x) => seen.push(x.message) });
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.equal(srv.count("/api/upload/create"), 5);
  assert.ok(seen.some((m) => /too many uploads/.test(m)));
  const gaps = at.slice(1).map((t, i) => t - at[i]);
  assert.ok(gaps[0] >= 9, `first wait ${gaps[0]}`);
  assert.ok(gaps.every((g) => g <= 60 * 1.5 + 30), `waits ${gaps}`);
});

test("changes paused on the server are waited out", async () => {
  const srv = new FakeServer();
  let paused = 2;
  srv.script = (c) => (c.path === "/api/upload/complete" && paused-- > 0 ? err(503, "changes_paused") : undefined);
  const seen = [];
  const u = upload(srv, fileOf(MiB), { onChange: (x) => seen.push(x.state) });
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.ok(seen.includes(states.waiting));
});

test("pause and resume send only what is missing", async () => {
  const srv = new FakeServer({ maxParallel: 2 });
  let gate;
  const opened = new Promise((r) => (gate = r));
  let sent = 0;
  srv.script = async (c) => {
    if (c.path === "/api/upload/part" && ++sent === 3) {
      gate();
      await new Promise((r) => setTimeout(r, 30));
    }
    return undefined;
  };
  const u = upload(srv, fileOf(6 * MiB));
  const run = u.start();
  await opened;
  u.pause();
  await run;
  assert.equal(u.state, states.paused);
  const have = [...srv.sessions.values()][0].parts.size;
  assert.ok(have < 6);
  srv.script = () => undefined;
  const before = srv.parts().length;
  u.set(states.queued);
  await u.start();
  assert.equal(u.state, states.done, u.message);
  const after = srv.parts().slice(before);
  assert.equal(after.length, 6 - have);
});

test("cancel aborts the session", async () => {
  const srv = new FakeServer({ maxParallel: 1 });
  srv.script = async (c) => {
    if (c.path === "/api/upload/part") await new Promise((r) => setTimeout(r, 20));
    return undefined;
  };
  const u = upload(srv, fileOf(8 * MiB));
  const run = u.start();
  await new Promise((r) => setTimeout(r, 30));
  await u.cancel();
  await run;
  assert.equal(u.state, states.canceled);
  assert.equal([...srv.sessions.values()][0].state, "aborted");
});

test("ranges and composite", async () => {
  assert.deepEqual(receivedParts([[1, 3], [5, 5]]), [1, 2, 3, 5]);
  assert.deepEqual(missingParts(6, [[1, 3], [5, 5]]), [4, 6]);
  assert.deepEqual(missingParts(0, []), []);
  const a = new Uint8Array(32).fill(1);
  const b = new Uint8Array(32).fill(2);
  assert.equal(await composite([a, b]), createHash("sha256").update(Buffer.concat([a, b])).digest("hex"));
});

test("the pool shrinks once per window and grows back from the current window", () => {
  const p = new PartPool(4);
  const w = [];
  for (let i = 0; i < 4; i++) {
    p.inUse++;
    w.push(p.drops);
  }
  p.release(w[0], false, true);
  assert.equal(p.limit, 3);
  p.release(w[1], false, true);
  assert.equal(p.limit, 3, "a part from the old window drops it again");
  p.release(w[2], true, false);
  p.release(w[3], true, false);
  assert.equal(p.limit, 3, "parts from the old window grow it");
  for (let i = 0; i < 3; i++) {
    p.inUse++;
    p.release(p.drops, true, false);
  }
  assert.equal(p.limit, 4);
  for (let i = 0; i < 10; i++) {
    p.inUse++;
    p.release(p.drops, false, true);
  }
  assert.equal(p.limit, 1, "never below 1");
});

test("a part sent again after a refusal goes before parts not yet sent", async () => {
  const p = new PartPool(1);
  const order = [];
  const w = await p.acquire();
  const fresh = p.acquire().then((x) => order.push("fresh") && x);
  const again = p.acquire(undefined, true).then((x) => order.push("again") && x);
  await new Promise((r) => setTimeout(r, 5));
  p.release(w, false, false);
  const w2 = await again;
  p.release(w2, true, false);
  await fresh;
  assert.deepEqual(order, ["again", "fresh"]);
});

test("refused parts wait without a place, and the pool narrows", async () => {
  const srv = new FakeServer();
  let refusals = 3;
  srv.script = (c) => (c.path === "/api/upload/part" && refusals-- > 0 ? err(503, "busy", {}, 0.01) : undefined);
  const pool = new PartPool(4);
  const u = upload(srv, fileOf(8 * MiB), { pool });
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.equal(srv.parts().length, 8 + 3);
  assert.ok(pool.drops >= 1);
  assert.equal(pool.inUse, 0);
});

test("too many requests on a part is a refusal too", async () => {
  const srv = new FakeServer();
  let once = true;
  srv.script = (c) => {
    if (c.path === "/api/upload/part" && once) {
      once = false;
      return err(429, "too_many_requests");
    }
    return undefined;
  };
  const pool = new PartPool(4);
  const u = upload(srv, fileOf(2 * MiB), { pool });
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.equal(pool.drops, 1);
});

// FakeLocks is the Web Locks API's request, enough for slots.
class FakeLocks {
  constructor() {
    this.held = new Set();
    this.queues = new Map();
    this.peak = 0;
  }
  async request(name, opts, cb) {
    if (typeof opts === "function") {
      cb = opts;
      opts = {};
    }
    if (this.held.has(name)) {
      if (opts.ifAvailable) return cb(null);
      await new Promise((resolve, reject) => {
        const q = this.queues.get(name) || [];
        q.push(resolve);
        this.queues.set(name, q);
        if (opts.signal) opts.signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })), { once: true });
      });
    }
    this.held.add(name);
    this.peak = Math.max(this.peak, this.held.size);
    try {
      return await cb({ name });
    } finally {
      this.held.delete(name);
      const q = this.queues.get(name);
      if (q && q.length) {
        this.held.add(name);
        this.held.delete(name);
        q.shift()();
      }
    }
  }
}

test("two tabs share four slots", async () => {
  const srv = new FakeServer();
  const locks = new FakeLocks();
  srv.script = async (c) => {
    if (c.path === "/api/upload/part") await new Promise((r) => setTimeout(r, 5));
    return undefined;
  };
  const a = upload(srv, fileOf(12 * MiB, "a.bin", 3), { locks, pool: new PartPool(4) });
  const b = upload(srv, fileOf(12 * MiB, "b.bin", 4), { locks, pool: new PartPool(4) });
  await Promise.all([a.start(), b.start()]);
  assert.equal(a.state, states.done, a.message);
  assert.equal(b.state, states.done, b.message);
  assert.ok(srv.peak <= 4, `${srv.peak} parts at once`);
  assert.ok(srv.peak > 1);
});

test("a part that broke off is sent again", async () => {
  const srv = new FakeServer();
  let once = true;
  srv.script = (c) => {
    if (c.path === "/api/upload/part" && once) {
      once = false;
      return err(400, "part_aborted");
    }
    return undefined;
  };
  const u = upload(srv, fileOf(MiB));
  await u.start();
  assert.equal(u.state, states.done, u.message);
});

test("a folder gone while a part was sent stops the upload", async () => {
  const srv = new FakeServer();
  srv.script = (c) => (c.path === "/api/upload/part" ? err(400, "parent_not_found") : undefined);
  const u = upload(srv, fileOf(MiB));
  await u.start();
  assert.equal(u.state, states.failed);
  assert.ok(u.canDiscard);
});

test("a single-request upload that broke off is sent again", async () => {
  const srv = new FakeServer();
  let left = 2;
  srv.script = (c) => {
    if (c.path === "/api/upload/create") return err(409, "cross_device");
    if (c.path === "/api/upload" && left-- > 0) return left ? err(400, "upload_aborted") : new TransportError("reset");
    return undefined;
  };
  const u = upload(srv, fileOf(MiB));
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.equal(srv.count("/api/upload"), 3);
});

test("a checksum mismatch at completion starts over", async () => {
  const srv = new FakeServer();
  let once = true;
  srv.script = (c) => {
    if (c.path === "/api/upload/complete" && once) {
      once = false;
      return err(400, "checksum_mismatch");
    }
    return undefined;
  };
  const u = upload(srv, fileOf(MiB));
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.equal(srv.sessions.size, 2);
  assert.equal([...srv.sessions.values()][0].state, "aborted");
});

test("cancel or pause while a restart aborts the old session stops the upload", async () => {
  for (const action of ["cancel", "pause"]) {
    const srv = new FakeServer();
    let u;
    let once = true;
    srv.script = async (c) => {
      if (c.path === "/api/upload/part" && once) {
        once = false;
        return err(409, "part_conflict");
      }
      if (c.path === "/api/upload/abort") {
        if (action === "cancel") u.cancel();
        else u.pause();
        await new Promise((r) => setTimeout(r, 10));
      }
      return undefined;
    };
    u = upload(srv, fileOf(2 * MiB));
    await u.start();
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(u.state, action === "cancel" ? states.canceled : states.paused, action);
    assert.equal(srv.count("/api/upload/complete"), 0, action);
    assert.equal(srv.count("/api/upload/create"), 1, action);
  }
});

test("a part changed between pause and resume starts the upload over", async () => {
  const srv = new FakeServer({ maxParallel: 1 });
  const before = fileOf(4 * MiB, "f.bin", 5);
  let u;
  srv.script = (c) => {
    if (c.path === "/api/upload/complete" && u.file === before) {
      u.pause();
      return new TransportError("cut");
    }
    return undefined;
  };
  u = upload(srv, before);
  await u.start();
  assert.equal(u.state, states.paused);
  assert.equal([...srv.sessions.values()][0].parts.size, 4);
  const data = new Uint8Array(await before.arrayBuffer());
  data[2 * MiB + 10] ^= 0xff;
  u.file = new File([data], "f.bin", { lastModified: before.lastModified });
  u.set(states.queued);
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.equal(srv.sessions.size, 2);
  const placed = [...srv.sessions.values()][1];
  const all = Buffer.concat([1, 2, 3, 4].map((n) => placed.parts.get(n)));
  assert.equal(u.result.compositeSha256, sha(all).toString("hex"));
  assert.equal(placed.parts.get(3).toString("hex"), sha(data.subarray(2 * MiB, 3 * MiB)).toString("hex"));
});

test("cancel while create is answered aborts the session it made", async () => {
  const srv = new FakeServer();
  let u;
  srv.script = async (c) => {
    if (c.path === "/api/upload/create") {
      u.cancel();
      await new Promise((r) => setTimeout(r, 10));
    }
    return undefined;
  };
  u = upload(srv, fileOf(MiB));
  await u.start();
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(u.state, states.canceled);
  assert.deepEqual([...srv.sessions.values()].map((s) => s.state), ["aborted"]);
  assert.equal(srv.parts().length, 0);
});

test("changes paused on the server are reported for the banner", async () => {
  const srv = new FakeServer();
  let paused = 1;
  srv.script = (c) => (c.path === "/api/upload/complete" && paused-- > 0 ? err(503, "changes_paused") : undefined);
  let told = 0;
  const u = upload(srv, fileOf(MiB), { onPaused: () => told++ });
  await u.start();
  assert.equal(u.state, states.done, u.message);
  assert.equal(told, 1);
});
