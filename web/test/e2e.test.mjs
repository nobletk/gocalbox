// Browser tests of the UI against the real server, in Chromium through
// Playwright: node --test "web/test/*.test.mjs". They are skipped where
// Playwright or Go is missing.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
let chromium;
try {
  ({ chromium } = require("playwright"));
} catch {
  chromium = null;
}
let haveGo = true;
try {
  execFileSync("go", ["version"], { stdio: "ignore" });
} catch {
  haveGo = false;
}
const skip = !chromium || !haveGo ? "needs Playwright and Go" : false;

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const MiB = 1 << 20;
const password = "correct horse battery";

let dir;
let server;
let base;
let browser;
let code;
let log = "";

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
    s.on("error", reject);
  });
}

function bytes(size, seed = 7) {
  const b = Buffer.alloc(size);
  let x = seed;
  for (let i = 0; i < size; i += 4) {
    x = (x * 1103515245 + 12345) >>> 0;
    b.writeUInt32LE(x, i);
  }
  return b;
}

const sha = (b) => createHash("sha256").update(b).digest("hex");
const root = (...p) => path.join(dir, "root", ...p);

// wav makes a silent PCM file of the given seconds, which Chromium plays
// without codecs it may lack.
function wav(seconds) {
  const rate = 8000;
  const n = rate * seconds;
  const b = Buffer.alloc(44 + n);
  b.write("RIFF", 0);
  b.writeUInt32LE(36 + n, 4);
  b.write("WAVEfmt ", 8);
  b.writeUInt32LE(16, 16);
  b.writeUInt16LE(1, 20);
  b.writeUInt16LE(1, 22);
  b.writeUInt32LE(rate, 24);
  b.writeUInt32LE(rate, 28);
  b.writeUInt16LE(1, 32);
  b.writeUInt16LE(8, 34);
  b.write("data", 36);
  b.writeUInt32LE(n, 40);
  b.fill(128, 44);
  return b;
}

before(async () => {
  if (skip) return;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "gocalbox-e2e-"));
  fs.mkdirSync(path.join(dir, "root"));
  const bin = path.join(dir, process.platform === "win32" ? "gocalbox.exe" : "gocalbox");
  execFileSync("go", ["build", "-o", bin, "./cmd/gocalbox"], { cwd: repo, stdio: "inherit" });
  const port = await freePort();
  base = `http://localhost:${port}`;
  server = spawn(bin, [
    "-root", path.join(dir, "root"), "-state", path.join(dir, "state.db"), "-audit-log", path.join(dir, "audit.jsonl"),
    "-tls-dir", path.join(dir, "tls"), "-insecure-http", "-host", "localhost", "-port", String(port),
    "-min-password-length", "8", "-reauth-window", "3s", "-log-events=false",
  ], { stdio: ["ignore", "pipe", "pipe"] });
  const seen = (chunk) => {
    log += chunk;
  };
  server.stdout.on("data", seen);
  server.stderr.on("data", seen);
  for (let i = 0; i < 100 && !/setup=([A-Z0-9]+)/.test(log); i++) await new Promise((r) => setTimeout(r, 100));
  code = /setup=([A-Z0-9]+)/.exec(log)[1];
  browser = await chromium.launch();
});

after(async () => {
  if (skip) return;
  if (browser) await browser.close();
  if (server) server.kill();
  await new Promise((r) => setTimeout(r, 200));
  fs.rmSync(dir, { recursive: true, force: true });
});

// page opens a tab that fails the test on a script error, an alert, or a
// CSP report.
async function page(context) {
  const p = await context.newPage();
  p.problems = [];
  p.on("pageerror", (e) => p.problems.push(`page error: ${e.message}`));
  p.on("dialog", (d) => {
    p.problems.push(`dialog: ${d.message()}`);
    d.dismiss();
  });
  p.on("console", (m) => {
    if (m.type() === "error" && /Content Security Policy|Refused/.test(m.text())) p.problems.push(m.text());
  });
  return p;
}

async function login(p, user = "admin", pw = password) {
  await p.goto(base + "/");
  await p.fill("form input[autocomplete=username]", user);
  await p.fill("form input[type=password]", pw);
  await p.click("form button[type=submit]");
  await p.waitForSelector(".topbar");
}

async function openFolder(p, folder) {
  await p.goto(`${base}/#/${folder.split("/").map(encodeURIComponent).join("/")}`);
  await p.waitForSelector(".crumbs .current, .empty, table.files");
  await p.waitForFunction(() => !document.querySelector(".list-status").textContent);
}

async function upload(p, files) {
  const chooser = p.waitForEvent("filechooser");
  await p.click("text=Upload files");
  await (await chooser).setFiles(files);
}

async function waitDone(p, name, timeout = 60000) {
  await p.waitForSelector(`.upload.done[data-name="${name}"]`, { timeout });
}

function track(p) {
  const t = { inflight: 0, peak: 0, parts: [] };
  p.on("request", (r) => {
    if (r.url().includes("/api/upload/part")) {
      t.inflight++;
      t.peak = Math.max(t.peak, t.inflight);
      t.parts.push(new URL(r.url()).searchParams.get("n"));
    }
  });
  const done = (r) => {
    if (r.url().includes("/api/upload/part")) t.inflight--;
  };
  p.on("requestfinished", done);
  p.on("requestfailed", done);
  return t;
}

test("setup through the console's link, with the code taken out of the address", { skip }, async () => {
  const ctx = await browser.newContext();
  const p = await page(ctx);
  await p.goto(`${base}/#setup=${code}`);
  await p.waitForSelector("form");
  assert.equal(new URL(p.url()).hash, "");
  assert.equal(await p.inputValue("form input >> nth=0"), code);
  await p.fill("form input[autocomplete=username]", "admin");
  await p.fill("form input[type=password] >> nth=0", password);
  await p.fill("form input[type=password] >> nth=1", password);
  await p.click("form button[type=submit]");
  await p.waitForSelector("table.files");
  assert.deepEqual(await p.$$eval("table.files tbody tr", (rows) => rows.map((r) => r.dataset.name)), ["public", "users"]);
  assert.deepEqual(p.problems, []);
  await ctx.close();
});

test("a wrong password is refused, and a file link logs in and opens the file", { skip }, async () => {
  fs.writeFileSync(root("public", "note.txt"), "hello");
  const ctx = await browser.newContext();
  const p = await page(ctx);
  await p.goto(base + "/");
  await p.fill("form input[autocomplete=username]", "admin");
  await p.fill("form input[type=password]", "wrong password");
  await p.click("form button[type=submit]");
  await p.waitForSelector("text=Wrong username or password");
  await p.goto(`${base}/files/public/note.txt`);
  assert.match(p.url(), /\?next=/);
  await p.fill("form input[autocomplete=username]", "admin");
  await p.fill("form input[type=password]", password);
  await p.click("form button[type=submit]");
  await p.waitForURL(`${base}/files/public/note.txt`);
  assert.equal(await p.textContent("body"), "hello");
  await ctx.close();
});

test("folders and files: create, rename, move and delete", { skip }, async () => {
  const ctx = await browser.newContext();
  const p = await page(ctx);
  await login(p);
  await openFolder(p, "public");

  await p.click("text=New folder");
  await p.fill("dialog input", "albums");
  await p.click("dialog button[type=submit]");
  await p.waitForSelector('tr[data-name="albums"]');
  assert.ok(fs.statSync(root("public", "albums")).isDirectory());
  assert.ok(await p.$('.tree li[data-path="public/albums"]'));

  await p.click("text=New folder");
  await p.fill("dialog input", "albums");
  await p.click("dialog button[type=submit]");
  await p.waitForSelector("dialog .form-error:has-text('already there')");
  await p.click("dialog >> text=Cancel");

  await upload(p, [{ name: "a.txt", mimeType: "text/plain", buffer: Buffer.from("aaa") }]);
  await waitDone(p, "a.txt");
  await p.waitForSelector('tr[data-name="a.txt"]');

  await p.click('tr[data-name="a.txt"] >> text=Rename');
  await p.fill("dialog input", "b.txt");
  await p.click("dialog button[type=submit]");
  await p.waitForSelector('tr[data-name="b.txt"]');
  assert.equal(fs.readFileSync(root("public", "b.txt"), "utf8"), "aaa");

  await p.click('tr[data-name="b.txt"] >> text=Move');
  await p.click('dialog .tree li[data-path="public/albums"] > .tree-row .label');
  await p.click("dialog button[type=submit]");
  await p.waitForSelector('tr[data-name="b.txt"]', { state: "detached" });
  assert.equal(fs.readFileSync(root("public", "albums", "b.txt"), "utf8"), "aaa");

  await p.click('tr[data-name="albums"] .name');
  await p.waitForSelector('tr[data-name="b.txt"]');
  assert.equal(await p.textContent(".crumbs .current"), "albums");
  await p.click('tr[data-name="b.txt"] >> text=Delete');
  await p.click("dialog button[type=submit]");
  await p.waitForSelector('tr[data-name="b.txt"]', { state: "detached" });
  assert.ok(!fs.existsSync(root("public", "albums", "b.txt")));
  assert.deepEqual(p.problems, []);
  await ctx.close();
});

test("a large upload sends its parts in parallel and arrives whole", { skip }, async () => {
  const ctx = await browser.newContext();
  const p = await page(ctx);
  const t = track(p);
  await login(p);
  await openFolder(p, "public");
  // Parts answered slowly overlap however fast this machine hashes them.
  await p.route("**/api/upload/part*", async (route) => {
    await new Promise((r) => setTimeout(r, 500));
    await route.continue().catch(() => {});
  });
  const data = bytes(40 * MiB);
  await upload(p, [{ name: "big.bin", mimeType: "application/octet-stream", buffer: data }]);
  await waitDone(p, "big.bin");
  assert.equal(sha(fs.readFileSync(root("public", "big.bin"))), sha(data));
  assert.ok(t.peak > 1, `at most ${t.peak} part at once`);
  assert.ok(t.peak <= 4, `${t.peak} parts at once`);
  assert.deepEqual(p.problems, []);
  await ctx.close();
});

test("two tabs uploading at once keep to four bodies in flight", { skip }, async () => {
  const ctx = await browser.newContext();
  const t = { inflight: 0, peak: 0 };
  ctx.on("request", (r) => {
    if (r.url().includes("/api/upload/part")) t.peak = Math.max(t.peak, ++t.inflight);
  });
  const done = (r) => {
    if (r.url().includes("/api/upload/part")) t.inflight--;
  };
  ctx.on("requestfinished", done);
  ctx.on("requestfailed", done);
  await ctx.route("**/api/upload/part*", async (route) => {
    await new Promise((r) => setTimeout(r, 500));
    await route.continue().catch(() => {});
  });
  const tabs = [await page(ctx), await page(ctx)];
  await login(tabs[0]);
  for (const p of tabs) await openFolder(p, "public");
  const files = [bytes(40 * MiB, 21), bytes(40 * MiB, 22)];
  await Promise.all(tabs.map((p, i) => upload(p, [{ name: `tab${i}.bin`, mimeType: "application/octet-stream", buffer: files[i] }])));
  await Promise.all(tabs.map((p, i) => waitDone(p, `tab${i}.bin`)));
  assert.ok(t.peak <= 4, `${t.peak} bodies at once`);
  assert.ok(t.peak > 2, `at most ${t.peak} at once`);
  files.forEach((f, i) => assert.equal(sha(fs.readFileSync(root("public", `tab${i}.bin`))), sha(f)));
  await ctx.close();
});

test("after a reload, choosing the file again sends only the missing parts", { skip }, async () => {
  const ctx = await browser.newContext();
  const p = await page(ctx);
  await login(p);
  await openFolder(p, "public");
  const data = bytes(48 * MiB, 11);
  let done = 0;
  let letThrough = 2;
  // Two parts get through; the rest hang until the reload drops them.
  await p.route("**/api/upload/part*", async (route) => {
    if (letThrough-- > 0) await route.continue().catch(() => {});
  });
  p.on("requestfinished", (r) => {
    if (r.url().includes("/api/upload/part")) done++;
  });
  await upload(p, [{ name: "resume.bin", mimeType: "application/octet-stream", buffer: data }]);
  await p.waitForFunction(() => document.querySelector('.upload[data-name="resume.bin"] .state')?.textContent === "Uploading");
  while (done < 2) await new Promise((r) => setTimeout(r, 50));
  p.removeAllListeners("dialog");
  p.on("dialog", (d) => d.accept());
  await p.reload();
  await p.unroute("**/api/upload/part*");
  await p.waitForSelector('.upload.unfinished[data-name="resume.bin"]');

  const status = await p.evaluate(async () => (await (await fetch("/api/upload/list")).json()).uploads.find((u) => u.name === "resume.bin"));
  const have = status.received.reduce((n, [a, b]) => n + b - a + 1, 0);
  assert.ok(have >= 2 && have < status.partCount, `${have} of ${status.partCount}`);

  const t = track(p);
  const chooser = p.waitForEvent("filechooser");
  await p.click('.upload.unfinished[data-name="resume.bin"] >> text=Choose the file…');
  await (await chooser).setFiles([{ name: "resume.bin", mimeType: "application/octet-stream", buffer: data }]);
  await waitDone(p, "resume.bin");
  assert.equal(t.parts.length, status.partCount - have);
  assert.equal(sha(fs.readFileSync(root("public", "resume.bin"))), sha(data));
  await ctx.close();
});

test("an upload goes on after logging in again mid-way", { skip }, async () => {
  const ctx = await browser.newContext();
  const p = await page(ctx);
  await login(p);
  await openFolder(p, "public");
  const data = bytes(32 * MiB, 13);
  let parts = 0;
  let loggedOut = false;
  await p.route("**/api/upload/part*", async (route) => {
    if (++parts === 2 && !loggedOut) {
      loggedOut = true;
      const other = await ctx.request.post(`${base}/api/auth/logout`, { headers: { "Content-Type": "application/json" }, data: "{}" });
      assert.equal(other.status(), 204);
    }
    await route.continue().catch(() => {});
  });
  await upload(p, [{ name: "relogin.bin", mimeType: "application/octet-stream", buffer: data }]);
  await p.waitForSelector("dialog:has-text('Log in again')");
  await p.fill("dialog input[type=password]", password);
  await p.click("dialog button[type=submit]");
  await waitDone(p, "relogin.bin");
  assert.equal(sha(fs.readFileSync(root("public", "relogin.bin"))), sha(data));
  const sessions = await (await ctx.request.get(`${base}/api/upload/list`)).json();
  assert.equal(sessions.uploads.filter((u) => u.name === "relogin.bin" && u.state === "receiving").length, 0);
  await ctx.close();
});

test("without the engine, uploads fall back to one request and say they won't resume", { skip }, async () => {
  const ctx = await browser.newContext();
  const p = await page(ctx);
  await login(p);
  await openFolder(p, "public");
  await p.route("**/api/upload/create", (route) => route.fulfill({
    status: 503, contentType: "application/json",
    body: JSON.stringify({ error: { code: "uploads_unavailable", message: "resumable uploads are turned off" } }),
  }));
  const data = bytes(3 * MiB, 17);
  await upload(p, [{ name: "single.bin", mimeType: "application/octet-stream", buffer: data }]);
  await waitDone(p, "single.bin");
  assert.match(await p.textContent('.upload[data-name="single.bin"]'), /one request/);
  assert.equal(sha(fs.readFileSync(root("public", "single.bin"))), sha(data));
  await ctx.close();
});

test("audio plays in the viewer and seeks with a range request", { skip }, async () => {
  fs.writeFileSync(root("public", "tone.wav"), wav(20));
  const ctx = await browser.newContext();
  const p = await page(ctx);
  const ranges = [];
  p.on("request", (r) => {
    if (r.url().endsWith("/files/public/tone.wav") && r.headers().range) ranges.push(r.headers().range);
  });
  await login(p);
  await openFolder(p, "public");
  await p.click('tr[data-name="tone.wav"] .name');
  await p.waitForSelector("dialog.viewer audio");
  const seeked = await p.evaluate(() => new Promise((resolve, reject) => {
    const a = document.querySelector("dialog.viewer audio");
    a.muted = true;
    const go = () => {
      a.addEventListener("seeked", () => resolve(a.currentTime), { once: true });
      a.currentTime = 15;
    };
    if (a.readyState >= 1) go();
    else a.addEventListener("loadedmetadata", go, { once: true });
    a.addEventListener("error", () => reject(new Error("media error")), { once: true });
    setTimeout(() => reject(new Error("no seek")), 10000);
  }));
  assert.ok(Math.abs(seeked - 15) < 0.5, `at ${seeked}`);
  assert.ok(ranges.length > 0, "no range request");
  await p.click("dialog.viewer button[aria-label=Close]");
  assert.deepEqual(p.problems, []);
  await ctx.close();
});

test("a folder downloads as a zip archive", { skip }, async () => {
  fs.mkdirSync(root("public", "zipme", "inner"), { recursive: true });
  fs.writeFileSync(root("public", "zipme", "one.txt"), "1");
  fs.writeFileSync(root("public", "zipme", "inner", "two.txt"), "22");
  const ctx = await browser.newContext({ acceptDownloads: true });
  const p = await page(ctx);
  await login(p);
  await openFolder(p, "public/zipme");
  const dl = p.waitForEvent("download");
  await p.click(".toolbar >> text=Download folder");
  const d = await dl;
  assert.equal(d.suggestedFilename(), "zipme.zip");
  const file = path.join(dir, "zipme.zip");
  await d.saveAs(file);
  const z = fs.readFileSync(file);
  assert.equal(z.subarray(0, 2).toString(), "PK");
  for (const n of ["zipme/one.txt", "zipme/inner/two.txt"]) assert.ok(z.includes(Buffer.from(n)), n);
  await ctx.close();
});

test("names from the server are shown as text", { skip }, async () => {
  const evil = `<img src=x onerror="window.pwned=1">.txt`;
  fs.writeFileSync(root("public", evil), "x");
  const ctx = await browser.newContext();
  const p = await page(ctx);
  await login(p);
  await openFolder(p, "public");
  await p.waitForSelector(`tr[data-name='${evil}']`);
  assert.equal(await p.evaluate(() => window.pwned), undefined);
  assert.equal(await p.$("table.files img"), null);
  assert.deepEqual(p.problems, []);
  await ctx.close();
});

test("an invited contributor joins through the link and sees only their actions", { skip }, async () => {
  const adminCtx = await browser.newContext();
  const a = await page(adminCtx);
  await login(a);
  await a.goto(`${base}/#admin`);
  await a.click("text=Invite someone");
  await a.selectOption("dialog select", "contributor");
  await a.fill("dialog input >> nth=0", "carol");
  await a.click("dialog button[type=submit]");
  await a.waitForSelector("dialog textarea");
  const text = await a.inputValue("dialog textarea");
  const link = /(http\S+#invite=\S+)/.exec(text)[1];
  await a.click("dialog button[type=submit]");

  const ctx = await browser.newContext();
  const p = await page(ctx);
  await p.goto(link);
  await p.waitForSelector("text=Create your account");
  assert.equal(new URL(p.url()).hash, "");
  assert.equal(await p.inputValue("form input[autocomplete=username]"), "carol");
  await p.fill("form input[type=password] >> nth=0", password);
  await p.fill("form input[type=password] >> nth=1", password);
  await p.click("form button[type=submit]");
  await p.waitForSelector("table.files");
  assert.equal(await p.$(".main-nav a[data-route=admin]"), null);

  await openFolder(p, "public");
  const theirs = await p.$$eval('tr[data-name="note.txt"] .row-actions button', (b) => b.map((x) => x.textContent));
  assert.deepEqual(theirs, []);
  await upload(p, [{ name: "carol.txt", mimeType: "text/plain", buffer: Buffer.from("c") }]);
  await waitDone(p, "carol.txt");
  await p.waitForSelector('tr[data-name="carol.txt"]');
  const mine = await p.$$eval('tr[data-name="carol.txt"] .row-actions button', (b) => b.map((x) => x.textContent));
  assert.deepEqual(mine, ["Rename", "Move", "Delete"]);
  assert.equal(await p.textContent('tr[data-name="carol.txt"] td.who'), "carol");
  assert.deepEqual(p.problems, []);
  await ctx.close();
  await adminCtx.close();
});

test("an admin change after the password window asks for the password", { skip }, async () => {
  const ctx = await browser.newContext();
  const p = await page(ctx);
  await login(p);
  await p.goto(`${base}/#admin`);
  await p.waitForSelector('tr[data-user="carol"]');
  await new Promise((r) => setTimeout(r, 3500));
  await p.click('tr[data-user="carol"] >> text=Disable');
  await p.waitForSelector("dialog:has-text('Confirm your password')");
  await p.fill("dialog input[type=password]", password);
  await p.click("dialog button[type=submit]");
  await p.waitForSelector('tr[data-user="carol"] >> text=Disabled');
  await p.click('tr[data-user="carol"] >> text=Enable');
  await p.waitForSelector('tr[data-user="carol"] >> text=Active');
  await ctx.close();
});

test("a folder listing that arrives late is dropped", { skip }, async () => {
  fs.mkdirSync(root("public", "slowA"), { recursive: true });
  fs.mkdirSync(root("public", "fastB"), { recursive: true });
  fs.writeFileSync(root("public", "slowA", "only-in-A.txt"), "a");
  fs.writeFileSync(root("public", "fastB", "only-in-B.txt"), "b");
  const ctx = await browser.newContext();
  const p = await page(ctx);
  await login(p);
  await p.route("**/api/files?path=public%2FslowA", async (route) => {
    await new Promise((r) => setTimeout(r, 1500));
    await route.continue().catch(() => {});
  });
  await p.goto(`${base}/#/public/slowA`);
  await new Promise((r) => setTimeout(r, 200));
  await p.goto(`${base}/#/public/fastB`);
  await p.waitForSelector('tr[data-name="only-in-B.txt"]');
  await new Promise((r) => setTimeout(r, 2000));
  assert.deepEqual(await p.$$eval("table.files tbody tr", (rows) => rows.map((r) => r.dataset.name)), ["only-in-B.txt"]);
  assert.equal(await p.textContent(".crumbs .current"), "fastB");
  await ctx.close();
});

test("Escape doesn't answer the prompt to log in again", { skip }, async () => {
  const ctx = await browser.newContext();
  const p = await page(ctx);
  await login(p);
  await openFolder(p, "public");
  await ctx.request.post(`${base}/api/auth/logout`, { headers: { "Content-Type": "application/json" }, data: "{}" });
  await p.click('.tree li[data-path="public/fastB"] > .tree-row .label');
  await p.waitForSelector("dialog:has-text('Log in again')");
  await p.keyboard.press("Escape");
  await new Promise((r) => setTimeout(r, 300));
  assert.ok(await p.$("dialog:has-text('Log in again')"));
  await p.fill("dialog input[type=password]", password);
  await p.click("dialog button[type=submit]");
  await p.waitForSelector("dialog", { state: "detached" });
  await ctx.close();
});

test("a page restored from the back/forward cache checks its session", { skip }, async () => {
  const ctx = await browser.newContext();
  const p = await page(ctx);
  await login(p);
  await openFolder(p, "public");
  await ctx.request.post(`${base}/api/auth/logout`, { headers: { "Content-Type": "application/json" }, data: "{}" });
  await p.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true })));
  await p.waitForSelector("form input[autocomplete=username]");
  assert.equal(await p.$("table.files"), null);
  await ctx.close();
});

test("login refusals say what to do", { skip }, async () => {
  const ctx = await browser.newContext();
  const p = await page(ctx);
  const answers = [
    { status: 403, body: { error: { code: "password_disabled", message: "This account's password is disabled." } }, want: /reset link/ },
    { status: 429, body: { error: { code: "too_many_attempts", message: "Too many attempts." } }, want: /browser you have used/ },
  ];
  for (const a of answers) {
    await p.route("**/api/auth/login", (route) => route.fulfill({ status: a.status, contentType: "application/json", body: JSON.stringify(a.body) }));
    await p.goto(base + "/");
    await p.fill("form input[autocomplete=username]", "admin");
    await p.fill("form input[type=password]", "x");
    await p.click("form button[type=submit]");
    await p.waitForFunction(() => document.querySelector(".form-error").textContent.length > 0);
    assert.match(await p.textContent(".form-error"), a.want);
    await p.unroute("**/api/auth/login");
  }
  await ctx.close();
});

test("the banner shows while changes are paused", { skip }, async () => {
  const ctx = await browser.newContext();
  const p = await page(ctx);
  await p.route("**/api/status", (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ setupRequired: false, changesPaused: true }) }));
  await login(p);
  await p.waitForSelector(".banner:not(.hidden)");
  assert.match(await p.textContent(".banner"), /changes are paused/);
  await ctx.close();
});

test("notes and browsers are shown as text, and a password change lists the links it revoked", { skip }, async () => {
  const evil = "<img src=x onerror=window.pwned=1>";
  const ctx = await browser.newContext({ userAgent: `Mozilla/5.0 ${evil}` });
  const p = await page(ctx);
  await login(p);
  await p.goto(`${base}/#admin`);
  await p.click("text=Invite someone");
  await p.fill("dialog input >> nth=1", evil);
  await p.click("dialog button[type=submit]");
  await p.waitForSelector("dialog textarea");
  await p.click("dialog button[type=submit]");
  await p.waitForSelector(`td:has-text("${evil}")`);
  await p.goto(`${base}/#account`);
  await p.waitForSelector(`td span:has-text("${evil}")`);
  assert.equal(await p.evaluate(() => window.pwned), undefined);
  assert.equal(await p.$("img"), null);

  const change = async (from, to) => {
    await p.fill("form input >> nth=0", from);
    await p.fill("form input >> nth=1", to);
    await p.fill("form input >> nth=2", to);
    await p.click("form button[type=submit]");
    await p.waitForSelector("dialog:has-text('Password changed')");
  };
  await change(password, "another long password");
  assert.match(await p.textContent("dialog"), new RegExp(`Invite as contributor \\(${evil.replace(/[()]/g, "\\$&")}\\)`));
  await p.click("dialog button[type=submit]");
  await change("another long password", password);
  await p.click("dialog button[type=submit]");
  assert.deepEqual(p.problems, []);
  await ctx.close();
});

test("the admin and account pages fit a phone", { skip }, async () => {
  const ctx = await browser.newContext({ viewport: { width: 360, height: 740 }, isMobile: true, hasTouch: true });
  const p = await page(ctx);
  await login(p);
  for (const h of ["#admin", "#account", "#/public"]) {
    await p.goto(base + "/" + h);
    await p.waitForSelector("table");
    assert.ok(await p.evaluate(() => document.scrollingElement.scrollWidth <= window.innerWidth), `${h} scrolls sideways`);
  }
  await p.goto(base + "/#admin");
  await p.waitForSelector('tr[data-user="admin"] select');
  const w = await p.$eval('tr[data-user="admin"] select', (s) => s.getBoundingClientRect().width);
  assert.ok(w >= 100, `the role is ${w}px wide`);
  await ctx.close();
});

test("logging out ends the session and returns to the login page", { skip }, async () => {
  const ctx = await browser.newContext();
  const p = await page(ctx);
  await login(p);
  await p.click("text=Log out");
  await p.waitForSelector("form input[autocomplete=username]");
  const me = await ctx.request.get(`${base}/api/auth/me`);
  assert.equal(me.status(), 401);
  await ctx.close();
});

test("the UI's CSP allows no inline script", { skip }, async () => {
  const res = await fetch(base + "/");
  const csp = res.headers.get("content-security-policy");
  assert.match(csp, /script-src 'self';/);
  assert.doesNotMatch(csp, /unsafe-inline/);
});
