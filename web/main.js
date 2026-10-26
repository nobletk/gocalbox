import { ApiError, get, on, post } from "./api.js";
import { renderLogin, renderSetup, renderInvite, renderReset, relogin, revokedLinksList } from "./auth.js";
import { AdminPage, AccountPage } from "./admin.js";
import { alertDialog, confirmDialog, showError } from "./dialogs.js";
import { FileBrowser, pathFromHash } from "./files.js";
import { UploadQueue } from "./uploads.js";
import { el, clear, safeNext } from "./util.js";

const root = document.getElementById("app");
let me = null;
let queue = null;
let browser = null;
let view = null;
let banner = null;
let pausedPoll = null;
let loginPrompt = null;

function linkFromHash() {
  const m = /^#(setup|invite|reset)=([^&]+)$/.exec(location.hash);
  if (!m) return null;
  // The token leaves the address bar before anything else, so it isn't
  // shown, bookmarked or sent on; the browser's history still keeps it.
  history.replaceState(null, "", location.pathname + location.search);
  try {
    return { kind: m[1], token: decodeURIComponent(m[2]) };
  } catch {
    return null;
  }
}

async function boot() {
  const link = linkFromHash();
  let status;
  try {
    status = await get("/api/status", { quiet: true });
  } catch (err) {
    clear(root).appendChild(el("div", { class: "auth" }, el("div", { class: "auth-card" },
      el("h1", { text: "The server can't be reached" }),
      el("p", { class: "form-error", text: err.message }),
      el("button", { type: "button", class: "primary", text: "Try again", onclick: () => location.reload() }))));
    return;
  }
  if (status.setupRequired) return renderSetup(root, link && link.kind === "setup" ? link.token : "", enter);
  if (link && link.kind === "invite") return renderInvite(root, link.token, enter);
  if (link && link.kind === "reset") {
    return renderReset(root, link.token, async (res, revoked) => {
      await enter(res);
      const list = revokedLinksList(revoked);
      if (list) await alertDialog("Password set", [el("p", { text: "Your other sessions have ended." }), list]);
    });
  }
  try {
    me = await get("/api/auth/me", { quiet: true });
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) return renderLogin(root, enter);
    showError(err);
    return renderLogin(root, enter);
  }
  await enter(me, status);
}

async function enter(who, status) {
  const next = safeNext(location.search, location.origin);
  if (next) {
    location.replace(next);
    return;
  }
  if (location.search) history.replaceState(null, "", location.pathname + location.hash);
  me = who.id ? who : await get("/api/auth/me");
  if (!status || status.changesPaused === undefined) status = await get("/api/status", { quiet: true }).catch(() => ({}));
  shell();
  setPaused(Boolean(status.changesPaused));
  route();
  queue.loadUnfinished();
}

function shell() {
  queue = queue || new UploadQueue({ relogin: askLogin, onUploaded: (dir) => browser && browser.uploaded(dir) });
  browser = new FileBrowser({ me, queue });
  const nav = el("nav", { class: "main-nav" },
    el("a", { href: "#/", text: "Files", dataset: { route: "files" } }),
    me.role === "admin" ? el("a", { href: "#admin", text: "Users", dataset: { route: "admin" } }) : null,
    el("a", { href: "#account", text: "Account", dataset: { route: "account" } }),
  );
  banner = el("div", { class: "banner hidden", role: "alert" });
  view = el("main", { class: "view" });
  clear(root).append(
    el("header", { class: "topbar" },
      el("a", { class: "brand", href: "#/" }, el("span", { class: "logo", text: "📦" }), "Gocalbox"),
      nav,
      el("div", { class: "account-box" },
        el("span", { class: "muted", text: me.username }),
        el("button", { type: "button", class: "ghost", text: "Log out", onclick: logout })),
    ),
    banner,
    view,
  );
}

function route() {
  const h = location.hash;
  let page;
  let name = "files";
  if (h === "#admin" && me.role === "admin") {
    name = "admin";
    page = new AdminPage({ me });
  } else if (h === "#account") {
    name = "account";
    page = new AccountPage({ me, onSignedOut: () => location.replace("/") });
  }
  for (const a of root.querySelectorAll(".main-nav a")) a.classList.toggle("active", a.dataset.route === name);
  if (page) {
    clear(view).appendChild(page.element);
    page.show();
    return;
  }
  if (!view.contains(browser.element)) clear(view).appendChild(browser.element);
  browser.show(pathFromHash(h));
}

function setPaused(paused) {
  if (!banner) return;
  banner.classList.toggle("hidden", !paused);
  banner.textContent = paused
    ? "The server's audit log has failed, so changes are paused: files can be read, but not uploaded, moved or deleted until an admin restarts the server."
    : "";
  if (paused && !pausedPoll) {
    pausedPoll = setInterval(async () => {
      const s = await get("/api/status", { quiet: true }).catch(() => null);
      if (s && s.changesPaused === false) {
        clearInterval(pausedPoll);
        pausedPoll = null;
        setPaused(false);
      }
    }, 15000);
  }
}

// askLogin asks for the password once, however many requests found the
// session ended; the work in progress waits for the answer.
function askLogin() {
  if (!loginPrompt) {
    loginPrompt = relogin(me.username).then(async (ok) => {
      loginPrompt = null;
      if (!ok) {
        await post("/api/auth/logout", {}, { quiet: true }).catch(() => {});
        location.replace("/");
      }
      return ok;
    });
  }
  return loginPrompt;
}

async function logout() {
  if (queue && queue.uploads.some((u) => !u.finished && u.state !== "paused")) {
    const ok = await confirmDialog({ title: "Log out", message: "Uploads are still running. They stop, and you can go on with them after logging in again.", confirm: "Log out" });
    if (!ok) return;
  }
  for (const u of queue ? queue.uploads : []) u.pause();
  try {
    await post("/api/auth/logout", {}, { quiet: true });
  } catch (err) {
    if (!(err instanceof ApiError && err.status === 401)) showError(err, "Logging out");
  }
  location.replace("/");
}

on("unauthenticated", () => {
  if (me) askLogin().then((ok) => ok && route());
});
on("paused", () => setPaused(true));

window.addEventListener("hashchange", () => {
  if (me && view) route();
});

// A page restored from the back/forward cache may show what a session that
// has since ended could see; it is checked before it is used.
window.addEventListener("pageshow", async (ev) => {
  if (!ev.persisted || !me) return;
  try {
    await get("/api/auth/me", { quiet: true });
  } catch {
    clear(root);
    location.reload();
  }
});

boot();
