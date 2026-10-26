import { emit, get, post } from "./api.js";
import { confirmDialog, notify, showError } from "./dialogs.js";
import { Upload, PartPool, states, receivedParts } from "./uploader.js";
import { el, clear, formatSize, formatRate, formatDuration, formatDate } from "./util.js";

const labels = {
  queued: "Waiting",
  preparing: "Preparing",
  uploading: "Uploading",
  waiting: "Waiting",
  completing: "Finishing",
  paused: "Paused",
  done: "Done",
  failed: "Failed",
  canceled: "Canceled",
};

// UploadQueue runs one upload at a time, each with its parts in parallel,
// and shows them in a panel with the unfinished uploads of earlier visits.
export class UploadQueue {
  constructor({ relogin, onUploaded }) {
    this.uploads = [];
    this.unfinished = [];
    this.pool = new PartPool(4);
    this.relogin = relogin;
    this.onUploaded = onUploaded;
    this.loginWait = null;
    this.open = true;
    this.panel = el("section", { class: "uploads hidden", "aria-label": "Uploads" });
    this.drawScheduled = false;
    document.body.appendChild(this.panel);
    window.addEventListener("beforeunload", (ev) => {
      if (this.uploads.some((u) => !u.finished && u.state !== states.paused)) {
        ev.preventDefault();
        ev.returnValue = "";
      }
    });
  }

  // waitForLogin is shared by every upload, so a session that ended asks
  // for the password once.
  waitForLogin() {
    if (!this.loginWait) {
      this.loginWait = this.relogin().then((ok) => {
        this.loginWait = null;
        if (!ok) {
          for (const u of this.uploads) if (!u.finished) u.pause();
          throw Object.assign(new Error("aborted"), { name: "AbortError" });
        }
      });
    }
    return this.loginWait;
  }

  add(files, dir) {
    for (const file of files) this.push(new Upload(file, dir, this.options()));
    this.show();
    this.pump();
  }

  options(session) {
    return {
      session,
      pool: this.pool,
      onPaused: () => emit("paused", true),
      waitForLogin: () => this.waitForLogin(),
      onChange: (u) => this.changed(u),
    };
  }

  push(u) {
    this.uploads.push(u);
    this.draw();
  }

  changed(u) {
    if (u.state === states.done && !u.reported) {
      u.reported = true;
      if (u.warning) notify(`${u.name}: ${u.warning}`, "warn", 10000);
      this.onUploaded(u.dir);
    }
    this.draw();
  }

  pump() {
    if (this.uploads.some((u) => u.running)) return;
    const next = this.uploads.find((u) => u.state === states.queued);
    if (!next) return;
    next.start().then(() => {
      this.draw();
      this.pump();
    });
  }

  resume(u) {
    if (u.running) return;
    u.set(states.queued);
    this.pump();
  }

  async loadUnfinished() {
    try {
      const res = await get("/api/upload/list", { quiet: true });
      const tracked = new Set(this.uploads.map((u) => u.session && u.session.uploadId));
      this.unfinished = (res.uploads || []).filter((s) => s.state === "receiving" && !tracked.has(s.uploadId));
    } catch {
      this.unfinished = [];
    }
    if (this.unfinished.length) this.show();
    this.draw();
  }

  continueWith(s, file) {
    if (file.size !== s.size) {
      notify(`${file.name} has ${formatSize(file.size)}; the unfinished upload ${s.name} has ${formatSize(s.size)}. Choose the same file.`, "error", 10000);
      return;
    }
    const go = () => {
      this.unfinished = this.unfinished.filter((x) => x.uploadId !== s.uploadId);
      this.push(new Upload(file, s.dir, this.options(s)));
      this.pump();
    };
    if (file.name !== s.name) {
      confirmDialog({
        title: "Different name",
        message: `You chose ${file.name}, but the upload was of ${s.name}. The parts already sent are checked against this file, and the upload starts over if they differ. Go on?`,
        confirm: "Go on",
      }).then((ok) => ok && go());
      return;
    }
    go();
  }

  async discard(s) {
    const ok = await confirmDialog({ title: "Discard the upload", message: `Discard the unfinished upload of ${s.name}? The parts already sent are deleted.`, confirm: "Discard", danger: true });
    if (!ok) return;
    try {
      await post("/api/upload/abort", { uploadId: s.uploadId });
      this.unfinished = this.unfinished.filter((x) => x.uploadId !== s.uploadId);
      this.draw();
    } catch (err) {
      showError(err, "Discarding the upload");
    }
  }

  clearFinished() {
    this.uploads = this.uploads.filter((u) => !u.finished);
    this.draw();
  }

  show() {
    this.panel.classList.remove("hidden");
  }

  draw() {
    if (this.drawScheduled) return;
    this.drawScheduled = true;
    requestAnimationFrame(() => {
      this.drawScheduled = false;
      this.render();
    });
  }

  render() {
    const active = this.uploads.filter((u) => !u.finished).length;
    const toggle = el("button", { type: "button", class: "icon", "aria-expanded": String(this.open), "aria-label": this.open ? "Collapse" : "Expand", text: this.open ? "▾" : "▴" });
    toggle.addEventListener("click", () => {
      this.open = !this.open;
      this.render();
    });
    const head = el("header", {},
      el("h2", { text: active ? `Uploading ${active} of ${this.uploads.length}` : this.unfinished.length ? "Unfinished uploads" : "Uploads" }),
      this.uploads.some((u) => u.finished) ? el("button", { type: "button", class: "link", text: "Clear finished", onclick: () => this.clearFinished() }) : null,
      toggle,
      !active && !this.unfinished.length ? el("button", { type: "button", class: "icon", "aria-label": "Close", text: "×", onclick: () => this.panel.classList.add("hidden") }) : null,
    );
    clear(this.panel).appendChild(head);
    if (!this.open) return;
    const list = el("ul", { class: "upload-list" });
    for (const u of this.uploads) list.appendChild(this.row(u));
    for (const s of this.unfinished) list.appendChild(this.unfinishedRow(s));
    this.panel.appendChild(list);
  }

  row(u) {
    const pct = u.size ? Math.floor((u.sent / u.size) * 100) : u.state === states.done ? 100 : 0;
    const left = u.rate > 0 ? (u.size - u.sent) / u.rate : NaN;
    const detail = [
      `${formatSize(u.sent)} of ${formatSize(u.size)}`,
      u.state === states.uploading && u.rate ? formatRate(u.rate) : "",
      u.state === states.uploading && Number.isFinite(left) ? `${formatDuration(left)} left` : "",
    ].filter(Boolean).join(" · ");
    const actions = [];
    if (u.running && u.state !== states.completing) actions.push(button("Pause", () => u.pause()));
    if (!u.running && (u.state === states.paused || u.state === states.failed && u.resumable)) actions.push(button(u.state === states.failed ? "Retry" : "Resume", () => this.resume(u)));
    if (!u.finished) actions.push(button("Cancel", () => u.cancel().then(() => this.draw())));
    else if (u.state === states.failed && u.canDiscard) actions.push(button("Discard", () => u.discard().then(() => this.draw())));
    return el("li", { class: `upload ${u.state}`, dataset: { name: u.name } },
      el("div", { class: "upload-name" }, el("strong", { text: u.name }), el("span", { class: "muted", text: u.dir ? ` in ${u.dir}` : " in the top folder" })),
      el("progress", { max: 100, value: pct }),
      el("div", { class: "upload-detail" },
        el("span", { class: "state", text: labels[u.state] || u.state }),
        el("span", { class: "muted", text: detail }),
      ),
      u.message ? el("div", { class: "upload-message", text: u.message }) : null,
      el("div", { class: "upload-actions" }, actions),
    );
  }

  unfinishedRow(s) {
    const have = receivedParts(s.received).length;
    const pct = s.partCount ? Math.floor((have / s.partCount) * 100) : 0;
    const input = el("input", { type: "file", class: "hidden" });
    input.addEventListener("change", () => input.files[0] && this.continueWith(s, input.files[0]));
    return el("li", { class: "upload unfinished", dataset: { name: s.name } },
      el("div", { class: "upload-name" }, el("strong", { text: s.name }), el("span", { class: "muted", text: s.dir ? ` in ${s.dir}` : " in the top folder" })),
      el("progress", { max: 100, value: pct }),
      el("div", { class: "upload-detail" },
        el("span", { class: "state", text: "Interrupted" }),
        el("span", { class: "muted", text: `${pct}% of ${formatSize(s.size)} · kept until ${formatDate(s.expiresAt)}` }),
      ),
      el("div", { class: "upload-message", text: "Choose the same file again to go on from where it stopped." }),
      el("div", { class: "upload-actions" }, input, button("Choose the file…", () => input.click()), button("Discard", () => this.discard(s))),
    );
  }
}

function button(label, fn) {
  return el("button", { type: "button", class: "small", text: label, onclick: fn });
}
