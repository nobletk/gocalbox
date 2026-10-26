import { ApiError, files, post } from "./api.js";
import { askText, confirmDialog, notify, openDialog, showError } from "./dialogs.js";
import { FolderTree } from "./tree.js";
import { openViewer, viewable } from "./viewer.js";
import { el, clear, formatSize, joinPath, parentPath, baseName, fileURL, zipURL, kindOf, icons } from "./util.js";

export function pathFromHash(hash) {
  if (!hash.startsWith("#/")) return "";
  try {
    return hash.slice(2).split("/").filter(Boolean).map(decodeURIComponent).join("/");
  } catch {
    return "";
  }
}

export function hashFor(path) {
  return "#/" + path.split("/").filter(Boolean).map(encodeURIComponent).join("/");
}

// FileBrowser shows one folder at a time, with the folder tree beside it.
export class FileBrowser {
  constructor({ me, queue }) {
    this.me = me;
    this.queue = queue;
    this.path = "";
    this.entries = [];
    this.sort = { key: "name", dir: 1 };
    this.tree = new FolderTree({ onSelect: (p) => this.go(p) });
    this.crumbs = el("nav", { class: "crumbs", "aria-label": "Folder" });
    this.list = el("div", { class: "file-list" });
    this.status = el("p", { class: "muted list-status", role: "status" });
    this.fileInput = el("input", { type: "file", multiple: true, class: "hidden" });
    this.fileInput.addEventListener("change", () => {
      if (this.fileInput.files.length) this.queue.add(Array.from(this.fileInput.files), this.path);
      this.fileInput.value = "";
    });
    this.toolbar = el("div", { class: "toolbar" });
    this.sidebar = el("aside", { class: "sidebar" }, this.tree.element);
    this.main = el("section", { class: "content" }, this.crumbs, this.toolbar, this.status, this.list, this.fileInput);
    this.element = el("div", { class: "layout" }, this.sidebar, this.main);
    this.dropZone();
  }

  dropZone() {
    let depth = 0;
    const isFiles = (ev) => ev.dataTransfer && Array.from(ev.dataTransfer.types).includes("Files");
    this.main.addEventListener("dragenter", (ev) => {
      if (!isFiles(ev)) return;
      ev.preventDefault();
      depth++;
      this.main.classList.add("dropping");
    });
    this.main.addEventListener("dragover", (ev) => {
      if (isFiles(ev)) ev.preventDefault();
    });
    this.main.addEventListener("dragleave", () => {
      if (--depth <= 0) {
        depth = 0;
        this.main.classList.remove("dropping");
      }
    });
    this.main.addEventListener("drop", (ev) => {
      if (!isFiles(ev)) return;
      ev.preventDefault();
      depth = 0;
      this.main.classList.remove("dropping");
      const dropped = Array.from(ev.dataTransfer.items || [])
        .filter((it) => it.kind === "file" && !(it.webkitGetAsEntry && it.webkitGetAsEntry() && it.webkitGetAsEntry().isDirectory))
        .map((it) => it.getAsFile())
        .filter(Boolean);
      const skipped = (ev.dataTransfer.items ? ev.dataTransfer.items.length : 0) - dropped.length;
      if (skipped > 0) notify("Folders can't be uploaded by dropping them; drop the files inside them instead.", "warn");
      if (dropped.length) this.queue.add(dropped, this.path);
    });
  }

  async go(path) {
    const h = hashFor(path);
    if (location.hash !== h) {
      location.hash = h;
      return;
    }
    await this.show(path);
  }

  async show(path) {
    // A listing that arrives after a newer one was asked for is dropped:
    // its rows would build their paths from the newer folder.
    const seq = (this.seq = (this.seq || 0) + 1);
    this.path = path;
    this.renderCrumbs();
    this.renderToolbar();
    this.status.textContent = "Loading…";
    this.tree.reveal(path);
    try {
      const entries = await files(path);
      if (seq !== this.seq) return;
      this.entries = entries;
      this.status.textContent = "";
    } catch (err) {
      if (seq !== this.seq) return;
      this.entries = [];
      this.status.textContent = err instanceof ApiError && err.status === 404
        ? "This folder doesn't exist, or you may not see it."
        : `This folder can't be shown: ${err.message}`;
    }
    this.renderList();
    document.title = `${path ? baseName(path) : "All files"} – Gocalbox`;
  }

  refresh() {
    return this.show(this.path);
  }

  // uploaded refreshes the view when a file arrived in the folder shown.
  uploaded(dir) {
    if (dir === this.path) this.refresh();
  }

  renderCrumbs() {
    const parts = this.path ? this.path.split("/") : [];
    const items = [el("a", { href: hashFor(""), text: "All files" })];
    parts.forEach((part, i) => {
      items.push(el("span", { class: "sep", text: "/" }));
      const p = parts.slice(0, i + 1).join("/");
      items.push(i === parts.length - 1 ? el("span", { class: "current", text: part }) : el("a", { href: hashFor(p), text: part }));
    });
    clear(this.crumbs).append(...items);
  }

  renderToolbar() {
    const canWrite = this.me.role !== "viewer" || (this.me.bindings || []).some((b) =>
      b.role === "contributor" && (b.folder === "" || this.path === b.folder || this.path.startsWith(b.folder + "/")));
    clear(this.toolbar).append(
      el("button", { type: "button", class: "ghost folders-toggle", text: "Folders", onclick: () => this.element.classList.toggle("show-tree") }),
      canWrite ? el("button", { type: "button", class: "primary", text: "Upload files", onclick: () => this.fileInput.click() }) : null,
      canWrite ? el("button", { type: "button", text: "New folder", onclick: () => this.mkdir() }) : null,
      el("a", { class: "button", href: zipURL(this.path), text: "Download folder", download: "" }),
    );
  }

  sorted() {
    const { key, dir } = this.sort;
    return [...this.entries].sort((a, b) => {
      if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
      const c = key === "size" ? a.size - b.size : a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" });
      return c * dir || a.name.localeCompare(b.name);
    });
  }

  renderList() {
    const rows = this.sorted();
    if (!rows.length) {
      clear(this.list).appendChild(el("p", { class: "empty", text: this.status.textContent ? "" : "This folder is empty. Drop files here to upload them." }));
      return;
    }
    const header = (label, key) => {
      const active = this.sort.key === key;
      return el("th", { scope: "col", "aria-sort": active ? (this.sort.dir > 0 ? "ascending" : "descending") : "none" },
        el("button", {
          type: "button", class: "link", text: `${label}${active ? (this.sort.dir > 0 ? " ▲" : " ▼") : ""}`,
          onclick: () => {
            this.sort = { key, dir: active ? -this.sort.dir : 1 };
            this.renderList();
          },
        }));
    };
    const viewables = rows.filter(viewable);
    const table = el("table", { class: "files" },
      el("thead", {}, el("tr", {}, header("Name", "name"), header("Size", "size"), el("th", { scope: "col", class: "who", text: "Uploaded by" }), el("th", { scope: "col", class: "actions-col" }, el("span", { class: "sr-only", text: "Actions" })))),
      el("tbody", {}, rows.map((e) => this.row(e, viewables))),
    );
    clear(this.list).appendChild(table);
  }

  row(e, viewables) {
    const p = joinPath(this.path, e.name);
    const kind = e.isDir ? "dir" : kindOf(e.name);
    const name = el("button", { type: "button", class: "name link", title: e.name },
      el("span", { class: "icon-cell", "aria-hidden": "true", text: icons[kind] }),
      el("span", { class: "name-text", text: e.name }));
    name.addEventListener("click", () => {
      if (e.isDir) this.go(p);
      else if (viewable(e)) openViewer(this.path, viewables, viewables.indexOf(e));
      else location.assign(fileURL(p, true));
    });
    const actions = el("div", { class: "row-actions" },
      el("a", { class: "button small", href: e.isDir ? zipURL(p) : fileURL(p, true), download: e.isDir ? "" : e.name, text: "Download", title: e.isDir ? "Download as a zip archive" : "Download" }),
    );
    const allowed = new Set(e.actions || []);
    if (allowed.has("rename")) actions.append(el("button", { type: "button", class: "small", text: "Rename", onclick: () => this.rename(e) }));
    if (allowed.has("move")) actions.append(el("button", { type: "button", class: "small", text: "Move", onclick: () => this.move(e) }));
    if (allowed.has("delete")) actions.append(el("button", { type: "button", class: "small danger", text: "Delete", onclick: () => this.remove(e) }));
    return el("tr", { dataset: { name: e.name, kind } },
      el("td", { class: "name-col" }, name),
      el("td", { class: "size", text: e.isDir ? "" : formatSize(e.size) }),
      el("td", { class: "who muted", text: e.uploader || "" }),
      el("td", { class: "actions-col" }, actions),
    );
  }

  async mkdir() {
    const name = await askText({
      title: "New folder", label: "Name", confirm: "Create",
      validate: (v) => post("/api/fs/mkdir", { targetPath: this.path, name: v }).catch(reword),
    });
    if (name === null) return;
    await this.afterChange([this.path]);
  }

  async rename(e) {
    const p = joinPath(this.path, e.name);
    const name = await askText({
      title: `Rename ${e.isDir ? "folder" : "file"}`, label: "New name", value: e.name, confirm: "Rename", selectStem: !e.isDir,
      validate: async (v) => {
        if (v === e.name) return;
        await post("/api/fs/rename", { oldPath: p, newPath: joinPath(this.path, v) }).catch(reword);
      },
    });
    if (name === null || name === e.name) return;
    await this.afterChange([this.path]);
  }

  async move(e) {
    const from = joinPath(this.path, e.name);
    const target = await pickFolder(`Move ${e.name}`, this.path, from, e.isDir);
    if (target === null) return;
    try {
      await post("/api/fs/move", { oldPath: from, newPath: joinPath(target, e.name) });
      notify(`Moved ${e.name} to ${target || "All files"}.`, "ok");
    } catch (err) {
      showError(reworded(err), `Moving ${e.name}`);
    }
    await this.afterChange([this.path, target, ...(e.isDir ? [from] : [])]);
  }

  async remove(e) {
    const p = joinPath(this.path, e.name);
    const ok = await confirmDialog({
      title: `Delete ${e.isDir ? "folder" : "file"}`,
      message: e.isDir ? `Delete the folder ${e.name} and everything in it? This can't be undone.` : `Delete ${e.name}? This can't be undone.`,
      confirm: "Delete", danger: true,
    });
    if (!ok) return;
    try {
      await post("/api/fs/delete", { path: p });
    } catch (err) {
      showError(reworded(err), `Deleting ${e.name}`);
    }
    await this.afterChange([this.path]);
  }

  async afterChange(dirs) {
    await this.tree.refresh(...dirs);
    await this.refresh();
  }
}

const rewordings = {
  already_exists: "Something with this name is already there.",
  invalid_name: "This name isn't allowed. Names can't contain / or be . or ..",
  bound_folder: "This folder's access is set by an admin, so it can't be moved, renamed or deleted.",
  move_into_self: "A folder can't be moved into itself.",
  forbidden: "You may not do this here.",
  not_found: "It's gone: someone may have moved or deleted it. Refresh to see the folder as it is now.",
};

function reworded(err) {
  if (err instanceof ApiError && rewordings[err.code]) return new Error(rewordings[err.code]);
  return err;
}

function reword(err) {
  throw reworded(err);
}

// pickFolder asks for a target folder from a tree of its own. A folder
// can't be moved into itself, so its own subtree is refused.
async function pickFolder(title, start, moving, isDir) {
  let chosen = start;
  const current = el("p", { class: "muted" });
  const tree = new FolderTree({
    onSelect: (p) => {
      chosen = p;
      current.textContent = `Move to: ${p || "All files"}`;
    },
  });
  current.textContent = `Move to: ${start || "All files"}`;
  const p = openDialog({
    title,
    className: "picker",
    body: [el("div", { class: "picker-tree" }, tree.element), current],
    actions: [
      { label: "Cancel", value: null },
      { label: "Move here", value: true, submit: true, kind: "primary" },
    ],
    onSubmit: async () => {
      if (isDir && (chosen === moving || chosen.startsWith(moving + "/"))) throw new Error("A folder can't be moved into itself.");
      if (chosen === parentPath(moving)) throw new Error("It is in this folder already; choose another.");
      return chosen;
    },
  });
  tree.reveal(start);
  const result = await p;
  return typeof result === "string" ? result : null;
}
