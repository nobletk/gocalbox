import { files } from "./api.js";
import { el, clear, joinPath } from "./util.js";

// FolderTree is a tree of folders whose children load when a folder is
// first opened. onSelect is called with a folder's path.
export class FolderTree {
  constructor({ onSelect, rootLabel = "All files" }) {
    this.onSelect = onSelect;
    this.root = { path: "", name: rootLabel, children: null, open: true };
    this.selected = "";
    this.element = el("ul", { class: "tree", role: "tree" });
  }

  async load(node) {
    try {
      const entries = await files(node.path);
      const old = new Map((node.children || []).map((c) => [c.name, c]));
      node.children = entries.filter((e) => e.isDir).map((e) => old.get(e.name) || { path: joinPath(node.path, e.name), name: e.name, children: null, open: false });
      node.error = false;
    } catch {
      node.children = [];
      node.error = true;
    }
  }

  find(path) {
    let node = this.root;
    if (!path) return node;
    for (const part of path.split("/")) {
      const next = (node.children || []).find((c) => c.name === part);
      if (!next) return null;
      node = next;
    }
    return node;
  }

  // reveal opens every folder down to path, loading what isn't loaded yet.
  async reveal(path) {
    const seq = (this.seq = (this.seq || 0) + 1);
    this.selected = path;
    let node = this.root;
    if (!node.children) await this.load(node);
    node.open = true;
    if (path) {
      for (const part of path.split("/")) {
        const next = (node.children || []).find((c) => c.name === part);
        if (!next) break;
        node = next;
        if (!node.children) await this.load(node);
        node.open = true;
      }
    }
    if (seq === this.seq) this.render();
  }

  // refresh reloads the folders whose children may have changed.
  async refresh(...paths) {
    for (const p of new Set(paths)) {
      const node = this.find(p);
      if (node && node.children) await this.load(node);
    }
    this.render();
  }

  async toggle(node) {
    node.open = !node.open;
    if (node.open && !node.children) await this.load(node);
    this.render();
  }

  render() {
    clear(this.element).appendChild(this.item(this.root, 0));
  }

  item(node, depth) {
    const hasKids = node.children === null || node.children.length > 0;
    const caret = el("button", {
      type: "button", class: "caret", tabIndex: -1,
      "aria-label": node.open ? `Close ${node.name}` : `Open ${node.name}`,
      text: hasKids ? (node.open ? "▾" : "▸") : "",
      disabled: !hasKids,
    });
    caret.addEventListener("click", (ev) => {
      ev.stopPropagation();
      this.toggle(node);
    });
    const label = el("button", { type: "button", class: "label", text: node.name, title: node.path || node.name });
    label.addEventListener("click", () => {
      this.selected = node.path;
      if (!node.open) this.toggle(node);
      else this.render();
      this.onSelect(node.path);
    });
    const row = el("div", {
      class: `tree-row${node.path === this.selected ? " selected" : ""}`,
      style: { "--depth": String(depth) },
    }, caret, el("span", { class: "folder-icon", text: "📁" }), label);
    const li = el("li", { role: "treeitem", "aria-expanded": node.open ? "true" : "false", dataset: { path: node.path } }, row);
    if (node.open && node.children && node.children.length) {
      li.appendChild(el("ul", { role: "group" }, node.children.map((c) => this.item(c, depth + 1))));
    }
    return li;
  }
}
