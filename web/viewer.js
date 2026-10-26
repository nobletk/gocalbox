import { el, fileURL, kindOf, joinPath } from "./util.js";

// openViewer shows a file in the page; items are the viewable files of the
// folder, so the arrows move between them.
export function openViewer(dir, items, index) {
  let i = index;
  const stage = el("div", { class: "viewer-stage" });
  const title = el("h2", { class: "viewer-title" });
  const download = el("a", { class: "button small", text: "Download" });
  const prev = el("button", { type: "button", class: "icon", "aria-label": "Previous", text: "‹" });
  const next = el("button", { type: "button", class: "icon", "aria-label": "Next", text: "›" });
  const close = el("button", { type: "button", class: "icon", "aria-label": "Close", text: "×" });
  const dialog = el("dialog", { class: "viewer" },
    el("header", {}, title, download, prev, next, close),
    stage,
  );

  const show = () => {
    const item = items[i];
    const p = joinPath(dir, item.name);
    const src = fileURL(p);
    title.textContent = item.name;
    download.href = fileURL(p, true);
    download.setAttribute("download", item.name);
    prev.disabled = i === 0;
    next.disabled = i === items.length - 1;
    for (const m of stage.querySelectorAll("video, audio")) m.pause();
    stage.replaceChildren(content(kindOf(item.name), src, item.name));
  };
  const move = (d) => {
    if (i + d >= 0 && i + d < items.length) {
      i += d;
      show();
    }
  };
  const finish = () => {
    for (const m of stage.querySelectorAll("video, audio")) m.pause();
    stage.replaceChildren();
    dialog.close();
    dialog.remove();
  };
  prev.addEventListener("click", () => move(-1));
  next.addEventListener("click", () => move(1));
  close.addEventListener("click", finish);
  dialog.addEventListener("cancel", (ev) => {
    ev.preventDefault();
    finish();
  });
  dialog.addEventListener("keydown", (ev) => {
    if (ev.target instanceof HTMLMediaElement) return;
    if (ev.key === "ArrowLeft") move(-1);
    if (ev.key === "ArrowRight") move(1);
  });
  document.body.appendChild(dialog);
  dialog.showModal();
  show();
  return dialog;
}

function content(kind, src, name) {
  switch (kind) {
    case "video":
      return el("video", { src, controls: true, autoplay: true, preload: "metadata", playsInline: true });
    case "audio":
      return el("audio", { src, controls: true, autoplay: true, preload: "metadata" });
    case "image":
      return el("img", { src, alt: name });
    case "pdf":
    case "text":
      return el("iframe", { src, title: name });
    default:
      return el("p", { class: "muted", text: "This file can't be shown here; download it instead." });
  }
}

export function viewable(entry) {
  return !entry.isDir && kindOf(entry.name) !== "other";
}
