// Every string from the server reaches the page through text nodes or
// properties, never as HTML, so a file or user name can't add markup.
export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "dataset") Object.assign(node.dataset, v);
    // The page's CSP refuses style attributes; properties set through the
    // CSSOM are allowed.
    else if (k === "style") for (const [p, val] of Object.entries(v)) node.style.setProperty(p, val);
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
    else if (k in node && typeof v !== "string") node[k] = v;
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v === true ? "" : v);
  }
  append(node, children);
  return node;
}

function append(node, children) {
  for (const c of children) {
    if (c === undefined || c === null || c === false) continue;
    if (Array.isArray(c)) append(node, c);
    else if (c instanceof Node) node.appendChild(c);
    else node.appendChild(document.createTextNode(String(c)));
  }
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

const units = ["B", "KiB", "MiB", "GiB", "TiB"];

export function formatSize(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return "";
  let i = 0;
  let v = bytes;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return i === 0 ? `${v} B` : `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

export function formatRate(bytesPerSecond) {
  return bytesPerSecond > 0 ? `${formatSize(bytesPerSecond)}/s` : "";
}

export function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return "";
  if (seconds < 60) return `${Math.ceil(seconds)} s`;
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m} min ${Math.round(seconds % 60)} s`;
  return `${Math.floor(m / 60)} h ${m % 60} min`;
}

export function formatDate(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
}

export function joinPath(dir, name) {
  return dir ? `${dir}/${name}` : name;
}

export function parentPath(p) {
  const i = p.lastIndexOf("/");
  return i < 0 ? "" : p.slice(0, i);
}

export function baseName(p) {
  return p.slice(p.lastIndexOf("/") + 1);
}

// fileURL encodes each segment, so that "#", "?" and "%" in a name stay
// part of it.
export function fileURL(p, download = false) {
  const url = "/files/" + p.split("/").map(encodeURIComponent).join("/");
  return download ? `${url}?download` : url;
}

export function zipURL(dir) {
  return `/api/fs/zip?path=${encodeURIComponent(dir)}`;
}

const kinds = {
  video: ["mp4", "m4v", "webm", "ogv", "mov", "mkv"],
  audio: ["mp3", "m4a", "aac", "wav", "flac", "ogg", "oga", "opus", "weba"],
  image: ["jpg", "jpeg", "png", "gif", "webp", "avif", "bmp", "ico"],
  pdf: ["pdf"],
  text: ["txt", "log", "md", "csv", "tsv", "json", "yaml", "yml", "ini", "srt"],
};

// kindOf follows the types the server shows inline; anything else is only
// downloaded.
export function kindOf(name) {
  const ext = name.includes(".") ? name.slice(name.lastIndexOf(".") + 1).toLowerCase() : "";
  for (const [kind, exts] of Object.entries(kinds)) if (exts.includes(ext)) return kind;
  return "other";
}

export const icons = { dir: "📁", video: "🎬", audio: "🎵", image: "🖼", pdf: "📄", text: "📄", other: "📦" };

// safeNext returns where to go after logging in, when the server sent the
// browser here from a file it wanted: only a file path on this server.
export function safeNext(search, origin) {
  const next = new URLSearchParams(search).get("next");
  if (!next || !next.startsWith("/files/") || next.includes("\\")) return null;
  try {
    const u = new URL(next, origin);
    return u.origin === origin && u.pathname.startsWith("/files/") ? u.pathname + u.search : null;
  } catch {
    return null;
  }
}
