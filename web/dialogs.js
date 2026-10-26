import { el } from "./util.js";

// openDialog shows a modal form. Each action closes it with its value; an
// action with submit runs onSubmit first, which may throw to keep it open
// and show the message.
// A dialog that isn't dismissible ignores Escape, for questions whose
// answer must be one of its buttons.
export function openDialog({ title, body = [], actions = [], onSubmit, className, dismissible = true }) {
  return new Promise((resolve) => {
    const error = el("p", { class: "form-error", role: "alert" });
    const buttons = actions.map((a) =>
      el("button", {
        type: a.submit ? "submit" : "button",
        class: a.kind || "",
        value: a.value === undefined ? "" : String(a.value),
        text: a.label,
        dataset: { action: String(a.value) },
      }),
    );
    const form = el("form", { method: "dialog", class: "dialog-form", novalidate: true },
      el("h2", { text: title }),
      el("div", { class: "dialog-body" }, body),
      error,
      el("div", { class: "dialog-actions" }, buttons),
    );
    const dialog = el("dialog", { class: className ? `dialog ${className}` : "dialog" }, form);
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      dialog.close();
      dialog.remove();
      resolve(value);
    };
    actions.forEach((a, i) => {
      if (a.submit) return;
      buttons[i].addEventListener("click", () => finish(a.value === undefined ? null : a.value));
    });
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const submitter = actions.find((a) => a.submit);
      if (!submitter) return;
      error.textContent = "";
      buttons.forEach((b) => (b.disabled = true));
      try {
        const value = onSubmit ? await onSubmit() : submitter.value;
        finish(value === undefined ? submitter.value : value);
      } catch (err) {
        error.textContent = err && err.message ? err.message : String(err);
        buttons.forEach((b) => (b.disabled = false));
      }
    });
    dialog.addEventListener("cancel", (ev) => {
      ev.preventDefault();
      if (dismissible) finish(null);
    });
    document.body.appendChild(dialog);
    dialog.showModal();
    const first = form.querySelector("input, select, textarea");
    if (first) {
      first.focus();
      if (first.select && first.type === "text") first.select();
    }
  });
}

export async function askText({ title, label, value = "", confirm = "OK", validate, selectStem = false }) {
  const input = el("input", { type: "text", value, autocomplete: "off", spellcheck: "false" });
  const p = openDialog({
    title,
    body: el("label", {}, el("span", { text: label }), input),
    actions: [
      { label: "Cancel", value: null },
      { label: confirm, value: true, submit: true, kind: "primary" },
    ],
    onSubmit: async () => {
      const v = input.value.trim();
      if (!v) throw new Error("Enter a name.");
      if (validate) await validate(v);
      return v;
    },
  });
  if (selectStem) {
    const dot = value.lastIndexOf(".");
    if (dot > 0) input.setSelectionRange(0, dot);
  }
  const result = await p;
  return typeof result === "string" ? result : null;
}

export async function confirmDialog({ title, message, confirm = "OK", danger = false }) {
  const result = await openDialog({
    title,
    body: el("p", { text: message }),
    actions: [
      { label: "Cancel", value: false },
      { label: confirm, value: true, submit: true, kind: danger ? "danger" : "primary" },
    ],
  });
  return result === true;
}

export async function alertDialog(title, message) {
  await openDialog({
    title,
    body: Array.isArray(message) ? message : el("p", { text: message }),
    actions: [{ label: "OK", value: true, submit: true, kind: "primary" }],
  });
}

let toastBox;

export function notify(message, kind = "info", ms = 5000) {
  if (!toastBox) {
    toastBox = el("div", { class: "toasts", role: "status", "aria-live": "polite" });
    document.body.appendChild(toastBox);
  }
  const t = el("div", { class: `toast ${kind}` }, el("span", { text: message }));
  const close = el("button", { type: "button", class: "icon", "aria-label": "Dismiss", text: "×" });
  close.addEventListener("click", () => t.remove());
  t.appendChild(close);
  toastBox.appendChild(t);
  if (ms > 0) setTimeout(() => t.remove(), ms);
}

export function showError(err, what) {
  const msg = err && err.message ? err.message : String(err);
  notify(what ? `${what}: ${msg}` : msg, "error", 8000);
}
