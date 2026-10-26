import { ApiError, post } from "./api.js";
import { openDialog } from "./dialogs.js";
import { el, clear, formatDate } from "./util.js";

function field(label, input, hint) {
  return el("label", { class: "field" }, el("span", { text: label }), input, hint ? el("small", { text: hint }) : null);
}

function card(title, ...content) {
  return el("div", { class: "auth" },
    el("div", { class: "auth-card" },
      el("div", { class: "brand" }, el("span", { class: "logo", text: "📦" }), "Gocalbox"),
      el("h1", { text: title }),
      content,
    ),
  );
}

// form wires a submit handler that disables the button while it runs and
// shows the server's message on failure.
function form(fields, submitLabel, onSubmit, extra = []) {
  const error = el("p", { class: "form-error", role: "alert" });
  const button = el("button", { type: "submit", class: "primary wide", text: submitLabel });
  const f = el("form", { novalidate: true }, fields, error, button, extra);
  f.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    error.textContent = "";
    button.disabled = true;
    try {
      await onSubmit(error);
    } catch (err) {
      error.textContent = err.message || String(err);
    } finally {
      button.disabled = false;
    }
  });
  return f;
}

function passwordPair(minHint) {
  const pw = el("input", { type: "password", autocomplete: "new-password", required: true });
  const again = el("input", { type: "password", autocomplete: "new-password", required: true });
  return {
    fields: [field("Password", pw, minHint), field("Repeat the password", again)],
    value() {
      if (!pw.value) throw new Error("Enter a password.");
      if (pw.value !== again.value) throw new Error("The two passwords differ.");
      return pw.value;
    },
  };
}

const caHelp = () =>
  el("p", { class: "muted small" },
    "If your browser warned that this connection isn't private, install the server's certificate authority on this device: ",
    el("a", { href: "/ca.crt", text: "download it" }),
    ", then open it to install it as a trusted certificate. You can remove it again afterwards.");

export function renderLogin(root, onDone, notice) {
  const user = el("input", { type: "text", autocomplete: "username", autocapitalize: "none", spellcheck: "false", required: true });
  const pw = el("input", { type: "password", autocomplete: "current-password", required: true });
  clear(root).appendChild(card("Log in",
    notice ? el("p", { class: "notice", text: notice }) : null,
    form([field("Username", user), field("Password", pw)], "Log in", async (error) => {
      try {
        const me = await post("/api/auth/login", { username: user.value.trim(), password: pw.value }, { quiet: true });
        await onDone(me);
      } catch (err) {
        if (err instanceof ApiError && err.code === "password_disabled") {
          error.textContent = `${err.message} Ask an admin for a password reset link.`;
          return;
        }
        if (err instanceof ApiError && err.code === "too_many_attempts" && err.retryAfter === null) {
          error.textContent = `${err.message} Logging in from a browser you have used here before still works.`;
          return;
        }
        throw err;
      } finally {
        pw.value = "";
      }
    }),
  ));
  user.focus();
}

export function renderSetup(root, code, onDone) {
  const codeInput = el("input", { type: "text", value: code || "", autocomplete: "off", spellcheck: "false", required: true });
  const user = el("input", { type: "text", autocomplete: "username", autocapitalize: "none", spellcheck: "false", required: true });
  const pair = passwordPair();
  const keep = el("input", { type: "checkbox" });
  const keepRow = el("label", { class: "check hidden" }, keep, el("span", { text: "Keep the existing folders (everyone can then read /public)" }));
  clear(root).appendChild(card("Set up the server",
    el("p", { class: "muted", text: "Create the first admin account. The setup code is printed on the server's console when it starts." }),
    form([field("Setup code", codeInput), field("Admin username", user), ...pair.fields, keepRow], "Create the admin", async (error) => {
      try {
        const me = await post("/api/setup", {
          code: codeInput.value, username: user.value.trim(), password: pair.value(), useExisting: keep.checked,
        }, { quiet: true });
        await onDone(me);
      } catch (err) {
        if (err instanceof ApiError && err.code === "layout_exists") {
          keepRow.classList.remove("hidden");
          error.textContent = err.message;
          return;
        }
        throw err;
      }
    }),
    caHelp(),
  ));
  (code ? user : codeInput).focus();
}

export async function renderInvite(root, token, onDone) {
  let info;
  try {
    info = await post("/api/invite/inspect", { token }, { quiet: true });
  } catch (err) {
    clear(root).appendChild(card("Invitation", el("p", { class: "form-error", text: err.message }), el("a", { href: "/", text: "Go to the login page" })));
    return;
  }
  const user = el("input", {
    type: "text", value: info.username || "", readOnly: Boolean(info.username),
    autocomplete: "username", autocapitalize: "none", spellcheck: "false", required: true,
  });
  const pair = passwordPair();
  clear(root).appendChild(card("Create your account",
    el("p", { class: "muted" }, `You're invited as ${roleName(info.role)}. The invitation is valid until ${formatDate(info.expires)}.`),
    form([field("Username", user), ...pair.fields], "Create the account", async () => {
      const me = await post("/api/invite/accept", { token, username: user.value.trim(), password: pair.value() }, { quiet: true });
      await onDone(me);
    }),
    caHelp(),
  ));
  (info.username ? root.querySelector("input[type=password]") : user).focus();
}

export async function renderReset(root, token, onDone) {
  let info;
  try {
    info = await post("/api/reset/inspect", { token }, { quiet: true });
  } catch (err) {
    clear(root).appendChild(card("Password reset", el("p", { class: "form-error", text: err.message }), el("a", { href: "/", text: "Go to the login page" })));
    return;
  }
  const pair = passwordPair();
  clear(root).appendChild(card("Choose a new password",
    el("p", { class: "muted" }, `For the account ${info.username}. The link is valid until ${formatDate(info.expires)}. Setting the password signs this account out everywhere else.`),
    form(pair.fields, "Set the password", async () => {
      const res = await post("/api/reset/accept", { token, password: pair.value() }, { quiet: true });
      await onDone(res, res.revokedLinks || []);
    }),
    caHelp(),
  ));
  root.querySelector("input").focus();
}

export function roleName(role) {
  return { admin: "an admin", contributor: "a contributor", viewer: "a viewer" }[role] || role;
}

// confirmPassword asks for the password again for changes that need a
// recent one; it resolves true once the server accepts it.
export async function confirmPassword() {
  const pw = el("input", { type: "password", autocomplete: "current-password" });
  const ok = await openDialog({
    title: "Confirm your password",
    body: [el("p", { class: "muted", text: "Changing users and folder access needs your password again." }), field("Password", pw)],
    actions: [
      { label: "Cancel", value: false },
      { label: "Confirm", value: true, submit: true, kind: "primary" },
    ],
    onSubmit: async () => {
      await post("/api/auth/confirm", { password: pw.value }, { quiet: true });
      return true;
    },
  });
  return ok === true;
}

// relogin asks the same user to log in again after their session ended,
// so that work in progress, such as uploads, can go on. It resolves false
// if they choose to leave instead.
export async function relogin(username) {
  const pw = el("input", { type: "password", autocomplete: "current-password" });
  const result = await openDialog({
    title: "Log in again",
    dismissible: false,
    body: [
      el("p", { class: "muted" }, `Your session has ended. Enter the password of ${username} to go on where you left off; uploads in progress continue.`),
      field("Password", pw),
    ],
    actions: [
      { label: "Log out", value: false },
      { label: "Log in", value: true, submit: true, kind: "primary" },
    ],
    onSubmit: async () => {
      await post("/api/auth/login", { username, password: pw.value }, { quiet: true });
      return true;
    },
  });
  return result === true;
}

export function revokedLinksList(links) {
  if (!links || links.length === 0) return null;
  return el("div", {},
    el("p", { text: "These unused links were revoked; make them again if they're still needed:" }),
    el("ul", {}, links.map((l) => el("li", {
      text: l.kind === "invite"
        ? `Invite${l.username ? ` for ${l.username}` : ""} as ${l.role}${l.note ? ` (${l.note})` : ""}`
        : `Password reset for ${l.username}`,
    }))),
  );
}
