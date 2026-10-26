import { get, post, withReauth } from "./api.js";
import { confirmPassword, revokedLinksList } from "./auth.js";
import { confirmDialog, notify, openDialog, showError, alertDialog } from "./dialogs.js";
import { el, clear, formatDate } from "./util.js";

const roles = ["viewer", "contributor", "admin"];

function isLoopback(host) {
  return host === "localhost" || host.startsWith("127.") || host === "[::1]" || host === "::1";
}

// linkText is what an admin sends: the steps to trust the server first,
// since opening the link before would show a certificate warning.
export function linkText(base, kind, token, fingerprint) {
  const url = `${base}/#${kind}=${token}`;
  const lines = [];
  if (fingerprint) {
    lines.push(`1. Install the server's certificate authority: open ${base}/ca.crt and install it as a trusted certificate.`);
    lines.push(`   Its SHA-256 fingerprint is ${fingerprint}.`);
    lines.push(`2. Then open ${url}`);
  } else {
    lines.push(`Open ${url}`);
  }
  return { url, text: lines.join("\n") };
}

async function showLink(link, what) {
  const text = el("textarea", { readOnly: true, rows: 5, class: "link-text" });
  const addr = el("input", { type: "url", placeholder: "https://192.168.1.20:8443", value: link.address || "" });
  const needsAddress = !link.address && isLoopback(location.hostname);
  const update = () => {
    const base = (addr.value.trim() || location.origin).replace(/\/+$/, "");
    text.value = linkText(base, link.kind, link.token, link.caFingerprint).text;
  };
  addr.addEventListener("input", update);
  update();
  const copy = el("button", { type: "button", text: "Copy" });
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text.value);
      copy.textContent = "Copied";
    } catch {
      text.select();
    }
  });
  await openDialog({
    title: what,
    body: [
      el("p", { class: "muted", text: `Send this to the person it is for. It works once, until ${formatDate(link.expires)}, and isn't shown again.` }),
      needsAddress ? el("label", { class: "field" }, el("span", { text: "Address other devices reach this server at" }), addr) : null,
      text,
      copy,
    ],
    actions: [{ label: "Done", value: true, submit: true, kind: "primary" }],
  });
}

export class AdminPage {
  constructor({ me }) {
    this.me = me;
    this.element = el("div", { class: "page" });
  }

  change(fn) {
    return withReauth(fn, confirmPassword);
  }

  async show() {
    clear(this.element).append(el("h1", { text: "Users" }), el("p", { class: "muted", text: "Loading…" }));
    let users, links;
    try {
      [users, links] = await Promise.all([get("/api/admin/users/list"), get("/api/admin/links/list")]);
    } catch (err) {
      clear(this.element).append(el("h1", { text: "Users" }), el("p", { class: "form-error", text: err.message }));
      return;
    }
    clear(this.element).append(
      el("div", { class: "page-head" }, el("h1", { text: "Users" }), el("button", { type: "button", class: "primary", text: "Invite someone", onclick: () => this.invite() })),
      this.usersTable(users),
      el("h2", { text: "Unused links" }),
      links.length ? this.linksTable(links) : el("p", { class: "muted", text: "None." }),
      el("p", { class: "muted small", text: "Folder access for single users is managed through the API (/api/admin/bindings/…)." }),
    );
  }

  usersTable(users) {
    return el("div", { class: "table-wrap" }, el("table", { class: "grid" },
      el("thead", {}, el("tr", {}, ["User", "Role", "State", "Created", ""].map((h) => el("th", { scope: "col", text: h })))),
      el("tbody", {}, users.map((u) => {
        const role = el("select", { "aria-label": `Role of ${u.username}` }, roles.map((r) => el("option", { value: r, text: r, selected: r === u.role })));
        role.addEventListener("change", () => this.update(u, { role: role.value }, `${u.username} is now ${role.value}.`).catch(() => (role.value = u.role)));
        const state = u.disabled ? "Disabled" : u.passwordDisabled ? "Password disabled" : "Active";
        const self = u.id === this.me.id;
        return el("tr", { dataset: { user: u.username } },
          el("td", {}, el("strong", { text: u.username }), self ? el("span", { class: "muted", text: " (you)" }) : null),
          el("td", {}, role),
          el("td", { class: u.disabled || u.passwordDisabled ? "warn-text" : "", text: state }),
          el("td", { class: "muted", text: `${formatDate(u.createdAt)}${u.createdByName ? ` by ${u.createdByName}` : ""}` }),
          el("td", { class: "row-actions" },
            el("button", { type: "button", class: "small", text: u.disabled ? "Enable" : "Disable", onclick: () => this.update(u, { disabled: !u.disabled }, `${u.username} is ${u.disabled ? "enabled" : "disabled"}.`).catch(() => {}) }),
            el("button", { type: "button", class: "small", text: "Reset link", onclick: () => this.resetLink(u) }),
            el("button", { type: "button", class: "small danger", text: "Delete", onclick: () => this.remove(u) }),
          ),
        );
      })),
    ));
  }

  linksTable(links) {
    return el("div", { class: "table-wrap" }, el("table", { class: "grid" },
      el("thead", {}, el("tr", {}, ["Link", "For", "Expires", ""].map((h) => el("th", { scope: "col", text: h })))),
      el("tbody", {}, links.map((l) => el("tr", {},
        el("td", { text: l.kind === "invite" ? `Invite as ${l.role}` : "Password reset" }),
        el("td", { text: [l.username || l.user || "anyone", l.note].filter(Boolean).join(" – ") }),
        el("td", { class: "muted", text: formatDate(l.expires) }),
        el("td", {}, el("button", { type: "button", class: "small", text: "Revoke", onclick: () => this.revoke(l) })),
      ))),
    ));
  }

  async update(u, change, done) {
    try {
      await this.change(() => post("/api/admin/users/update", { id: u.id, ...change }));
      notify(done, "ok");
    } catch (err) {
      showError(err, `Changing ${u.username}`);
      throw err;
    } finally {
      this.show();
    }
  }

  async resetLink(u) {
    try {
      const link = await this.change(() => post("/api/admin/users/reset-link", { id: u.id }));
      await showLink(link, `Password reset link for ${u.username}`);
    } catch (err) {
      showError(err, "Making the reset link");
    }
    this.show();
  }

  async remove(u) {
    const ok = await confirmDialog({
      title: "Delete user",
      message: `Delete ${u.username}? Their home folder is kept aside on the server, and their sessions end.`,
      confirm: "Delete", danger: true,
    });
    if (!ok) return;
    try {
      const res = await this.change(() => post("/api/admin/users/delete", { id: u.id }));
      notify(res.archivedHome ? `${u.username} is deleted; their home is kept at ${res.archivedHome}.` : `${u.username} is deleted.`, "ok");
    } catch (err) {
      showError(err, `Deleting ${u.username}`);
    }
    this.show();
  }

  async revoke(l) {
    try {
      await this.change(() => post("/api/admin/links/revoke", { id: l.id }));
    } catch (err) {
      showError(err, "Revoking the link");
    }
    this.show();
  }

  async invite() {
    const role = el("select", {}, roles.map((r) => el("option", { value: r, text: r, selected: r === "contributor" })));
    const username = el("input", { type: "text", autocapitalize: "none", spellcheck: "false", placeholder: "they choose it" });
    const note = el("input", { type: "text", maxLength: 100, placeholder: "who it is for" });
    let link = null;
    const ok = await openDialog({
      title: "Invite someone",
      body: [
        el("label", { class: "field" }, el("span", { text: "Role" }), role),
        el("label", { class: "field" }, el("span", { text: "Username (optional)" }), username),
        el("label", { class: "field" }, el("span", { text: "Note (optional)" }), note),
      ],
      actions: [
        { label: "Cancel", value: false },
        { label: "Make the link", value: true, submit: true, kind: "primary" },
      ],
      onSubmit: async () => {
        link = await this.change(() => post("/api/admin/invites/create", { role: role.value, username: username.value.trim(), note: note.value.trim() }));
        return true;
      },
    });
    if (ok === true && link) await showLink(link, "Invitation link");
    this.show();
  }
}

export class AccountPage {
  constructor({ me, onSignedOut }) {
    this.me = me;
    this.onSignedOut = onSignedOut;
    this.element = el("div", { class: "page" });
  }

  async show() {
    const current = el("input", { type: "password", autocomplete: "current-password" });
    const next = el("input", { type: "password", autocomplete: "new-password" });
    const again = el("input", { type: "password", autocomplete: "new-password" });
    const error = el("p", { class: "form-error", role: "alert" });
    const form = el("form", { class: "narrow", novalidate: true },
      el("label", { class: "field" }, el("span", { text: "Current password" }), current),
      el("label", { class: "field" }, el("span", { text: "New password" }), next),
      el("label", { class: "field" }, el("span", { text: "Repeat the new password" }), again),
      error,
      el("button", { type: "submit", class: "primary", text: "Change the password" }),
    );
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      error.textContent = "";
      if (next.value !== again.value) {
        error.textContent = "The two new passwords differ.";
        return;
      }
      try {
        const res = await post("/api/auth/password", { current: current.value, new: next.value }, { quiet: true });
        form.reset();
        const list = revokedLinksList(res.revokedLinks);
        await alertDialog("Password changed", [el("p", { text: "Your other sessions have ended." }), list]);
        this.show();
      } catch (err) {
        error.textContent = err.message;
      }
    });

    const sessions = el("div", {}, el("p", { class: "muted", text: "Loading…" }));
    clear(this.element).append(
      el("h1", { text: "Your account" }),
      el("p", { class: "muted" }, `${this.me.username}, ${this.me.role}${this.me.home ? `; your home folder is ${this.me.home}` : ""}.`),
      el("h2", { text: "Password" }),
      form,
      el("div", { class: "page-head" }, el("h2", { text: "Where you're signed in" }),
        el("button", { type: "button", text: "Sign out everywhere else", onclick: () => this.revokeOthers() })),
      sessions,
    );
    try {
      const list = await get("/api/auth/sessions");
      clear(sessions).appendChild(el("div", { class: "table-wrap" }, el("table", { class: "grid" },
        el("thead", {}, el("tr", {}, ["Browser", "Address", "Last seen", ""].map((h) => el("th", { scope: "col", text: h })))),
        el("tbody", {}, list.map((s) => el("tr", {},
          el("td", {}, el("span", { text: s.userAgent || "unknown" }), s.current ? el("strong", { text: " (this browser)" }) : null),
          el("td", { text: s.address }),
          el("td", { class: "muted", text: formatDate(s.lastSeen) }),
          el("td", {}, el("button", { type: "button", class: "small", text: s.current ? "Sign out" : "End", onclick: () => this.revoke(s) })),
        ))),
      )));
    } catch (err) {
      clear(sessions).appendChild(el("p", { class: "form-error", text: err.message }));
    }
  }

  async revoke(s) {
    try {
      await post("/api/auth/sessions/revoke", { id: s.id });
      if (s.current) return this.onSignedOut();
    } catch (err) {
      showError(err, "Ending the session");
    }
    this.show();
  }

  async revokeOthers() {
    const ok = await confirmDialog({ title: "Sign out everywhere else", message: "End every other session of your account? Unused links you made are revoked too.", confirm: "Sign out others" });
    if (!ok) return;
    try {
      const res = await post("/api/auth/sessions/revoke-others", {});
      const list = revokedLinksList(res.revokedLinks);
      if (list) await alertDialog("Signed out everywhere else", [list]);
      else notify("Your other sessions have ended.", "ok");
    } catch (err) {
      showError(err, "Signing out the other sessions");
    }
    this.show();
  }
}
