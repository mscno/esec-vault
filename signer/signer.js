// The esec vault passkey signer. It is hosted apart from the vault server,
// so the server's own pages cannot make or use a passkey (passkeys are bound
// to this page's origin). Everything shown here is worked out here:
//
//   - a new passkey's fingerprint words, from the key the browser made, for
//     the person to compare with what their device shows before adding it;
//   - what a signature signs: each link the server asks to have signed is
//     decoded here, described from its own bytes (accounts by their GitHub
//     id, looked up at GitHub), and its hash computed here. A change this
//     page cannot describe is not signed.
"use strict";

(() => {
  if (window.top !== window.self) {
    document.getElementById("framed").hidden = false;
    return;
  }

  // The vault server: this page's host without "sign.". On a test host
  // (*.localhost) it may be given as ?server=.
  const server = (() => {
    const q = new URLSearchParams(location.search).get("server");
    if (q && /(^|\.)localhost$/.test(location.hostname)) return q.replace(/\/$/, "");
    if (!location.hostname.startsWith("sign.")) return "";
    return location.protocol + "//" + location.host.slice(5);
  })();

  const $ = (id) => document.getElementById(id);
  const enc = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const dec = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
  const utf8 = (s) => new TextEncoder().encode(s);
  const cat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let i = 0;
    for (const p of parts) { out.set(p, i); i += p.length; }
    return out;
  };
  const sha256 = async (b) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));

  const flash = (text, bad) => {
    const f = $("flash");
    f.className = bad ? "bad" : "";
    f.textContent = text;
    f.scrollIntoView({ block: "nearest" });
  };

  const api = async (method, path, body) => {
    const r = await fetch(server + "/signer/v1" + path, {
      method,
      credentials: "include",
      headers: method === "POST" ? { "Content-Type": "application/json", "X-Esec-Signer": "1" } : { "X-Esec-Signer": "1" },
      body: method === "POST" ? JSON.stringify(body || {}) : undefined,
    });
    const j = await r.json().catch(() => ({ error: "The vault server did not answer." }));
    if (!r.ok) {
      const e = new Error(j.error || "That did not work.");
      e.status = r.status;
      throw e;
    }
    return j;
  };

  // Fingerprint words, as fpwords.Words: SHA-256 over length-prefixed parts,
  // 11 bits per word from the BIP39 English list.
  const words = async (n, domain, ...parts) => {
    const pieces = [];
    for (const p of [utf8(domain), ...parts]) {
      const len = new Uint8Array(4);
      new DataView(len.buffer).setUint32(0, p.length);
      pieces.push(len, p);
    }
    const sum = await sha256(cat(...pieces));
    const out = [];
    for (let i = 0; i < n; i++) {
      let idx = 0;
      for (let b = 0; b < 11; b++) {
        const bit = i * 11 + b;
        idx = (idx << 1) | ((sum[bit >> 3] >> (7 - (bit & 7))) & 1);
      }
      out.push(BIP39[idx]);
    }
    return out.join("-");
  };

  // GitHub logins by numeric id, looked up at GitHub, not the vault server.
  const logins = new Map();
  const github = async (user) => {
    const m = /^gh:([1-9][0-9]{0,19})$/.exec(user || "");
    if (!m) return null;
    if (!logins.has(m[1])) {
      logins.set(m[1], fetch("https://api.github.com/user/" + m[1], { headers: { Accept: "application/vnd.github+json" } })
        .then((r) => (r.ok ? r.json() : null)).then((j) => (j && j.login) || null).catch(() => null));
    }
    return logins.get(m[1]);
  };
  const who = async (user, claimed) => {
    const login = await github(user);
    const id = user.slice(3);
    if (!login) return { text: `GitHub account #${id} (could not ask GitHub its login)`, ok: !claimed };
    if (claimed && claimed.toLowerCase() !== login.toLowerCase()) {
      return { text: `GitHub account #${id}, which GitHub calls @${login}, but the change calls @${claimed}`, ok: false };
    }
    return { text: `@${login} (GitHub account #${id})`, ok: true };
  };
  const envs = (list) => (list && list.length ? list.join(", ") : "nothing");

  // describe returns what a link does, from its own content, or null for
  // anything this page will not sign.
  const describe = async (kind, link, me) => {
    if (link.signer !== me) return null;
    const b = link.body || {};
    if (kind === "project-link") {
      const p = link.project;
      switch (link.type) {
        case "member_add": {
          if (b.admin || b.verified !== "web" || !b.member) return null;
          const w = await who(b.member.user, b.member.login);
          return { text: `In ${p}: add ${w.text}, who reads ${envs(b.envs)}`, ok: w.ok };
        }
        case "member_update": {
          if (b.admin) return null;
          const w = await who(b.user);
          return { text: `In ${p}: ${w.text} reads ${envs(b.envs)} from now on`, ok: w.ok };
        }
        case "member_remove": {
          const w = await who(b.user);
          return { text: `In ${p}: remove ${w.text}`, ok: w.ok };
        }
        case "machine_remove":
          return { text: `In ${p}: remove the machine ${b.id}`, ok: true };
        case "group_set":
          return { text: b.envs && b.envs.length ? `In ${p}: the machine group ${b.group} reads ${envs(b.envs)}` : `In ${p}: the machine group ${b.group} reads nothing any more`, ok: true };
      }
      return null;
    }
    if (kind === "group-link") {
      const g = link.group;
      switch (link.type) {
        case "remove":
          if (b.destroyed) return null;
          return { text: `In the machine group ${g}: remove ${b.id}`, ok: true };
        case "access_remove":
          return { text: `The machine group ${g} stops taking keys from ${b.project}`, ok: true };
      }
    }
    return null;
  };

  let me = null;
  let pending = null;

  const showChanges = async () => {
    const list = $("changes");
    list.textContent = "";
    const { changes } = await api("GET", "/changes");
    if (!changes.length) {
      const li = document.createElement("li");
      li.className = "muted";
      li.textContent = "Nothing waits to be signed.";
      list.append(li);
    }
    for (const c of changes) {
      const li = document.createElement("li");
      const b = document.createElement("button");
      b.type = "button";
      b.className = "secondary";
      b.textContent = "Review";
      b.addEventListener("click", () => review(c.id));
      li.append(`${c.target}: ${c.kind} `, b);
      list.append(li);
    }
  };

  const review = async (id) => {
    if (!me.passkeys.length) {
      flash("Add a passkey first (below), and add it from one of your devices.", true);
      return;
    }
    const delegate = $("passkey").value;
    let r;
    try {
      r = await api("POST", `/changes/${id}/begin`, { delegate });
    } catch (e) {
      flash(e.message, true);
      return;
    }
    const body = $("review-body");
    body.textContent = "";
    const items = [];
    let ok = true;
    for (const l of r.links) {
      const bytes = dec(l.body);
      let link;
      try { link = JSON.parse(new TextDecoder().decode(bytes)); } catch { link = null; }
      const d = link && (l.kind === "project-link" || l.kind === "group-link") && link.signer_delegate === delegate ? await describe(l.kind, link, me.user) : null;
      const div = document.createElement("div");
      div.className = "change" + (d && d.ok ? "" : " warn");
      const what = document.createElement("div");
      what.className = "what";
      what.textContent = d ? d.text : "This page cannot tell what this signs, so it will not sign it. Sign it on a device: esec vault changes";
      const raw = document.createElement("details");
      const sum = document.createElement("summary");
      sum.textContent = "The exact bytes signed";
      const pre = document.createElement("pre");
      pre.textContent = new TextDecoder().decode(bytes);
      raw.append(sum, pre);
      div.append(what, raw);
      body.append(div);
      if (!d || !d.ok) ok = false;
      items.push({ challenge: await sha256(cat(utf8(`esec-vault/${l.kind}/v1\n`), bytes)) });
    }
    pending = ok ? { id, delegate, rpId: r.rpId, credentialId: r.credentialId, items } : null;
    $("sign").disabled = !ok;
    $("review").hidden = false;
    $("review").scrollIntoView();
  };

  $("sign").addEventListener("click", async () => {
    if (!pending) return;
    $("sign").disabled = true;
    try {
      const assertions = [];
      for (const it of pending.items) {
        const a = await navigator.credentials.get({
          publicKey: { challenge: it.challenge, rpId: pending.rpId, allowCredentials: [{ type: "public-key", id: dec(pending.credentialId) }], userVerification: "preferred", timeout: 120000 },
        });
        assertions.push({ credentialId: enc(a.rawId), authenticatorData: enc(a.response.authenticatorData), clientDataJSON: enc(a.response.clientDataJSON), signature: enc(a.response.signature) });
      }
      const r = await api("POST", `/changes/${pending.id}/finish`, { delegate: pending.delegate, assertions });
      flash(r.message);
      $("review").hidden = true;
      pending = null;
      history.replaceState(null, "", location.pathname + location.search);
      await showChanges();
    } catch (e) {
      flash(e.name === "NotAllowedError" ? "Not signed." : e.message, true);
      $("sign").disabled = false;
    }
  });
  $("cancel").addEventListener("click", () => { $("review").hidden = true; pending = null; });

  $("register-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    const button = form.querySelector("button");
    button.disabled = true;
    try {
      const o = await api("POST", "/passkeys/options");
      if (o.rpId !== location.hostname) throw new Error("The vault server named another site for the passkey; not making it.");
      const cred = await navigator.credentials.create({
        publicKey: {
          challenge: dec(o.challenge),
          rp: { id: location.hostname, name: "esec vault" },
          user: { id: dec(o.userId), name: me.login, displayName: me.login },
          pubKeyCredParams: [{ type: "public-key", alg: -8 }, { type: "public-key", alg: -7 }],
          excludeCredentials: o.exclude.map((id) => ({ type: "public-key", id: dec(id) })),
          authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
          attestation: "none",
          timeout: 120000,
        },
      });
      const spki = new Uint8Array(cred.response.getPublicKey());
      const fingerprint = await words(6, "esec-vault passkey v1", spki, new Uint8Array(cred.rawId), utf8(location.origin));
      await api("POST", "/passkeys", {
        name: form.elements.name.value,
        scope: form.elements.scope.value,
        credentialId: enc(cred.rawId),
        publicKey: enc(spki),
        alg: cred.response.getPublicKeyAlgorithm(),
        clientDataJSON: enc(cred.response.clientDataJSON),
      });
      $("words-text").textContent = fingerprint;
      $("words").hidden = false;
      flash("Passkey made. Add it from one of your devices; check the words first.");
    } catch (err) {
      flash(err.name === "NotAllowedError" ? "No passkey was made." : err.message, true);
    } finally {
      button.disabled = false;
    }
  });

  (async () => {
    if (!server || !window.PublicKeyCredential) {
      document.body.textContent = !server ? "This page must be served from sign.<your vault server's host>." : "This browser has no passkeys.";
      return;
    }
    try {
      me = await api("GET", "/me");
    } catch (e) {
      if (e.status === 401) {
        $("signin-link").href = server + "/account";
        $("signin-link").textContent = server;
        $("signin").hidden = false;
        return;
      }
      document.body.textContent = e.message;
      return;
    }
    $("who").textContent = `@${me.login} on ${server}`;
    const sel = $("passkey");
    for (const p of me.passkeys) {
      const o = document.createElement("option");
      o.value = p.id;
      o.textContent = p.name;
      sel.append(o);
    }
    $("main").hidden = false;
    await showChanges();
    const m = /^#change=([0-9]+)$/.exec(location.hash);
    if (m) await review(m[1]);
    if (location.hash === "#register") $("register").scrollIntoView();
  })();
})();
