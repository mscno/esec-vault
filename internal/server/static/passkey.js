// Passkeys on the esec vault pages: register one, and sign a change with
// one. The server builds what is signed; your devices check every
// signature, and what a passkey may sign at all.
"use strict";

(() => {
  const enc = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const dec = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
  const csrf = () => document.querySelector('meta[name="csrf"]')?.content || "";

  const post = async (path, body) => {
    const r = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
      body: JSON.stringify(body || {}),
    });
    const j = await r.json().catch(() => ({ error: "The server did not answer." }));
    if (!r.ok) throw new Error(j.error || "That did not work.");
    return j;
  };

  const flash = (text, warn) => {
    const f = document.getElementById("flash");
    if (!f) return;
    f.className = "flash flash-" + (warn ? "warn" : "info");
    f.textContent = text;
    f.scrollIntoView({ block: "nearest" });
  };

  const supported = () => window.PublicKeyCredential && navigator.credentials;

  document.addEventListener("DOMContentLoaded", () => {
    if (!supported()) {
      for (const el of document.querySelectorAll("[data-passkey-register] button, [data-passkey-change]")) el.disabled = true;
      return;
    }
    for (const el of document.querySelectorAll("[data-passkey-change]")) el.hidden = false;
  });

  // Register a passkey.
  document.addEventListener("submit", async (e) => {
    const form = e.target.closest("form[data-passkey-register]");
    if (!form) return;
    e.preventDefault();
    const button = form.querySelector("button");
    button.disabled = true;
    try {
      const o = await post("/account/passkeys/options");
      const cred = await navigator.credentials.create({
        publicKey: {
          challenge: dec(o.challenge),
          rp: { id: o.rpId, name: o.rpName },
          user: { id: dec(o.userId), name: o.userName, displayName: o.userName },
          pubKeyCredParams: [{ type: "public-key", alg: -8 }, { type: "public-key", alg: -7 }],
          excludeCredentials: o.exclude.map((id) => ({ type: "public-key", id: dec(id) })),
          authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
          attestation: "none",
          timeout: 120000,
        },
      });
      const r = await post("/account/passkeys", {
        name: form.elements.name.value,
        scope: form.elements.scope.value,
        credentialId: enc(cred.rawId),
        publicKey: enc(cred.response.getPublicKey()),
        alg: cred.response.getPublicKeyAlgorithm(),
        clientDataJSON: enc(cred.response.clientDataJSON),
      });
      flash("Passkey made. Its fingerprint: " + r.words + ". " + r.message);
      setTimeout(() => location.reload(), 4000);
    } catch (err) {
      flash(err.name === "NotAllowedError" ? "No passkey was made." : err.message, true);
    } finally {
      button.disabled = false;
    }
  });

  // Sign a change with a passkey.
  document.addEventListener("click", async (e) => {
    const b = e.target.closest("button[data-passkey-change]");
    if (!b) return;
    const id = b.dataset.passkeyChange;
    if (!/^[0-9]+$/.test(id)) return;
    const choice = document.getElementById("passkey-choice");
    const delegate = choice ? choice.value : b.dataset.passkeyDelegate;
    b.disabled = true;
    try {
      const o = await post("/changes/" + id + "/passkey/begin", { delegate });
      const assertions = [];
      for (const ch of o.challenges) {
        const a = await navigator.credentials.get({
          publicKey: {
            challenge: dec(ch),
            rpId: o.rpId,
            allowCredentials: [{ type: "public-key", id: dec(o.credentialId) }],
            userVerification: "preferred",
            timeout: 120000,
          },
        });
        assertions.push({
          credentialId: enc(a.rawId),
          authenticatorData: enc(a.response.authenticatorData),
          clientDataJSON: enc(a.response.clientDataJSON),
          signature: enc(a.response.signature),
        });
      }
      const r = await post("/changes/" + id + "/passkey/finish", { delegate, assertions });
      flash(r.message);
      setTimeout(() => location.reload(), 1500);
    } catch (err) {
      flash(err.name === "NotAllowedError" ? "Not signed." : err.message, true);
      b.disabled = false;
    }
  });
})();
