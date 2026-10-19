// Small conveniences for the esec vault pages. Every page works without
// this script; it never sends anything anywhere.
"use strict";

document.addEventListener("DOMContentLoaded", () => {
  // Copy buttons stay hidden without scripts or a clipboard.
  if (navigator.clipboard) {
    for (const b of document.querySelectorAll("[data-copy]")) b.hidden = false;
  }

  // Show exact times in the viewer's time zone.
  for (const t of document.querySelectorAll("time[datetime]")) {
    const d = new Date(t.dateTime);
    if (!isNaN(d)) t.title = d.toLocaleString();
  }

  // Filter the rows of a table as you type.
  for (const input of document.querySelectorAll("input[data-filter]")) {
    const table = document.querySelector(input.dataset.filter);
    if (!table) continue;
    input.hidden = false;
    input.addEventListener("input", () => {
      const q = input.value.trim().toLowerCase();
      for (const row of table.tBodies[0].rows) {
        row.hidden = q !== "" && !row.textContent.toLowerCase().includes(q);
      }
    });
  }

  // Format a device code as XXXX-XXXX while it is typed.
  const code = document.querySelector("input.code");
  if (code) {
    code.addEventListener("input", () => {
      const raw = code.value.toUpperCase().replace(/[^0-9A-Z]/g, "").slice(0, 8);
      code.value = raw.length > 4 ? raw.slice(0, 4) + "-" + raw.slice(4) : raw;
    });
  }
});

document.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-copy]");
  if (!b) return;
  b.dataset.label ??= b.textContent;
  try {
    await navigator.clipboard.writeText(b.dataset.copy);
    b.textContent = "Copied";
  } catch {
    b.textContent = "Copy failed";
  }
  clearTimeout(b.resetTimer);
  b.resetTimer = setTimeout(() => { b.textContent = b.dataset.label; }, 1500);
});

// Ask before forms that suspend, disable or end something.
document.addEventListener("submit", (e) => {
  const message = e.target.dataset.confirm;
  if (message && !window.confirm(message)) e.preventDefault();
});
