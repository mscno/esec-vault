// Small conveniences for the esec vault pages. Every page works without
// this script; it never sends anything anywhere.
"use strict";

// setup makes what the page shows usable: on load, and again whenever
// Datastar patches part of it, so patched rows get the same.
function setup() {
  // Copy buttons stay hidden without scripts or a clipboard.
  if (navigator.clipboard) {
    for (const b of document.querySelectorAll("[data-copy][hidden]")) b.hidden = false;
  }
  for (const b of document.querySelectorAll("[data-filter-word][hidden]")) b.hidden = false;

  // Show exact times in the viewer's time zone.
  for (const t of document.querySelectorAll("time[datetime]:not([title])")) {
    const d = new Date(t.dateTime);
    if (!isNaN(d)) t.title = d.toLocaleString();
  }

  // Filters show once their table is there, and keep filtering it.
  for (const input of document.querySelectorAll("input[data-filter]")) {
    if (!document.querySelector(input.dataset.filter)) continue;
    input.hidden = false;
    applyFilter(input);
  }

  // Format a device code as XXXX-XXXX while it is typed.
  const code = document.querySelector("input.code:not([data-ready])");
  if (code) {
    code.dataset.ready = "1";
    code.addEventListener("input", () => {
      const raw = code.value.toUpperCase().replace(/[^0-9A-Z]/g, "").slice(0, 8);
      code.value = raw.length > 4 ? raw.slice(0, 4) + "-" + raw.slice(4) : raw;
    });
  }
}

// applyFilter hides the rows of a filter's table (or the [data-row]
// elements of another container) that lack any of the words
// typed: each word must be in the row's text or its data-tags.
function applyFilter(input) {
  const table = document.querySelector(input.dataset.filter);
  if (!table) return;
  const rows = table.tBodies && table.tBodies[0] ? table.tBodies[0].rows : table.querySelectorAll("[data-row]");
  const words = input.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  let shown = 0;
  for (const row of rows) {
    const text = (row.textContent + " " + (row.dataset.tags || "")).toLowerCase();
    row.hidden = words.some((w) => !text.includes(w));
    if (!row.hidden) shown++;
  }
  const count = document.querySelector(input.dataset.filter + "-count");
  if (count) count.textContent = words.length ? shown + " shown" : "";
}

document.addEventListener("input", (e) => {
  if (e.target.matches("input[data-filter]")) applyFilter(e.target);
});

// A filter word on a button: put it in the filter, or take it out.
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-filter-word]");
  if (!b) return;
  const input = document.querySelector(b.dataset.filterInput);
  if (!input) return;
  const words = input.value.trim().split(/\s+/).filter(Boolean);
  const w = b.dataset.filterWord;
  input.value = (words.includes(w) ? words.filter((x) => x !== w) : [...words, w]).join(" ");
  applyFilter(input);
});

document.addEventListener("DOMContentLoaded", () => {
  setup();
  let pending = false;
  new MutationObserver(() => {
    if (pending) return;
    pending = true;
    requestAnimationFrame(() => { pending = false; setup(); });
  }).observe(document.body, { childList: true, subtree: true });
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
// (Forms Datastar sends ask in their own handler, which runs first.)
document.addEventListener("submit", (e) => {
  if (e.defaultPrevented) return;
  const message = e.target.dataset.confirm;
  if (message && !window.confirm(message)) e.preventDefault();
});
