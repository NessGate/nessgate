"use strict";

const $ = (id) => document.getElementById(id);

/* ------------------------- Copy buttons & tabs ------------------------- */

document.addEventListener("click", (e) => {
  const btn = e.target.closest("button.copy[data-copy]");
  if (!btn) return;
  navigator.clipboard.writeText(btn.dataset.copy).then(() => {
    const original = btn.textContent;
    btn.textContent = "Copied";
    setTimeout(() => { btn.textContent = original; }, 1200);
  }).catch(() => {});
});

document.querySelectorAll(".tab[data-tab]").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab[data-tab]").forEach((t) => t.classList.toggle("active", t === tab));
    document.querySelectorAll(".snippet").forEach((s) => { s.hidden = s.id !== "snip-" + tab.dataset.tab; });
  });
});

/* ------------------------------ Resolver ------------------------------ */

const resolveForm = $("resolveForm");
if (resolveForm) {
  resolveForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const box = $("resolveResult");
    box.hidden = false;
    box.className = "result";
    box.textContent = "Resolving…";
    const domain = $("resolveDomain").value.trim();
    try {
      // The resolver: reads whatever the domain publishes across the supported
      // standards and returns one normalized list, each with a link to its source.
      const res = await fetch("/discover/" + encodeURIComponent(domain));
      const data = await res.json();
      box.textContent = "";
      if (data.error) { box.textContent = data.error; return; }
      const resources = Array.isArray(data.resources)
        ? data.resources.filter((r) => r && typeof r.url === "string" && r.url.startsWith("https://"))
        : [];
      if (!resources.length) {
        box.textContent = (data.domain || domain) + " publishes no machine-readable resources we recognize yet.";
        return;
      }
      const status = document.createElement("p");
      status.className = "ok";
      status.textContent = resources.length + " machine-readable resource" + (resources.length === 1 ? "" : "s") + " found";
      box.append(status);
      for (const r of resources) {
        const line = document.createElement("p");
        line.className = "res-line";
        const tag = document.createElement("span");
        tag.className = "res-tag";
        tag.textContent = r.type || "resource";
        const link = document.createElement("a");
        link.href = r.url;
        link.rel = "nofollow";
        link.textContent = r.url;
        line.append(tag, link);
        if (r.source) {
          line.append(document.createTextNode(" · via " + r.source));
        }
        box.append(line);
      }
    } catch {
      box.textContent = "Resolve failed. Please try again.";
    }
  });
}
