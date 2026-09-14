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
      const renderList = (list, heading) => {
        const status = document.createElement("p");
        status.className = "ok";
        status.textContent = heading;
        box.append(status);
        for (const r of list) {
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
          if (r.source) line.append(document.createTextNode(" · via " + r.source));
          box.append(line);
        }
      };
      const d = data.domain || domain;
      if (resources.length) {
        renderList(resources, resources.length + " machine-readable resource" + (resources.length === 1 ? "" : "s") + " found");
        return;
      }
      // Exact host is empty — look for verified resources on related hosts under
      // the same domain (Organization Discovery) before answering.
      box.textContent = "Nothing on " + d + " itself — checking related hosts…";
      let related = [];
      try {
        const orgRes = await fetch("/explore/" + encodeURIComponent(domain) + "?org=1");
        const orgData = await orgRes.json();
        related = Array.isArray(orgData.resources)
          ? orgData.resources.filter((r) => r && r.evidence === "same-domain-host" && typeof r.url === "string" && r.url.startsWith("https://"))
          : [];
      } catch {}
      box.textContent = "";
      if (related.length) {
        renderList(related, "Nothing on " + d + " itself, but " + related.length + " verified resource" + (related.length === 1 ? "" : "s") + " on related hosts under the same domain:");
        const note = document.createElement("p");
        note.className = "meta";
        note.textContent = "Same registrable domain — the relationship is implied by shared DNS control, not independently verified.";
        box.append(note);
        return;
      }
      box.textContent =
        "No supported resources found on " + d + " itself or its common related hosts. " +
        "This is an exact-host check — other subdomains or external registries may still publish machine-readable resources.";
    } catch {
      box.textContent = "Resolve failed. Please try again.";
    }
  });
}
