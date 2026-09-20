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
      // Exact host is empty: answer immediately and honestly, then OFFER the
      // slower related-host check as a separate, explicit action.
      const msg = document.createElement("p");
      msg.textContent =
        "No supported resources could be confirmed on " + d + " itself. This is an exact-host check — " +
        "related hosts (like a developers. subdomain) or external registries may still publish some.";
      box.append(msg);
      const orgBtn = document.createElement("button");
      orgBtn.type = "button";
      orgBtn.textContent = "Check related hosts →";
      box.append(orgBtn);
      orgBtn.addEventListener("click", async () => {
        orgBtn.disabled = true;
        orgBtn.textContent = "Checking related hosts… (up to ~30s)";
        // Client-side hard timeout so the UI can never hang on a slow check.
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 35000);
        let related = null; // null = the check itself failed/timed out
        let checkedHosts = [];
        let rateLimited = false;
        let redirectTarget = null; // the domain's own cross-domain homepage redirect (aws.com → aws.amazon.com)
        try {
          const orgRes = await fetch("/explore/" + encodeURIComponent(domain) + "?org=1", { signal: ctrl.signal });
          if (orgRes.status === 429) {
            rateLimited = true;
          } else {
            const orgData = await orgRes.json();
            if (!orgData.error) {
              related = (Array.isArray(orgData.resources) ? orgData.resources : []).filter(
                (r) => r && r.evidence === "same-domain-host" && typeof r.url === "string" && r.url.startsWith("https://")
              );
              if (Array.isArray(orgData.orgChecked)) checkedHosts = orgData.orgChecked;
              if (orgData.homepageRedirect && typeof orgData.homepageRedirect.to === "string") {
                try { redirectTarget = new URL(orgData.homepageRedirect.to).hostname.replace(/^www\./, ""); } catch {}
              }
            }
          }
        } catch {} finally {
          clearTimeout(timer);
        }
        orgBtn.remove();
        if (rateLimited) {
          const p = document.createElement("p");
          p.className = "meta";
          p.textContent = "Rate limit reached — please wait a minute and try again.";
          box.append(p);
          return;
        }
        if (related === null) {
          const p = document.createElement("p");
          p.className = "meta";
          p.textContent = "The related-host check did not complete in time. Please try again.";
          box.append(p);
          return;
        }
        if (related.length) {
          renderList(related, related.length + " verified resource" + (related.length === 1 ? "" : "s") + " on related hosts under the same domain:");
          const note = document.createElement("p");
          note.className = "meta";
          note.textContent = "Same registrable domain; the organizational relationship is not independently verified.";
          box.append(note);
        } else {
          const p = document.createElement("p");
          p.className = "meta";
          p.textContent =
            (checkedHosts.length
              ? "Checked " + checkedHosts.join(", ") + " — nothing machine-readable was confirmed there. "
              : "Nothing could be confirmed on common related hosts. ") +
            "Note: some sites' bot protection blocks checks from hosted infrastructure, so published files can be missed here.";
          box.append(p);
        }
        // The domain itself redirects to a different registrable domain — the
        // publisher's own configuration. Offer to check that domain instead
        // (its own resolution, under its own authority — never merged in here).
        if (redirectTarget && redirectTarget !== domain) {
          const p = document.createElement("p");
          p.textContent = domain + " itself redirects to " + redirectTarget + " — its resources likely live under that domain.";
          box.append(p);
          const followBtn = document.createElement("button");
          followBtn.type = "button";
          followBtn.textContent = "Check " + redirectTarget + " →";
          followBtn.addEventListener("click", () => {
            $("resolveDomain").value = redirectTarget;
            resolveForm.requestSubmit();
          });
          box.append(followBtn);
        }
      });
    } catch {
      box.textContent = "Resolve failed. Please try again.";
    }
  });
}
