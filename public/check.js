"use strict";

const $ = (id) => document.getElementById(id);

const PROBE_INFO = {
  "llms.txt": {
    label: "llms.txt",
    what: "A plain-text guidance file for AI assistants at /llms.txt.",
    ifMissing: "Easy to add. Adoption is growing, though AI crawlers consume it inconsistently today.",
  },
  "ard-catalog": {
    label: "ARD catalog (ard.json)",
    what: "The Agentic Resource Discovery catalog — the Google/Microsoft/AWS-backed location for declaring your machine resources (/.well-known/ard.json).",
    ifMissing: "The newest major standard. Add an /.well-known/ard.json listing your machine-readable resources.",
  },
  "a2a-agent-card": {
    label: "A2A agent card",
    what: "How agents advertise capabilities under Google's A2A protocol (/.well-known/agent-card.json).",
    ifMissing: "Only relevant if you operate an AI agent others should be able to call.",
  },
  "api-catalog": {
    label: "API catalog (RFC 9727)",
    what: "The IETF standard location listing your public APIs (/.well-known/api-catalog).",
    ifMissing: "Worth adding if you publish APIs for developers or agents.",
  },
  "ai-info.json": {
    label: "ai-info.json",
    what: "A machine-readable company/product info file AI systems can read directly.",
    ifMissing: "A simple JSON file about who you are and what you offer — any structure you like.",
  },
  openapi: {
    label: "OpenAPI description",
    what: "A machine-readable description of your API at /openapi.json.",
    ifMissing: "Standard practice if you have a public API.",
  },
  ord: {
    label: "Open Resource Discovery",
    what: "The SAP / Linux Foundation ORD document (/.well-known/open-resource-discovery).",
    ifMissing: "Mostly relevant for enterprise API landscapes.",
  },
  awp: {
    label: "AWP manifest (provisional)",
    what: "An AWP manifest routing agents to your other protocols (/.well-known/awp.json).",
    ifMissing: "Optional aggregator manifest; only needed if you adopt AWP.",
  },
  "host-meta": {
    label: "host-meta (RFC 6415)",
    what: "A well-known links document (/.well-known/host-meta.json).",
    ifMissing: "Legacy web-linking mechanism; rarely required today.",
  },
  anp: {
    label: "Agent Network Protocol",
    what: "An ANP agent-descriptions document (/.well-known/agent-descriptions).",
    ifMissing: "Emerging agent standard; only relevant if you adopt ANP.",
    core: false,
  },
  ucp: {
    label: "Universal Commerce Protocol",
    what: "A UCP merchant profile (/.well-known/ucp).",
    ifMissing: "Emerging commerce standard from Google and Shopify; only relevant for merchants adopting UCP.",
    core: false,
  },
  "ard-link": {
    label: "ARD via rel=ard link",
    what: "An ARD catalog discovered through a <link rel=\"ard\"> tag in your homepage.",
    ifMissing: "Optional extra ARD surface; the well-known ard.json path is the primary one.",
    core: false,
  },
  "ard-agentmap": {
    label: "ARD via robots Agentmap",
    what: "An ARD catalog discovered through an Agentmap: directive in /robots.txt.",
    ifMissing: "Optional extra ARD surface; the well-known ard.json path is the primary one.",
    core: false,
  },
  "aid": {
    label: "AID (TXT record)",
    what: "An AID TXT record at _agent.<domain> (v=aid1;u=…) pointing to your agent (draft AID spec). Note: this is distinct from the IETF DNS-AID draft, which uses SVCB records at _agents.<domain>.",
    ifMissing: "Draft DNS-based discovery; optional and not yet widely adopted.",
    core: false,
  },
};

function row(found, label, detail, url) {
  const p = document.createElement("p");
  p.className = "res-line";
  const tag = document.createElement("span");
  tag.className = "res-tag " + (found ? "found" : "miss");
  tag.textContent = found ? "✓ found" : "— missing";
  const name = document.createElement("strong");
  name.textContent = label + " ";
  p.append(tag, document.createTextNode(" "), name);
  if (url) {
    const a = document.createElement("a");
    a.href = url;
    a.rel = "nofollow";
    a.textContent = url.replace(/^https:\/\//, "");
    p.append(a);
  }
  const d = document.createElement("span");
  d.className = "hint probe-detail";
  d.textContent = detail;
  p.append(d);
  return p;
}

$("checkForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = e.target.querySelector("button");
  const err = $("checkError");
  err.hidden = true;
  btn.disabled = true;
  btn.textContent = "Checking…";
  const domain = $("checkDomain").value.trim();
  try {
    const discRes = await fetch("/discover/" + encodeURIComponent(domain));
    const disc = await discRes.json();
    if (discRes.status === 400 || (disc.error && discRes.status !== 200)) {
      throw new Error(disc.error || "Could not check this domain.");
    }

    // Readiness report: which supported discovery files this domain publishes,
    // read on demand via the NessGate resolver.
    const pCard = $("probeCard");
    pCard.textContent = "";
    const foundTypes = new Map((disc.discovered || []).map((x) => [x.type, x.url]));
    let foundCount = 0;
    const checked = disc.checked && disc.checked.length ? disc.checked : Object.keys(PROBE_INFO);
    for (const key of checked) {
      const info = PROBE_INFO[key] || { label: key, what: "", ifMissing: "" };
      const url = foundTypes.get(key);
      if (url) foundCount++;
      pCard.append(row(!!url, info.label, url ? info.what : info.ifMissing, url || null));
    }
    const summary = document.createElement("p");
    summary.className = "meta probe-summary";
    summary.textContent =
      foundCount === 0
        ? "No supported discovery files could be confirmed on this exact host. Related product hosts or external registries may still publish some."
        : `You support ${foundCount} of ${checked.length} supported discovery mechanisms.`;
    pCard.append(summary);

    $("report").hidden = false;
    $("report").scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (ex) {
    err.hidden = false;
    err.textContent = ex.message || "Check failed. Please try again.";
  } finally {
    btn.disabled = false;
    btn.textContent = "Check";
  }
});
