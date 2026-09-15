// Validate the suspected www-only llms.txt cases with the resolver's OWN
// content rules (validateProbeContent) — an HTTP 200 alone proves nothing on
// SPA hosts that return their shell for every path. Classifies each case as
// genuine / html-shell / empty-or-error, with content-type and a body sample.
import { validateProbeContent } from "../src/worker.js";
import { readFileSync } from "node:fs";

const domains = readFileSync(process.argv[2], "utf8").trim().split(/[\s,]+/).filter(Boolean);
async function probe(u) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), 12000);
  try {
    const r = await fetch(u, { signal: c.signal, redirect: "follow", headers: { "User-Agent": "Mozilla/5.0" } });
    const text = await r.text();
    return { status: r.status, ct: r.headers.get("content-type") || "-", text, finalUrl: r.url };
  } catch (e) {
    return { status: 0, ct: "-", text: "", finalUrl: u };
  } finally {
    clearTimeout(t);
  }
}
let genuine = 0, shell = 0, err = 0;
for (const d of domains) {
  const r = await probe(`https://www.${d}/llms.txt`);
  const valid = r.status === 200 && validateProbeContent("text", r.text);
  const cls = r.status !== 200 ? "error/" + r.status : valid ? "GENUINE" : "html-shell/invalid";
  if (cls === "GENUINE") genuine++; else if (r.status === 200) shell++; else err++;
  console.log(`${d}: ${cls} | ct=${r.ct.split(";")[0]} | final=${r.finalUrl.slice(0, 60)} | head="${r.text.slice(0, 50).replace(/\s+/g, " ")}"`);
}
console.log(`\nsummary: GENUINE=${genuine} html-shell=${shell} error=${err} of ${domains.length}`);
