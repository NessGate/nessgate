import { readFileSync, writeFileSync } from "node:fs";
let miss = 0;
const rep = (file, pairs) => {
  let s = readFileSync(file, "utf8");
  for (const [a, b] of pairs) {
    if (!s.includes(a)) { miss++; console.log("MISS:", file, "::", String(a).slice(0, 60).replace(/\n/g, "\\n")); continue; }
    s = s.split(a).join(b);
  }
  writeFileSync(file, s);
};

/* ---------- webbotauth.mjs ---------- */
rep("packages/inspect/webbotauth.mjs", [

// imports: node:dns for the public-address check
[`import { createHash, verify as edVerify, createPublicKey } from "node:crypto";`,
 `import { createHash, verify as edVerify, createPublicKey } from "node:crypto";
import dnsPromises from "node:dns/promises";`],

// component parsing: items may carry parameters (";key=\"label\"" for dictionary members)
[`  const m = rawInner.match(/^\\(([^)]*)\\)/);
  if (!m) return null;
  const components = (m[1].match(/"([^"]*)"/g) || []).map((s) => s.slice(1, -1));`,
 `  const m = rawInner.match(/^\\(([^)]*)\\)/);
  if (!m) return null;
  // Each covered component is a quoted name optionally followed by parameters
  // (e.g. "signature-agent";key="agent2" for a Structured Fields dictionary
  // member, per RFC 9421 §2.1.2). The raw serialization is kept because the
  // signature base must reproduce the identifier exactly as covered.
  const components = [];
  for (const im of m[1].matchAll(/"([^"]+)"((?:;[a-zA-Z0-9_-]+(?:="[^"]*"|=\\d+|=\\?[01])?)*)/g)) {
    const keyM = (im[2] || "").match(/;key="([^"]*)"/);
    components.push({ name: im[1], paramsRaw: im[2] || "", key: keyM ? keyM[1] : null, raw: '"' + im[1] + '"' + (im[2] || "") });
  }`],

// buildSignatureBase: identifiers with params; sf-dictionary member resolution
[`  const lines = [];
  for (const comp of parsed.components) {
    let val;
    switch (comp) {
      case "@method": val = String(request.method || "GET").toUpperCase(); break;
      case "@authority": val = u.host.toLowerCase(); break;
      case "@target-uri": val = u.toString(); break;
      case "@path": val = u.pathname; break;
      case "@scheme": val = u.protocol.replace(":", ""); break;
      case "@query": val = u.search; break;
      default: {
        if (comp.startsWith("@")) return null; // unsupported derived component
        const hv = hget(comp);
        if (hv === undefined) return null; // a covered header is absent → base cannot be built
        val = String(hv).trim();
      }
    }
    lines.push(\`"\${comp}": \${val}\`);
  }`,
 `  const lines = [];
  for (const comp of parsed.components) {
    const name = typeof comp === "string" ? comp : comp.name;
    const key = typeof comp === "string" ? null : comp.key;
    const ident = typeof comp === "string" ? \`"\${comp}"\` : comp.raw;
    let val;
    switch (name) {
      case "@method": val = String(request.method || "GET").toUpperCase(); break;
      case "@authority": val = u.host.toLowerCase(); break;
      case "@target-uri": val = u.toString(); break;
      case "@path": val = u.pathname; break;
      case "@scheme": val = u.protocol.replace(":", ""); break;
      case "@query": val = u.search; break;
      default: {
        if (name.startsWith("@")) return null; // unsupported derived component
        const hv = hget(name);
        if (hv === undefined) return null; // a covered header is absent → base cannot be built
        if (key !== null) {
          // ;key= selects one Structured Fields dictionary member; the component
          // value is that member's serialized item (RFC 9421 §2.1.2).
          const member = sfDictMember(String(hv), key);
          if (member === null) return null;
          val = member;
        } else {
          val = String(hv).trim();
        }
      }
    }
    lines.push(\`\${ident}: \${val}\`);
  }`],

// sfDictMember + dictionary-aware directoryUrl (replacing the bare-string-only one)
[`function directoryUrl(signatureAgent) {
  if (typeof signatureAgent !== "string") return null;
  let v = signatureAgent.trim();
  if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1); // SF string
  try {
    if (/^https:\\/\\//i.test(v)) return new URL(v).toString();
    return new URL("https://" + v + "/.well-known/http-message-signatures-directory").toString();
  } catch { return null; }
}`,
 `// Minimal Structured Fields dictionary reader: label=item pairs, comma-separated.
// Returns the member's RAW serialized item (quotes preserved) or null.
export function sfDictMember(headerValue, key) {
  for (const m of String(headerValue).matchAll(/(?:^|,)\\s*([a-zA-Z*][a-zA-Z0-9_.*-]*)=("(?:[^"\\\\]|\\\\.)*"|[^,]*)/g)) {
    if (m[1] === key) return m[2].trim();
  }
  return null;
}
function sfDictMembers(headerValue) {
  const out = [];
  for (const m of String(headerValue).matchAll(/(?:^|,)\\s*([a-zA-Z*][a-zA-Z0-9_.*-]*)=("(?:[^"\\\\]|\\\\.)*"|[^,]*)/g)) {
    out.push({ key: m[1], raw: m[2].trim() });
  }
  return out;
}

// The Signature-Agent header is a Structured Fields DICTIONARY keyed by the
// signature label (current web-bot-auth drafts); the older bare sf-string form
// is still accepted for backward compatibility. Resolution order: the member
// whose key matches the signature label, else a single-member dictionary's only
// member, else — for the legacy form — the whole value as one sf-string.
function directoryUrl(signatureAgent, label) {
  if (typeof signatureAgent !== "string") return null;
  const toUrl = (s) => {
    let v = s.trim();
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1); // SF string
    try {
      if (/^https:\\/\\//i.test(v)) return new URL(v).toString();
      return new URL("https://" + v + "/.well-known/http-message-signatures-directory").toString();
    } catch { return null; }
  };
  const v = signatureAgent.trim();
  // Dictionary form: label="…" (the legacy form starts with a quote instead).
  if (/^[a-zA-Z*][a-zA-Z0-9_.*-]*=/.test(v)) {
    const exact = label ? sfDictMember(v, label) : null;
    if (exact !== null) return toUrl(exact);
    const members = sfDictMembers(v);
    if (members.length === 1) return toUrl(members[0].raw);
    return null; // several members, none matching this signature's label: ambiguous
  }
  return toUrl(v);
}`],

// hardened fetch core replacing safeFetchJson + guard
[`const badHost = (h) => {
  h = String(h || "").toLowerCase().replace(/\\.+$/, "");
  return !h || h === "localhost" || h.endsWith(".local") || h.endsWith(".internal") ||
    /^\\d{1,3}(\\.\\d{1,3}){3}$/.test(h) || h.includes(":") ||
    /^(10|127)\\./.test(h) || /^192\\.168\\./.test(h) || /^169\\.254\\./.test(h) || /^172\\.(1[6-9]|2\\d|3[01])\\./.test(h);
};

// Shared read-only JSON GET with the same https-only + host guard. Used by the
// agent-card signal too. Returns { json, finalUrl } or { error, status? }.
export async function safeFetchJson(fetchImpl, url, timeoutMs) {
  let u;
  try { u = new URL(url); } catch { return { error: "bad url" }; }
  if (u.protocol !== "https:" || badHost(u.hostname)) return { error: "host not allowed" };
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs || 8000);
  try {
    const res = await fetchImpl(url, { redirect: "follow", signal: ac.signal, headers: { accept: "application/json" } });
    if (!res.ok) return { error: "HTTP " + res.status, status: res.status };
    return { json: JSON.parse(await res.text()), finalUrl: (typeof res.url === "string" && res.url) || url };
  } catch (e) {
    return { error: String(e && e.message || e) };
  } finally { clearTimeout(t); }
}`,
 `const badHost = (h) => {
  h = String(h || "").toLowerCase().replace(/\\.+$/, "");
  return !h || h === "localhost" || h.endsWith(".local") || h.endsWith(".internal") ||
    /^\\d{1,3}(\\.\\d{1,3}){3}$/.test(h) || h.includes(":") ||
    /^(10|127)\\./.test(h) || /^192\\.168\\./.test(h) || /^169\\.254\\./.test(h) || /^172\\.(1[6-9]|2\\d|3[01])\\./.test(h);
};

// Every URL fetched here comes from attacker-influenceable request data, so the
// fetch core enforces: https-only; hostname guard; a DNS pre-check rejecting
// hosts whose A/AAAA answers include private/loopback/link-local space; manual
// redirects with EVERY hop re-validated (scheme, host guard, DNS); a hard
// response-size cap; and bounded hop count. The DNS pre-check narrows (but, with
// a platform fetch that re-resolves, cannot fully close) the DNS-rebinding
// window — full immunity needs a pinned-address dispatcher, which a portable
// library cannot impose. opts.dns is injectable for deterministic tests.
const MAX_RESPONSE_BYTES = 262144;
const MAX_REDIRECTS = 3;
const MAX_JWKS_KEYS = 32;

function privateIp(ip) {
  let v = String(ip || "").toLowerCase();
  const m4 = v.match(/^::ffff:(\\d+\\.\\d+\\.\\d+\\.\\d+)$/);
  if (m4) v = m4[1];
  if (/^\\d{1,3}(\\.\\d{1,3}){3}$/.test(v)) {
    const o = v.split(".").map(Number);
    return o[0] === 0 || o[0] === 10 || o[0] === 127 ||
      (o[0] === 100 && o[1] >= 64 && o[1] <= 127) ||
      (o[0] === 169 && o[1] === 254) ||
      (o[0] === 172 && o[1] >= 16 && o[1] <= 31) ||
      (o[0] === 192 && o[1] === 168) ||
      (o[0] === 192 && o[1] === 0) ||
      (o[0] === 198 && (o[1] === 18 || o[1] === 19));
  }
  return v === "::" || v === "::1" || v.startsWith("fc") || v.startsWith("fd") ||
    v.startsWith("fe8") || v.startsWith("fe9") || v.startsWith("fea") || v.startsWith("feb");
}

async function assertPublicDns(host, dnsImpl) {
  const dns = dnsImpl || dnsPromises;
  let a4 = [], a6 = [];
  try { a4 = await dns.resolve4(host); } catch {}
  try { a6 = await dns.resolve6(host); } catch {}
  const all = [...a4, ...a6];
  if (!all.length) throw new Error("host does not resolve");
  for (const ip of all) if (privateIp(ip)) throw new Error("host resolves to a private or reserved address");
}

async function readBoundedText(res) {
  if (res.body && typeof res.body.getReader === "function") {
    const reader = res.body.getReader();
    const chunks = [];
    let size = 0;
    while (size <= MAX_RESPONSE_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      chunks.push(value);
    }
    try { await reader.cancel(); } catch {}
    if (size > MAX_RESPONSE_BYTES) throw new Error("response exceeds the " + MAX_RESPONSE_BYTES + "-byte limit");
    return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf8");
  }
  const text = await res.text();
  if (text.length > MAX_RESPONSE_BYTES) throw new Error("response exceeds the " + MAX_RESPONSE_BYTES + "-byte limit");
  return text;
}

// Shared read-only JSON GET over the hardened core. Used by the agent-card and
// network-attribution signals too. Returns { json, finalUrl } or { error, status? }.
export async function safeFetchJson(fetchImpl, url, timeoutMs, opts = {}) {
  let current;
  try { current = new URL(url); } catch { return { error: "bad url" }; }
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs || 8000);
  try {
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      if (current.protocol !== "https:" || badHost(current.hostname)) return { error: "host not allowed" };
      try { await assertPublicDns(current.hostname, opts.dns); } catch (e) { return { error: "host not allowed (" + (e && e.message) + ")" }; }
      const res = await fetchImpl(current.toString(), { redirect: "manual", signal: ac.signal, headers: { accept: "application/json" } });
      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers && typeof res.headers.get === "function" ? res.headers.get("location") : null;
        if (!loc) return { error: "redirect without a location", status: res.status };
        try { current = new URL(loc, current); } catch { return { error: "bad redirect target" }; }
        continue; // next hop is fully re-validated at the top of the loop
      }
      if (!res.ok) return { error: "HTTP " + res.status, status: res.status };
      const text = await readBoundedText(res);
      return { json: JSON.parse(text), finalUrl: current.toString() };
    }
    return { error: "too many redirects (limit " + MAX_REDIRECTS + ")" };
  } catch (e) {
    return { error: String(e && e.message || e) };
  } finally { clearTimeout(t); }
}`],

// keyForKeyid: reuse the hardened core + key-count cap + key sanity
[`async function keyForKeyid(fetchImpl, dirUrl, keyid, timeoutMs) {
  let u;
  try { u = new URL(dirUrl); } catch { return { error: "bad directory url" }; }
  if (u.protocol !== "https:" || badHost(u.hostname)) return { error: "directory host not allowed" };
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs || 8000);
  try {
    const res = await fetchImpl(dirUrl, { redirect: "follow", signal: ac.signal, headers: { accept: "application/json" } });
    if (!res.ok) return { error: "directory HTTP " + res.status };
    const doc = JSON.parse(await res.text());
    const keys = Array.isArray(doc.keys) ? doc.keys : [];
    for (const jwk of keys) {
      if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519") continue;
      const tp = rfc7638ThumbprintOKP(jwk);
      if (tp === keyid || jwk.kid === keyid) return { jwk, matchedBy: jwk.kid === keyid ? "kid" : "thumbprint" };
    }
    return { error: "no key in directory matches keyid" };
  } catch (e) {
    return { error: "directory fetch failed: " + (e && e.message || e) };
  } finally { clearTimeout(t); }
}`,
 `async function keyForKeyid(fetchImpl, dirUrl, keyid, timeoutMs, opts = {}) {
  const r = await safeFetchJson(fetchImpl, dirUrl, timeoutMs, opts);
  if (r.error) return { error: "directory: " + r.error };
  const all = Array.isArray(r.json && r.json.keys) ? r.json.keys : [];
  const keys = all.slice(0, MAX_JWKS_KEYS); // bounded work on attacker-sized input
  for (const jwk of keys) {
    if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519") continue;
    if (typeof jwk.x !== "string" || jwk.x.length > 128) continue; // an Ed25519 x is 43 base64url chars
    const tp = rfc7638ThumbprintOKP(jwk);
    if (tp === keyid || jwk.kid === keyid) return { jwk, matchedBy: jwk.kid === keyid ? "kid" : "thumbprint" };
  }
  return { error: "no key in directory matches keyid" + (all.length > MAX_JWKS_KEYS ? " (directory inspected up to the " + MAX_JWKS_KEYS + "-key limit)" : "") };
}`],
]);

console.log(miss ? `webbotauth: ${miss} MISSES` : "webbotauth hardened + SF dictionary");
if (miss) process.exit(1);
