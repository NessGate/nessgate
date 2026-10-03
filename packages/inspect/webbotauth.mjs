// Web Bot Auth verification — RFC 9421 HTTP Message Signatures, Ed25519,
// implemented against draft-ietf-webbotauth-httpsig-protocol-00 (the active
// IETF WG protocol draft) and verified against its Appendix E.2 test vectors.
//
// This is the ONE place NessGate Inspect does cryptography. It reuses existing
// standards verbatim — RFC 9421 (message signatures), RFC 9651 (structured
// fields), RFC 7638 / RFC 8037 (JWK thumbprints) — and invents nothing. A
// successful verification proves exactly one thing: the holder of the named key
// signed THIS request, binding the listed components. It does NOT establish who
// operates the agent, nor any authorization — the profile says so explicitly,
// and inspect.mjs surfaces that limit on every result.

import { createPublicKey, verify as edVerify, createHash } from "node:crypto";
import dnsPromises from "node:dns/promises";

const WBA_PROFILE = "draft-ietf-webbotauth-httpsig-protocol-00";
const DIRECTORY_WELL_KNOWN = "/.well-known/http-message-signatures-directory";

// --- structured-field parsing (minimal, for the Web Bot Auth shapes) --------

// One Signature-Input member:
//   sig2=("@authority" "signature-agent";key="agent2");created=..;keyid="..";alg="ed25519";expires=..;tag="web-bot-auth"
export function parseSignatureInput(h) {
  if (typeof h !== "string") return null;
  const eq = h.indexOf("=");
  if (eq < 1) return null;
  const label = h.slice(0, eq).trim();
  const rawInner = h.slice(eq + 1).trim(); // used VERBATIM as the @signature-params value (RFC 9421 §2.3)
  const m = rawInner.match(/^\(([^)]*)\)/);
  if (!m) return null;
  // Each covered component is a quoted name optionally followed by parameters
  // (e.g. "signature-agent";key="agent2" for a Structured Fields dictionary
  // member, per RFC 9421 §2.1.2). The raw serialization is kept because the
  // signature base must reproduce the identifier exactly as covered.
  const components = [];
  for (const im of m[1].matchAll(/"([^"]+)"((?:;[a-zA-Z0-9_-]+(?:="[^"]*"|=\d+|=\?[01])?)*)/g)) {
    const keyM = (im[2] || "").match(/;key="([^"]*)"/);
    components.push({ name: im[1], paramsRaw: im[2] || "", key: keyM ? keyM[1] : null, raw: '"' + im[1] + '"' + (im[2] || "") });
  }
  const params = {};
  for (const p of rawInner.slice(m[0].length).split(";")) {
    const t = p.trim();
    if (!t) continue;
    const i = t.indexOf("=");
    if (i < 0) { params[t] = true; continue; }
    const k = t.slice(0, i).trim();
    let v = t.slice(i + 1).trim();
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
    else if (/^\d+$/.test(v)) v = Number(v);
    params[k] = v;
  }
  return { label, components, params, rawInner };
}

// ALL members of a Signature-Input dictionary (a request may carry several
// signatures). Quote-aware scan; each member is handed to parseSignatureInput.
export function parseSignatureInputDict(h) {
  if (typeof h !== "string") return [];
  const out = [];
  const s = h;
  let i = 0;
  while (i < s.length) {
    while (i < s.length && /[\s,]/.test(s[i])) i++;
    const lm = /^([A-Za-z*][A-Za-z0-9_.*-]*)=/.exec(s.slice(i));
    if (!lm) break;
    i += lm[0].length;
    if (s[i] !== "(") break;
    const close = s.indexOf(")", i); // component names are quoted strings; "(" cannot appear inside them
    if (close < 0) break;
    let j = close + 1, inQ = false;
    while (j < s.length) {
      const c = s[j];
      if (c === '"' && s[j - 1] !== "\\") inQ = !inQ;
      else if (c === "," && !inQ && /^\s*[A-Za-z*][A-Za-z0-9_.*-]*=\(/.test(s.slice(j + 1))) break;
      j++;
    }
    const parsed = parseSignatureInput(lm[1] + "=" + s.slice(i, j).trim());
    if (parsed) out.push(parsed);
    i = j + 1;
  }
  return out;
}

// Signature: sig1=:<base64>:
export function parseSignature(h, label) {
  if (typeof h !== "string") return null;
  const re = new RegExp(label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\s*=\\s*:([A-Za-z0-9+/=]*):");
  const m = h.match(re);
  if (!m) return null;
  try { return Buffer.from(m[1], "base64"); } catch { return null; }
}

// RFC 9651 Dictionary of String items, parameters preserved. Returns
// [{ key, raw (item + its parameters, serialized), value (unquoted string),
//    params: { name: value } }].
export function parseSfDict(headerValue) {
  const out = [];
  const re = /(?:^|,)\s*([a-zA-Z*][a-zA-Z0-9_.*-]*)=("(?:[^"\\]|\\.)*"|[^,;\s]*)((?:\s*;\s*[a-zA-Z*][a-zA-Z0-9_.*-]*(?:=(?:"(?:[^"\\]|\\.)*"|[^;,\s]*))?)*)/g;
  for (const m of String(headerValue || "").matchAll(re)) {
    const itemRaw = m[2].trim();
    const paramsRaw = (m[3] || "").trim();
    const params = {};
    for (const pm of paramsRaw.matchAll(/;\s*([a-zA-Z*][a-zA-Z0-9_.*-]*)(?:=("(?:[^"\\]|\\.)*"|[^;,\s]*))?/g)) {
      let v = pm[2] === undefined ? true : pm[2];
      if (typeof v === "string" && v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
      params[pm[1]] = v;
    }
    const value = itemRaw.startsWith('"') && itemRaw.endsWith('"') ? itemRaw.slice(1, -1).replace(/\\(.)/g, "$1") : itemRaw;
    out.push({ key: m[1], raw: itemRaw + (paramsRaw ? paramsRaw : ""), value, params });
  }
  return out;
}

// The RAW serialized member (item + parameters) for ;key= base construction
// (RFC 9421 §2.1.2 covers the member including its parameters), or null.
export function sfDictMember(headerValue, key) {
  for (const m of parseSfDict(headerValue)) if (m.key === key) return m.raw;
  return null;
}

// --- RFC 9421 signature base -------------------------------------------------
// headerGet is case-insensitive over a plain {name:value} object.
export function buildSignatureBase(request, parsed) {
  let u;
  try { u = new URL(request.url); } catch { return null; }
  const headers = request.headers || {};
  const hget = (n) => { for (const k in headers) if (k.toLowerCase() === n.toLowerCase()) return headers[k]; return undefined; };
  const lines = [];
  for (const comp of parsed.components) {
    const name = typeof comp === "string" ? comp : comp.name;
    const key = typeof comp === "string" ? null : comp.key;
    const ident = typeof comp === "string" ? `"${comp}"` : comp.raw;
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
          // value is that member's serialization INCLUDING its parameters
          // (RFC 9421 §2.1.2).
          const member = sfDictMember(String(hv), key);
          if (member === null) return null;
          val = member;
        } else {
          val = String(hv).trim();
        }
      }
    }
    lines.push(`${ident}: ${val}`);
  }
  lines.push(`"@signature-params": ${parsed.rawInner}`);
  return lines.join("\n");
}

// --- JWK thumbprint (RFC 7638; OKP form per RFC 8037 A.3) --------------------
export function rfc7638ThumbprintOKP(jwk) {
  // Lexical JSON of the required members only.
  const json = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}"}`;
  return createHash("sha256").update(json).digest("base64url");
}

// --- hardened fetch core ------------------------------------------------------
const badHost = (h) => {
  h = String(h || "").toLowerCase().replace(/\.+$/, "");
  return !h || h === "localhost" || h.endsWith(".local") || h.endsWith(".internal") ||
    /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(":") ||
    /^(10|127)\./.test(h) || /^192\.168\./.test(h) || /^169\.254\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h);
};

// Every URL fetched here comes from attacker-influenceable request data, so the
// fetch core enforces: https-only; hostname guard; a DNS pre-check rejecting
// hosts whose A/AAAA answers include private/loopback/link-local space; manual
// redirect handling with EVERY permitted hop re-validated (scheme, host guard,
// DNS); a hard response-size cap; and a bounded hop count. Web Bot Auth key
// discovery passes maxRedirects: 0 — the profile forbids following redirects
// there outright. The DNS pre-check narrows (but, with a platform fetch that
// re-resolves, cannot fully close) the DNS-rebinding window — full immunity
// needs a pinned-address dispatcher, which a portable library cannot impose.
// opts.dns is injectable for deterministic tests.
const MAX_RESPONSE_BYTES = 262144;
const MAX_REDIRECTS = 3;
const MAX_JWKS_KEYS = 32;

function privateIp(ip) {
  let v = String(ip || "").toLowerCase();
  const m4 = v.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (m4) v = m4[1];
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) {
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
// network-attribution signals too. opts.maxRedirects: 0 refuses ANY redirect
// (required for Web Bot Auth key discovery). Returns { json, finalUrl } or
// { error, status? }.
export async function safeFetchJson(fetchImpl, url, timeoutMs, opts = {}) {
  let current;
  try { current = new URL(url); } catch { return { error: "bad url" }; }
  const maxRedirects = typeof opts.maxRedirects === "number" ? opts.maxRedirects : MAX_REDIRECTS;
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs || 8000);
  try {
    for (let hop = 0; hop <= maxRedirects; hop++) {
      if (current.protocol !== "https:" || badHost(current.hostname)) return { error: "host not allowed" };
      try { await assertPublicDns(current.hostname, opts.dns); } catch (e) { return { error: "host not allowed (" + (e && e.message) + ")" }; }
      const res = await fetchImpl(current.toString(), { redirect: "manual", signal: ac.signal, headers: { accept: "application/json" } });
      if (res.status >= 300 && res.status < 400) {
        if (maxRedirects === 0) return { error: "HTTP " + res.status + " (redirects are not followed here)", status: res.status };
        const loc = res.headers && typeof res.headers.get === "function" ? res.headers.get("location") : null;
        if (!loc) return { error: "redirect without a location", status: res.status };
        try { current = new URL(loc, current); } catch { return { error: "bad redirect target" }; }
        continue; // next hop is fully re-validated at the top of the loop
      }
      if (!res.ok) return { error: "HTTP " + res.status, status: res.status };
      const text = await readBoundedText(res);
      return { json: JSON.parse(text), finalUrl: current.toString() };
    }
    return { error: "too many redirects (limit " + maxRedirects + ")" };
  } catch (e) {
    return { error: String(e && e.message || e) };
  } finally { clearTimeout(t); }
}

// Fetch a JWK Set and return the key whose RFC 7638 / RFC 8037 thumbprint equals
// keyid. The profile REQUIRES keyid to be the thumbprint, so a kid match alone
// never suffices. The profile also forbids following redirects during discovery
// (maxRedirects: 0) and requires a 200 answer.
async function keyByThumbprint(fetchImpl, keysUrl, keyid, timeoutMs, opts = {}) {
  const r = await safeFetchJson(fetchImpl, keysUrl, timeoutMs, { ...opts, maxRedirects: 0 });
  if (r.error) return { error: "key discovery: " + r.error };
  const all = Array.isArray(r.json && r.json.keys) ? r.json.keys : [];
  const keys = all.slice(0, MAX_JWKS_KEYS); // bounded work on attacker-sized input
  for (const jwk of keys) {
    if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519") continue;
    if (typeof jwk.x !== "string" || jwk.x.length > 128) continue; // an Ed25519 x is 43 base64url chars
    if (rfc7638ThumbprintOKP(jwk) === keyid) return { jwk };
    if (jwk.kid === keyid) return { error: "a key's kid matches, but keyid must be the key's JWK thumbprint under this profile" };
  }
  return { error: "no key in the JWK Set has a thumbprint matching keyid" + (all.length > MAX_JWKS_KEYS ? " (inspected up to the " + MAX_JWKS_KEYS + "-key limit)" : "") };
}

// Resolve WHERE the verification key lives, from the Signature-Agent header and
// the covered component, per the protocol draft:
// - The covered "signature-agent";key=K component names dictionary member K;
//   that member (and no other) is the one the signature binds, so that member
//   (and no other) drives discovery.
// - Member parameter `type` (default "directory") names the mechanism:
//   directory  → the value MUST be an origin; keys live at its well-known path.
//   jwks_uri   → the value IS the JWK Set URI.
//   anything else (including cimd, which this verifier does not implement) →
//   the member MUST be ignored; the mechanism is NEVER inferred.
// - The legacy bare sf-string form (covered as plain "signature-agent") is
//   accepted for migration, resolved as a directory URL/origin.
function resolveKeySource(signatureAgent, coveredKey) {
  if (typeof signatureAgent !== "string" || !signatureAgent.trim()) return { error: "no Signature-Agent header" };
  const v = signatureAgent.trim();
  const isDict = /^[a-zA-Z*][a-zA-Z0-9_.*-]*=/.test(v);
  const originKeysUrl = (s) => {
    let u;
    try { u = new URL(/^https:\/\//i.test(s) ? s : "https://" + s); } catch { return null; }
    if (u.protocol !== "https:" || (u.pathname !== "/" && u.pathname !== "") || u.search || u.hash) return null;
    return u.origin + DIRECTORY_WELL_KNOWN;
  };
  if (coveredKey !== null) {
    if (!isDict) return { error: 'the signature covers "signature-agent";key but the header is not a dictionary' };
    const member = parseSfDict(v).find((m) => m.key === coveredKey);
    if (!member) return { error: `the covered Signature-Agent member "${coveredKey}" is absent from the header` };
    const type = member.params.type === undefined ? "directory" : String(member.params.type);
    if (type === "directory") {
      const keysUrl = originKeysUrl(member.value);
      if (!keysUrl) return { error: "a directory-type Signature-Agent member must be an https origin" };
      return { type, keysUrl };
    }
    if (type === "jwks_uri") {
      if (!/^https:\/\//i.test(member.value)) return { error: "a jwks_uri Signature-Agent member must be an https URI" };
      return { type, keysUrl: member.value };
    }
    // cimd and anything unknown: the profile says ignore the member and never
    // infer the mechanism — with no usable member left, discovery fails honestly.
    return { error: `Signature-Agent type "${type}" is not supported by this verifier; the member is ignored as the profile requires` };
  }
  // Plain "signature-agent" coverage: the legacy single sf-string form.
  if (isDict) return { error: "plain signature-agent coverage with a dictionary-form header is not supported" };
  let s = v;
  if (s.startsWith('"') && s.endsWith('"')) s = s.slice(1, -1);
  try {
    if (/^https:\/\//i.test(s)) {
      const u = new URL(s);
      const keysUrl = (u.pathname === "/" || u.pathname === "") ? u.origin + DIRECTORY_WELL_KNOWN : u.toString();
      return { type: "directory", keysUrl, legacy: true };
    }
    return { type: "directory", keysUrl: new URL("https://" + s + DIRECTORY_WELL_KNOWN).toString(), legacy: true };
  } catch { return { error: "unusable legacy Signature-Agent value" }; }
}

// Verify a Web Bot Auth signed request against the WG protocol profile.
// Returns a structured result — never throws:
//   { present, verified, reason?, profile, keyid, algorithm, components,
//     created, expires, expired, directory, keySource }
// cryptographically-verified is returned ONLY when the profile holds in full:
// a single web-bot-auth-tagged signature; created AND expires present; keyid is
// the key's JWK thumbprint; at least @authority or @target-uri covered; the
// Signature-Agent member the discovery used is itself covered by the signature.
export async function verifyWebBotAuth(request, opts = {}) {
  const fetchImpl = opts.fetch || globalThis.fetch;
  const now = typeof opts.now === "number" ? opts.now : Math.floor(Date.now() / 1000);
  const headers = request.headers || {};
  const hget = (n) => { for (const k in headers) if (k.toLowerCase() === n.toLowerCase()) return headers[k]; return undefined; };

  const sigInput = hget("signature-input");
  const sig = hget("signature");
  if (!sigInput || !sig) return { present: false };

  const members = parseSignatureInputDict(sigInput);
  if (!members.length) return { present: true, verified: false, profile: WBA_PROFILE, reason: "unparseable Signature-Input" };
  const tagged = members.filter((p) => p.params.tag === "web-bot-auth");
  if (!tagged.length) return { present: true, verified: false, profile: WBA_PROFILE, reason: 'no signature is tagged "web-bot-auth" (the profile requires the tag)' };
  if (tagged.length > 1) return { present: true, verified: false, profile: WBA_PROFILE, reason: "several signatures are tagged web-bot-auth; refusing to pick one rather than misattribute" };
  const parsed = tagged[0];

  const out = {
    present: true, verified: false, profile: WBA_PROFILE,
    keyid: parsed.params.keyid, algorithm: parsed.params.alg,
    components: parsed.components.map((c) => (typeof c === "string" ? c : c.name + c.paramsRaw)),
    created: parsed.params.created, expires: parsed.params.expires,
    tag: parsed.params.tag,
  };
  if (parsed.params.alg && String(parsed.params.alg).toLowerCase() !== "ed25519")
    return { ...out, reason: `unsupported alg "${parsed.params.alg}" (this verifier implements ed25519 only)` };
  if (typeof parsed.params.created !== "number") return { ...out, reason: "the profile requires a created parameter" };
  if (typeof parsed.params.expires !== "number") return { ...out, reason: "the profile requires an expires parameter" };
  if (!parsed.params.keyid) return { ...out, reason: "no keyid in Signature-Input" };
  if (!parsed.components.some((c) => c.name === "@authority" || c.name === "@target-uri"))
    return { ...out, reason: "the profile requires @authority or @target-uri among the covered components" };

  const saComp = parsed.components.find((c) => c.name === "signature-agent");
  if (!saComp) return { ...out, reason: "the profile requires the Signature-Agent member used for discovery to be covered by the signature" };

  const signature = parseSignature(sig, parsed.label);
  if (!signature) return { ...out, reason: "unparseable or missing Signature value for " + parsed.label };

  const base = buildSignatureBase(request, parsed);
  if (base == null) return { ...out, reason: "could not reconstruct signature base (a covered component is absent)" };

  const src = resolveKeySource(hget("signature-agent"), saComp.key);
  if (src.error) return { ...out, reason: src.error };
  out.directory = src.keysUrl;
  out.keySource = { type: src.type, url: src.keysUrl, ...(src.legacy ? { legacy: true } : {}) };

  const found = await keyByThumbprint(fetchImpl, src.keysUrl, parsed.params.keyid, opts.timeoutMs, { dns: opts.dns });
  if (found.error) return { ...out, reason: found.error };
  out.matchedBy = "thumbprint";

  let keyObj;
  try { keyObj = createPublicKey({ key: found.jwk, format: "jwk" }); } catch (e) { return { ...out, reason: "bad JWK: " + (e && e.message) }; }
  let ok = false;
  try { ok = edVerify(null, Buffer.from(base, "utf8"), keyObj, signature); } catch (e) { return { ...out, reason: "verify error: " + (e && e.message) }; }
  if (!ok) return { ...out, reason: "signature does not validate against the discovered key" };

  // Cryptographically valid under the profile. Expiry is a freshness fact,
  // surfaced for the relying party (inspect.mjs downgrades expired to claimed).
  const expired = out.expires < now;
  return { ...out, verified: true, expired };
}
