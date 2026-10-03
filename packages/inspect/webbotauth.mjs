// Web Bot Auth verification (lab-only) — RFC 9421 HTTP Message Signatures,
// Ed25519, verified against a key fetched from the caller's declared directory.
//
// This is the ONE place NessGate Inspect does cryptography. It reuses existing
// standards verbatim — RFC 9421 (message signatures), RFC 7638 (JWK thumbprint),
// the Web Bot Auth profile (Ed25519 keys, a `Signature-Agent` directory) — and
// invents nothing. A successful verification proves exactly one thing: the holder
// of the named key signed THIS request, binding the listed components. It does
// NOT establish who operates the agent, nor any authorization — the Web Bot Auth
// spec says so explicitly, and inspect.mjs surfaces that limit on every result.

import { createPublicKey, verify as edVerify, createHash } from "node:crypto";

// --- structured-field parsing (minimal, for the Web Bot Auth shape) ---------

// Signature-Input: sig1=("@method" "@authority" "signature-agent");created=..;keyid="..";alg="ed25519";expires=..;tag="web-bot-auth"
export function parseSignatureInput(h) {
  if (typeof h !== "string") return null;
  const eq = h.indexOf("=");
  if (eq < 1) return null;
  const label = h.slice(0, eq).trim();
  const rawInner = h.slice(eq + 1).trim(); // used VERBATIM as the @signature-params value (RFC 9421 §2.3)
  const m = rawInner.match(/^\(([^)]*)\)/);
  if (!m) return null;
  const components = (m[1].match(/"([^"]*)"/g) || []).map((s) => s.slice(1, -1));
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

// Signature: sig1=:<base64>:
export function parseSignature(h, label) {
  if (typeof h !== "string") return null;
  const re = new RegExp(label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\s*=\\s*:([A-Za-z0-9+/=]*):");
  const m = h.match(re);
  if (!m) return null;
  try { return Buffer.from(m[1], "base64"); } catch { return null; }
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
    lines.push(`"${comp}": ${val}`);
  }
  lines.push(`"@signature-params": ${parsed.rawInner}`);
  return lines.join("\n");
}

// --- key directory (Web Bot Auth) -------------------------------------------
export function rfc7638ThumbprintOKP(jwk) {
  // Lexical JSON of the required members only, per RFC 7638.
  const json = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}"}`;
  return createHash("sha256").update(json).digest("base64url");
}

function directoryUrl(signatureAgent) {
  if (typeof signatureAgent !== "string") return null;
  let v = signatureAgent.trim();
  if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1); // SF string
  try {
    if (/^https:\/\//i.test(v)) return new URL(v).toString();
    return new URL("https://" + v + "/.well-known/http-message-signatures-directory").toString();
  } catch { return null; }
}

const badHost = (h) => {
  h = String(h || "").toLowerCase().replace(/\.+$/, "");
  return !h || h === "localhost" || h.endsWith(".local") || h.endsWith(".internal") ||
    /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(":") ||
    /^(10|127)\./.test(h) || /^192\.168\./.test(h) || /^169\.254\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h);
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
}

// Fetch the JWKS and return the public JWK whose thumbprint or kid matches keyid.
// SSRF note: the directory URL comes from an attacker-influenceable header, so it
// is https-only + host-guarded. Caller passes opts.fetch; nothing is cached/stored.
async function keyForKeyid(fetchImpl, dirUrl, keyid, timeoutMs) {
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
}

// Verify a Web Bot Auth signed request. Returns a structured result — never throws.
//   { present, verified, reason?, keyid, algorithm, components, created, expires,
//     expired, directory, matchedBy }
export async function verifyWebBotAuth(request, opts = {}) {
  const fetchImpl = opts.fetch || globalThis.fetch;
  const now = typeof opts.now === "number" ? opts.now : Math.floor(Date.now() / 1000);
  const headers = request.headers || {};
  const hget = (n) => { for (const k in headers) if (k.toLowerCase() === n.toLowerCase()) return headers[k]; return undefined; };

  const sigInput = hget("signature-input");
  const sig = hget("signature");
  if (!sigInput || !sig) return { present: false };

  const parsed = parseSignatureInput(sigInput);
  if (!parsed) return { present: true, verified: false, reason: "unparseable Signature-Input" };
  const out = {
    present: true, verified: false,
    keyid: parsed.params.keyid, algorithm: parsed.params.alg,
    components: parsed.components, created: parsed.params.created, expires: parsed.params.expires,
    tag: parsed.params.tag,
  };
  if (parsed.params.alg && String(parsed.params.alg).toLowerCase() !== "ed25519")
    return { ...out, reason: `unsupported alg "${parsed.params.alg}" (this profile verifies ed25519 only)` };

  const signature = parseSignature(sig, parsed.label);
  if (!signature) return { ...out, reason: "unparseable or missing Signature value for " + parsed.label };

  const base = buildSignatureBase(request, parsed);
  if (base == null) return { ...out, reason: "could not reconstruct signature base (a covered component is absent)" };

  const dir = directoryUrl(hget("signature-agent"));
  if (!dir) return { ...out, reason: "no usable Signature-Agent key directory" };
  out.directory = dir;
  if (!parsed.params.keyid) return { ...out, reason: "no keyid in Signature-Input" };

  const found = await keyForKeyid(fetchImpl, dir, parsed.params.keyid, opts.timeoutMs);
  if (found.error) return { ...out, reason: found.error };
  out.matchedBy = found.matchedBy;

  let keyObj;
  try { keyObj = createPublicKey({ key: found.jwk, format: "jwk" }); } catch (e) { return { ...out, reason: "bad JWK: " + (e && e.message) }; }
  let ok = false;
  try { ok = edVerify(null, Buffer.from(base, "utf8"), keyObj, signature); } catch (e) { return { ...out, reason: "verify error: " + (e && e.message) }; }
  if (!ok) return { ...out, reason: "signature does not validate against the directory key" };

  // Cryptographically valid. Expiry is a freshness fact, surfaced (not a decision).
  const expired = typeof out.expires === "number" && out.expires < now;
  return { ...out, verified: true, expired };
}
