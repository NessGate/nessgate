// Drop-in integration for NessGate Inspect (lab-only).
//
// Framework-agnostic middleware with the standard (req, res, next) signature, so
// it works verbatim in Express / Connect and in a plain node:http server. It runs
// Inspect on each incoming request and attaches the neutral normalized result to
// `req.nessgate`. It makes NO allow/deny, trust, score, blocking, or policy
// decision — it only observes and hands you the facts; your app does whatever it
// wants with them (log them, branch on them, ignore them).
//
// Express, drop in and use:
//   import { nessgateInspect } from "@nessgate/inspect/middleware";
//   app.use(nessgateInspect({ log: true }));
//   app.get("/", (req, res) => { /* read req.nessgate / req.nessgate.summary */ });
//
// Trusted source IP = the REAL socket peer. X-Forwarded-For is NOT trusted unless
// you pass { trustProxy: true } AND you actually run behind a trusted proxy.

import { inspect } from "./inspect.mjs";

export function nessgateInspect(options = {}) {
  const prop = options.property || "nessgate";
  return async function nessgateInspectMiddleware(req, res, next) {
    try {
      const headers = {};
      for (const [k, v] of Object.entries(req.headers || {})) headers[k] = Array.isArray(v) ? v.join(", ") : v;
      const authority = headers.host || "localhost";
      const scheme = req.protocol || (req.socket && req.socket.encrypted ? "https" : "http");
      const url = `${scheme}://${authority}${req.originalUrl || req.url || "/"}`;

      // Source IP: the real connection peer by default; forwarded headers only when
      // the integrator explicitly opts in (they are caller-settable otherwise).
      let sourceIp = (req.socket && req.socket.remoteAddress) || req.ip || undefined;
      if (options.trustProxy && typeof headers["x-forwarded-for"] === "string" && headers["x-forwarded-for"].trim())
        sourceIp = headers["x-forwarded-for"].split(",")[0].trim();

      const result = await inspect({ method: req.method, url, headers }, { sourceIp, timeoutMs: options.timeoutMs });
      result.summary2 = summarize(result); // convenience: the six fields a site owner usually wants
      req[prop] = result;
      if (options.log) (options.logger || console).log(logLine(result));
      if (typeof options.onResult === "function") { try { options.onResult(result, req); } catch { /* an app hook must never break the request */ } }
    } catch {
      req[prop] = null; // Inspect must never break the request path
    }
    next();
  };
}

// The six fields most domain owners want, extracted from the normalized result.
export function summarize(result) {
  const byKind = (k) => (result.facts || []).find((x) => x.kind === k);
  const ua = byKind("user-agent"), attr = byKind("public-attribution"), net = byKind("network-attribution"), wba = byKind("web-bot-auth");
  // The strongest VERIFIED fact, if any (network-verified | cryptographically-verified).
  const verified = (result.facts || []).find((x) => x.tier === "network-verified" || x.tier === "cryptographically-verified");
  const topTier = verified ? verified.tier : attr ? "directory-attributed" : (result.facts || []).length ? "claimed" : "unknown";
  return {
    declaredAgent: ua ? ua.value : null,
    attributedOperator: (attr && attr.operator) || (net && net.verified && net.operator) || null,
    verificationTier: topTier,
    verificationMethod: verified ? (verified.method || (verified.kind === "web-bot-auth" ? "rfc9421-web-bot-auth" : null)) : null,
    provenance: (verified || attr || ua || {}).provenance || [],
    unknowns: (result.facts || []).filter((x) => x.tier === "unknown").map((x) => ({ statement: x.statement, reason: x.reason })),
  };
}

function logLine(result) {
  const s = summarize(result);
  return `[nessgate-inspect] ${result.request.method} ${result.request.path} · agent=${s.declaredAgent || "-"} · operator=${s.attributedOperator || "-"} · tier=${s.verificationTier} · method=${s.verificationMethod || "-"}`;
}
