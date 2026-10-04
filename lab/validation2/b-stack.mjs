// B — the BEST AVAILABLE stack: official SDKs and established tooling, used as
// their documentation intends. Only the lines in THIS file are counted as
// application-owned glue; everything inside the SDKs is free for B.
//   @modelcontextprotocol/client v2 — the CURRENT official client package
//                                (2.3.0, 2026-10-02), transport + official OAuth discovery helpers
//   @a2a-js/sdk                — DefaultAgentCardResolver (official card fetch,
//                                including its v0.3 structural-drift handling)
//   @apidevtools/swagger-parser — OpenAPI validate/dereference
//   web-bot-auth               — the published verifier (app supplies the key
//                                resolver, per its VerifyOptions contract)
// Known structural gaps recorded, not papered over: no official tool reads
// llms.txt or ARD catalogs, so B does not see them at all.

import { Client, StreamableHTTPClientTransport, discoverOAuthProtectedResourceMetadata, discoverAuthorizationServerMetadata } from "@modelcontextprotocol/client";
import { DefaultAgentCardResolver } from "@a2a-js/sdk/client";
import SwaggerParser from "@apidevtools/swagger-parser";
import { verify as wbaVerify } from "web-bot-auth";
import { webcrypto } from "node:crypto";

export const PACKAGES = ["@modelcontextprotocol/client@2.3.0", "@a2a-js/sdk@1.3.0", "@apidevtools/swagger-parser@13.1.0", "web-bot-auth@0.2.0"];

/* ---- domain discovery (no official cross-protocol tool exists; this is app glue) ---- */
export async function discover(domain) {
  const found = [];
  // MCP: the official registry is the documented discovery channel.
  try {
    const ns = domain.toLowerCase().split(".").reverse().join(".");
    const r = await fetch(`https://registry.modelcontextprotocol.io/v0.1/servers?search=${encodeURIComponent(ns)}&limit=50`, { signal: AbortSignal.timeout(10000) });
    const doc = await r.json();
    let best = null;
    for (const e of doc.servers || []) {
      const s = e.server || e;
      const meta = e._meta && e._meta["io.modelcontextprotocol.registry/official"];
      if (!s || !String(s.name || "").startsWith(ns + "/")) continue;
      if (meta && meta.status && meta.status !== "active") continue;
      if (!best || (meta && meta.isLatest)) best = s; // prefer the registry's isLatest marker
    }
    const remote = best && (best.remotes || []).find((x) => x && x.url);
    if (remote) found.push({ kind: "mcp", url: remote.url });
  } catch {}
  // A2A: official resolver at the conventional base.
  try {
    const card = await new DefaultAgentCardResolver().resolve(`https://${domain}`);
    if (card) found.push({ kind: "a2a", card, url: `https://${domain}/.well-known/agent-card.json` });
  } catch {}
  // OpenAPI: conventional location + official parser.
  try {
    const api = await SwaggerParser.validate(`https://${domain}/openapi.json`);
    found.push({ kind: "openapi", api, url: `https://${domain}/openapi.json` });
  } catch {}
  return found; // llms.txt / ARD: no official tooling — structurally invisible to B
}

/* ---- readiness / auth resolution per protocol (app glue around SDK errors) ---- */
export async function checkMcp(url) {
  // Official documented negotiation: probe server/discover (modern 2026-07-28
  // era) with conservative fallback to the legacy initialize handshake.
  const client = new Client({ name: "b-stack", version: "1.0" }, { versionNegotiation: { mode: "auto" } });
  const transport = new StreamableHTTPClientTransport(new URL(url));
  try {
    await client.connect(transport);
    const v = client.getServerVersion ? client.getServerVersion() : undefined;
    await client.close().catch(() => {});
    return { protocol: "mcp", usable: true, state: "open", endpoint: url, version: v && v.version };
  } catch (e) {
    const msg = String(e && e.message || e);
    if (/401|Unauthorized/i.test(msg)) {
      try {
        const prm = await discoverOAuthProtectedResourceMetadata(new URL(url));
        const asMeta = await discoverAuthorizationServerMetadata(new URL(prm.authorization_servers[0]));
        return { protocol: "mcp", usable: true, state: "needs-credentials", endpoint: url, auth: "oauth2", tokenEndpoint: asMeta && asMeta.token_endpoint };
      } catch { return { protocol: "mcp", usable: true, state: "needs-credentials", endpoint: url, auth: "oauth2" }; }
    }
    if (/403/.test(msg)) return { protocol: "mcp", usable: true, state: "needs-credentials", endpoint: url, auth: "oauth2" }; // same natural guess as DIY
    if (/404|410|5\d\d/.test(msg)) return { protocol: "mcp", usable: false, state: "broken", endpoint: url };
    return { protocol: "mcp", usable: false, state: "error", detail: msg.slice(0, 60), endpoint: url };
  }
}

export function checkA2a(card) {
  const iface = Array.isArray(card.supportedInterfaces) && card.supportedInterfaces[0];
  const transport = (card.preferredTransport || (iface && (iface.protocolBinding || iface.transport)) || "").toLowerCase() || null;
  const endpoint = card.url || (iface && iface.url) || null;
  const version = card.protocolVersion || (iface && iface.protocolVersion) || null;
  if (!transport || !endpoint || !version) return { protocol: "a2a", usable: false, state: "incomplete" };
  const scheme = card.securitySchemes && Object.values(card.securitySchemes)[0];
  return scheme ? { protocol: "a2a", usable: true, state: "needs-credentials", endpoint, transport, version, auth: scheme.type }
                : { protocol: "a2a", usable: true, state: "open", endpoint, transport, version };
}

export function checkOpenApi(api, url) {
  const server = api.servers && api.servers[0] && api.servers[0].url;
  const schemes = (api.components && api.components.securitySchemes) || api.securityDefinitions || null;
  if (!server) return { protocol: "openapi", usable: false, state: "incomplete", url };
  if (!schemes) return { protocol: "openapi", usable: true, state: "open", endpoint: server };
  const first = Object.values(schemes)[0] || {};
  return { protocol: "openapi", usable: true, state: "needs-credentials", endpoint: server, auth: first.type === "http" ? "http:" + first.scheme : first.type };
}

export async function check(item) {
  if (item.kind === "mcp") return checkMcp(item.url);
  if (item.kind === "a2a") return checkA2a(item.card);
  if (item.kind === "openapi") return checkOpenApi(item.api, item.url);
  return { protocol: item.kind, state: "unsupported" };
}

/* ---- inbound identity via the published verifier (app supplies key discovery) ---- */
export async function verifyInbound(request, fetchImpl = fetch) {
  try {
    const sig = await wbaVerify(request, {
      resolver: async (cand) => {
        // the app still owns: locating the key material and wiring the crypto
        const entry = cand.signatureAgent;
        let keysUrl = entry && entry.url ? String(entry.url) : null;
        if (keysUrl && !/\.well-known/.test(keysUrl) && (!entry || entry.type !== "jwks_uri")) keysUrl = keysUrl.replace(/\/$/, "") + "/.well-known/http-message-signatures-directory";
        const jwks = await (await fetchImpl(keysUrl)).json();
        for (const k of jwks.keys || []) {
          if (k.kty !== "OKP" || k.crv !== "Ed25519") continue;
          const key = await webcrypto.subtle.importKey("jwk", k, { name: "Ed25519" }, true, ["verify"]);
          return { algorithm: "ed25519", keyid: cand.keyid, verify: async (data, signature) => webcrypto.subtle.verify({ name: "Ed25519" }, key, signature, data) };
        }
        throw new Error("no usable key");
      },
    });
    return { present: true, verified: true, keyid: sig && sig.keyid };
  } catch (e) {
    const msg = String(e && e.message || e);
    if (/no signature|missing/i.test(msg)) return { present: false };
    return { present: true, verified: false, reason: msg.slice(0, 80) };
  }
}
