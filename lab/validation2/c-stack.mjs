// C — NessGate for discovery/normalization/readiness/identity, with the
// official protocol SDKs used ONLY for execution once a plan says connect.
// Everything below is the complete application-owned integration.

import { resolve, assessReadiness, readinessProtocol } from "@nessgate/resolver";
import { inspect } from "@nessgate/inspect";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";

export const PACKAGES = ["@nessgate/resolver", "@nessgate/inspect", "@modelcontextprotocol/client v2 (execution only)"];

export async function discoverAndAssess(domain, opts = {}) {
  const d = await resolve(domain, { registry: true, delegate: true, ...opts });
  const states = [];
  const seen = new Set();
  for (const r of d.resources) {
    if (!readinessProtocol(r) || seen.has(r.url)) continue;
    seen.add(r.url);
    states.push(await assessReadiness(r, opts));
  }
  return { outcome: d.outcome, states };
}

// Execution handoff: when a plan says an MCP endpoint is ready, the ordinary
// official SDK takes over unchanged.
export async function executeMcp(endpoint) {
  const client = new Client({ name: "c-stack", version: "1.0" }, { versionNegotiation: { mode: "auto" } });
  await client.connect(new StreamableHTTPClientTransport(new URL(endpoint)));
  const tools = await client.listTools();
  await client.close().catch(() => {});
  return (tools.tools || []).map((t) => t.name);
}

export async function verifyInbound(request, opts = {}) {
  return inspect(request, opts);
}
