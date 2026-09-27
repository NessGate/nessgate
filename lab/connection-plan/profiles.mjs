// Sample CLIENT capability profiles for the connection-plan prototype.
//
// These follow the drafted client-capabilities schema: each `supports` entry names
// a protocol using NessGate's OWN label set, and OPTIONALLY narrows versions /
// transports / auth. Omitting a dimension = "the client accepts any." Ordering =
// the client's preference; `prefer` is the cross-protocol tie-break.
//
// Nothing here is authoritative — they exist only to exercise the matcher against
// realistic client shapes (an MCP agent, a REST/OpenAPI tool, an A2A agent, and a
// broad "polyglot" client that speaks everything).

export const PROFILES = {
  // A typical MCP-first agent runtime: streamable HTTP, OAuth or no-auth.
  "mcp-agent": {
    client: {
      id: "mcp-agent/1.0",
      supports: [
        { protocol: "mcp", versions: ["2025-06-18", "2025-03-26"], transports: ["streamable-http"], auth: ["oauth2", "none"] },
      ],
      prefer: ["mcp"],
    },
  },

  // A classic REST integration: OpenAPI over HTTPS with common auth schemes.
  "rest-tool": {
    client: {
      id: "rest-tool/2.3",
      supports: [
        { protocol: "openapi", transports: ["https"], auth: ["http:bearer", "apiKey", "oauth2", "none"] },
      ],
      prefer: ["openapi"],
    },
  },

  // An A2A agent that can also fall back to REST.
  "a2a-agent": {
    client: {
      id: "a2a-agent/0.9",
      supports: [
        { protocol: "a2a", auth: ["oauth2", "none"] },
        { protocol: "openapi", transports: ["https"], auth: ["http:bearer", "none"] },
      ],
      prefer: ["a2a", "openapi"],
    },
  },

  // A broad client that speaks everything NessGate can discover, any details.
  // With no version/transport/auth constraints, this maximizes matches and is
  // useful for measuring the raw "did we find ANY compatible path" question.
  polyglot: {
    client: {
      id: "polyglot/1.0",
      supports: [
        { protocol: "mcp" },
        { protocol: "openapi" },
        { protocol: "a2a" },
        { protocol: "ucp" },
        { protocol: "aid" },
      ],
      // No `prefer` on purpose → selectedPlan stays null (client chooses).
    },
  },
};
