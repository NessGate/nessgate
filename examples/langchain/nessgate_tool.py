"""NessGate as LangChain tools — give an agent a domain (and its own capabilities)
and get back HOW to connect, plus the raw list of what the domain publishes.

Two tools, no API key, no auth, open CORS. NessGate reads what the domain already
publishes and stores nothing; the agent can always follow `sourceUrl` to verify.

  - connect_domain(domain, client)  → the headline: one outcome
      (ready | credentials-required | incomplete | no-compatible-method) plus a
      connection plan (protocol, endpoint, transport, version, auth metadata), read
      from the service's own published metadata. Credentials stay with the caller.
  - discover_domain(domain)         → the raw normalized list of everything a
      domain publishes across every supported standard, each with a source URL.

Install:  pip install langchain-core requests
Use:      from nessgate_tool import connect_domain, discover_domain
"""
from __future__ import annotations

import requests
from langchain_core.tools import tool

NESSGATE = "https://nessgate.com"
NESSGATE_URL = NESSGATE + "/discover/"
_UA = "nessgate-langchain-example/1.0 (+https://nessgate.com)"


@tool
def connect_domain(domain: str, client: dict | None = None) -> dict:
    """Get a connection plan: how THIS client can connect to a domain's services.

    Given a domain (e.g. "supabase.com") and the calling client's capabilities,
    returns one honest outcome and a concrete plan:

      - outcome: "ready" (connect now, no credentials), "credentials-required"
        (everything is known — you supply your own secret), "incomplete" (the
        service under-published — see connection.missing[]), or
        "no-compatible-method" (nothing the client speaks).
      - connection: { protocol, endpoint, transport, version, auth } — auth carries
        the metadata the service published (e.g. OAuth authorize/token endpoints and
        scopes). Credentials stay with you and are never sent to NessGate.

    `client` shape: {"supports": [{"protocol": "mcp", "auth": ["oauth2","none"]}],
    "prefer": ["mcp"]}. Omit a dimension (versions/transports/auth) to accept any.
    Use this when you want to actually CONNECT, not just list what exists.
    """
    body = {"client": client or {"supports": [{"protocol": "mcp"}, {"protocol": "openapi"}]}}
    resp = requests.post(NESSGATE + "/connect/" + domain.strip(), json=body, timeout=30, headers={"user-agent": _UA})
    resp.raise_for_status()
    return resp.json()


@tool
def discover_domain(domain: str) -> dict:
    """Discover the machine-readable resources a company/domain publishes for AI.

    Given a domain (e.g. "supabase.com"), returns the interfaces it exposes across
    every supported standard — MCP servers, OpenAPI/REST APIs, A2A agent cards,
    llms.txt, ARD catalogs, and more — normalized into one list.

    Each resource carries:
      - source:    which standard it came from (e.g. "ard-catalog", "openapi")
      - url:       where the resource lives
      - sourceUrl: the document it was read from (follow it to verify)
      - class:     how far NessGate verified it — "verified-publisher-location"
                   (fetched + validated on the domain), "publisher-declared"
                   (declared on the domain, not fetched), "declared-external-pointer"
                   (points off the domain; unverified), or "unsupported".

    Use this when you need to connect to or call a company's official machine
    interfaces and want the authoritative, source-linked list in one request.
    """
    resp = requests.get(NESSGATE_URL + domain.strip(), timeout=20, headers={"user-agent": _UA})
    resp.raise_for_status()
    data = resp.json()
    return {
        "domain": data.get("domain"),
        "resources": [
            {
                "source": r.get("source"),
                "type": r.get("type"),
                "url": r.get("url"),
                "sourceUrl": r.get("sourceUrl"),
                "class": r.get("class"),
            }
            for r in data.get("resources", [])
        ],
        "checked": data.get("checked", []),
    }


if __name__ == "__main__":
    # Functional smoke: invoke the tools exactly as a LangChain agent would.
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "supabase.com"

    plan = connect_domain.invoke({"domain": target, "client": {"supports": [{"protocol": "mcp", "auth": ["oauth2", "none"]}]}})
    print(f"connect_domain({target}) → {plan.get('outcome')}")
    c = plan.get("connection") or {}
    if c:
        a = c.get("auth") or {}
        print(f"  {c.get('protocol')}  {c.get('endpoint')}  transport={c.get('transport')}")
        if a.get("tokenEndpoint"):
            print(f"  auth={a.get('type')}  token={a.get('tokenEndpoint')}")
    print()

    result = discover_domain.invoke({"domain": target})
    print(f"discover_domain({target}) → {len(result['resources'])} resources")
    for r in result["resources"][:6]:
        print(f"  [{r['class']}] {r['source']}: {r['url']}")
    print("\nfull connection plan JSON:")
    print(json.dumps(plan, indent=2)[:900])
