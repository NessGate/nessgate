"""NessGate as a LangChain tool — one domain in, its machine-readable resources out.

Wraps the public NessGate resolver (https://nessgate.com/discover/{domain}) as a
LangChain tool so an agent can discover, in ONE call, whatever machine interfaces
a company publishes — MCP servers, APIs, agent cards, llms.txt, ARD catalogs and
more — across every standard, each with a source URL to verify against the domain.

No API key, no auth, open CORS. NessGate reads what the domain already publishes
and stores nothing; the agent can always follow `sourceUrl` to check.

Install:  pip install langchain-core requests
Use:      from nessgate_tool import discover_domain
"""
from __future__ import annotations

import requests
from langchain_core.tools import tool

NESSGATE_URL = "https://nessgate.com/discover/"
_UA = "nessgate-langchain-example/1.0 (+https://nessgate.com)"


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
    # Functional smoke: invoke the tool exactly as a LangChain agent would.
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "supabase.com"
    result = discover_domain.invoke({"domain": target})
    print(f"tool name:        {discover_domain.name}")
    print(f"tool description: {discover_domain.description.splitlines()[0]}")
    print(f"resolved domain:  {result['domain']}  ({len(result['resources'])} resources)")
    for r in result["resources"][:8]:
        print(f"  [{r['class']}] {r['source']}: {r['url']}")
    print("\nfull JSON:")
    print(json.dumps(result, indent=2)[:900])
