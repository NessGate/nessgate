"""NessGate as LlamaIndex tools — give an agent a domain (and its own capabilities)
and get back how to connect, plus the raw list of what the domain publishes.

Two tools, no API key, no account. The core functions use only the Python
standard library (urllib); llama-index is needed only to wrap them as
FunctionTools, so the module also runs standalone.

  - connect_domain(domain, client)  -> one outcome
      (ready | credentials-required | incomplete | broken | no-compatible-method)
      plus a connection plan (protocol, endpoint, transport, version, auth
      metadata), read from the service's own published metadata. Credentials stay
      with the caller.
  - discover_domain(domain)         -> the normalized list of everything a domain
      publishes across the supported standards, each record with a source URL.

Install (for the FunctionTool wrappers):  pip install llama-index-core
Use:  from nessgate_tools import get_tools   # -> [connect_tool, discover_tool]

Response fields are documented in docs/data-model.md in the NessGate repository.
"""
from __future__ import annotations

import json
import urllib.request

NESSGATE = "https://nessgate.com"
_UA = "nessgate-llamaindex-example/1.0 (+https://nessgate.com)"


def _get(url: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, headers={"user-agent": _UA, "accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _post(url: str, body: dict, timeout: int = 45) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"user-agent": _UA, "accept": "application/json", "content-type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def connect_domain(domain: str, client: dict | None = None) -> dict:
    """Get a connection plan: how this client can connect to a domain's services.

    Given a domain (e.g. "supabase.com") and the calling client's capabilities,
    returns one outcome and a concrete plan:

      - outcome: "ready" (connect now, no credentials), "credentials-required"
        (everything known - supply your own secret), "incomplete" (the service
        under-publishes; connection.missing[] names each item), "broken" (the
        declared location answers but contradicts the declaration), or
        "no-compatible-method" (nothing the client declared support for).
      - connection: { protocol, endpoint, transport, version, auth } - auth carries
        the metadata the service published (e.g. OAuth authorize/token endpoints
        and scopes). Credentials stay with you; they are never sent to NessGate.

    `client` shape: {"supports": [{"protocol": "mcp", "auth": ["oauth2", "none"]}],
    "prefer": ["mcp"]}. Omit a dimension (versions/transports/auth) to accept any.
    Use this when the goal is to actually connect, not just list what exists.
    """
    body = {"client": client or {"supports": [{"protocol": "mcp"}, {"protocol": "openapi"}]}}
    return _post(f"{NESSGATE}/connect/{domain.strip()}", body)


def discover_domain(domain: str) -> dict:
    """List the machine-readable resources a domain publishes for AI agents.

    Given a domain (e.g. "supabase.com"), returns the interfaces it exposes across
    the supported standards (MCP servers, OpenAPI/REST, A2A agent cards, llms.txt,
    ARD catalogs, and more), normalized into one list. Each resource carries
    source, type, url, sourceUrl (follow it to verify against the domain), and a
    class stating how far NessGate verified it.
    """
    data = _get(f"{NESSGATE}/discover/{domain.strip()}")
    return {
        "domain": data.get("domain"),
        "outcome": data.get("outcome"),
        "resources": [
            {k: r.get(k) for k in ("source", "type", "url", "sourceUrl", "class")}
            for r in data.get("resources", [])
        ],
        "checked": data.get("checked", []),
    }


def get_tools():
    """The two functions wrapped as LlamaIndex FunctionTools."""
    from llama_index.core.tools import FunctionTool  # imported lazily on purpose

    return [
        FunctionTool.from_defaults(fn=connect_domain),
        FunctionTool.from_defaults(fn=discover_domain),
    ]


if __name__ == "__main__":
    # Standalone check (standard library only): call both functions the way an
    # agent would and print the essentials.
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "supabase.com"

    plan = connect_domain(target, {"supports": [{"protocol": "mcp", "auth": ["oauth2", "none"]}]})
    print(f"connect_domain({target}) -> {plan.get('outcome')}")
    c = plan.get("connection") or {}
    if c:
        a = c.get("auth") or {}
        print(f"  {c.get('protocol')}  {c.get('endpoint')}  transport={c.get('transport')}")
        if a.get("tokenEndpoint"):
            print(f"  auth={a.get('type')}  token={a.get('tokenEndpoint')}")

    found = discover_domain(target)
    print(f"discover_domain({target}) -> {found.get('outcome')}, {len(found['resources'])} resources")
    for r in found["resources"][:5]:
        print(f"  [{r['class']}] {r['source']}: {r['url']}")
