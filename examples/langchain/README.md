# NessGate + LangChain

Give a LangChain agent a domain **and its own capabilities**, and NessGate tells it
**how to connect** — one outcome (`ready` / `credentials-required` / `incomplete` /
`no-compatible-method`) with a concrete connection plan (protocol, endpoint,
transport, version, auth metadata), read from the service's own published metadata.
Two tools:

- **`connect_domain(domain, client)`** — the headline: how this client connects.
- **`discover_domain(domain)`** — the raw normalized list of everything a domain
  publishes across every supported standard, each linked to its source.

No API key, no auth, open CORS. NessGate reads what the domain already publishes and
stores nothing; credentials stay with the caller and are never sent to NessGate.

## Install

```bash
pip install langchain-core requests
```

## Run it (functional smoke — no LLM key needed)

`nessgate_tool.py` is a ready-to-use LangChain tool. Invoke it exactly as an agent would:

```bash
python nessgate_tool.py supabase.com
```

```
connect_domain(supabase.com) → credentials-required
  mcp  https://mcp.supabase.com/mcp  transport=streamable-http
  auth=oauth2  token=https://api.supabase.com/v1/oauth/token

discover_domain(supabase.com) → 14 resources
  [verified-publisher-location] llms.txt: https://supabase.com/llms.txt
  [publisher-declared] ard-catalog: https://mcp.supabase.com/mcp
  ...
```

Every discovered resource carries a `class` so the agent knows how far NessGate verified it:
`verified-publisher-location` (fetched + validated on the domain),
`publisher-declared` (declared on the domain, not fetched),
`declared-external-pointer` (points off the domain — unverified), or `unsupported`.

## Give it to an agent

```python
from langchain_anthropic import ChatAnthropic   # pip install langchain-anthropic
from nessgate_tool import connect_domain, discover_domain

llm = ChatAnthropic(model="claude-sonnet-4-6").bind_tools([connect_domain, discover_domain])

# The model calls connect_domain when the task is to actually connect to a service.
msg = llm.invoke("How does my MCP client connect to Supabase, and what auth does it need?")
print(msg.tool_calls)   # -> [{'name': 'connect_domain', 'args': {'domain': 'supabase.com', ...}}]
```

Wire it into a full tool-executing loop with LangGraph's `create_react_agent`:

```python
from langgraph.prebuilt import create_react_agent   # pip install langgraph
from langchain_anthropic import ChatAnthropic
from nessgate_tool import connect_domain, discover_domain

agent = create_react_agent(ChatAnthropic(model="claude-sonnet-4-6"), [connect_domain, discover_domain])
result = agent.invoke({"messages": [("user",
    "Connect me to Stripe's MCP server — what endpoint and auth do I use?")]})
print(result["messages"][-1].content)
```

Works with any tool-calling chat model (`ChatOpenAI`, `ChatAnthropic`, …) — the
tool is provider-agnostic.

## Prefer MCP?

NessGate also runs a remote MCP server exposing the SAME three tools
(`discover_domain`, `connect_domain`, `check_readiness`) at `https://nessgate.com/mcp`
(Streamable HTTP) — no separate package to install or maintain. Connect it to a
LangGraph agent with [`langchain-mcp-adapters`](https://github.com/langchain-ai/langchain-mcp-adapters):

```python
from langchain_mcp_adapters.client import MultiServerMCPClient   # pip install langchain-mcp-adapters
client = MultiServerMCPClient({"nessgate": {"url": "https://nessgate.com/mcp", "transport": "streamable_http"}})
tools = await client.get_tools()   # discover_domain, connect_domain, check_readiness
```

This is the neutral, framework-agnostic path — the same MCP server works from
LlamaIndex, Claude, or any MCP-aware client.

## Notes

- The tool calls the hosted resolver `GET https://nessgate.com/discover/{domain}`.
  To run discovery inside your own process with no dependency on nessgate.com,
  use the embeddable library instead (`npm i @nessgate/resolver`, or
  `import { resolve } from "https://nessgate.com/resolver.mjs"`).
- Add `?fast=1` to the endpoint for a faster, non-exhaustive lookup (skips the
  optional alternate ARD locators; not fully ARD-conformant).
