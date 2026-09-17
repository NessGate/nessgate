# NessGate + LangChain

Give a LangChain agent one tool — `discover_domain` — and it can resolve any
company's domain to the machine interfaces it publishes (MCP servers, APIs, agent
cards, llms.txt, ARD catalogs, …) across every standard, in **one call**, each
result linked to its source so the agent can verify against the domain.

No API key, no auth, open CORS. NessGate reads what the domain already publishes
and stores nothing.

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
tool name:        discover_domain
resolved domain:  supabase.com  (14 resources)
  [verified-publisher-location] llms.txt: https://supabase.com/llms.txt
  [publisher-declared] ard-catalog: https://mcp.supabase.com/mcp
  [publisher-declared] api-catalog: https://api.supabase.com/v1
  ...
```

Every resource carries a `class` so the agent knows how far NessGate verified it:
`verified-publisher-location` (fetched + validated on the domain),
`publisher-declared` (declared on the domain, not fetched),
`declared-external-pointer` (points off the domain — unverified), or `unsupported`.

## Give it to an agent

```python
from langchain_anthropic import ChatAnthropic   # pip install langchain-anthropic
from nessgate_tool import discover_domain

llm = ChatAnthropic(model="claude-sonnet-4-6").bind_tools([discover_domain])

# The model will call discover_domain when a task needs a company's interfaces.
msg = llm.invoke("What MCP server does Supabase publish, and where's its OpenAPI spec?")
print(msg.tool_calls)   # -> [{'name': 'discover_domain', 'args': {'domain': 'supabase.com'}, ...}]
```

Wire it into a full tool-executing loop with LangGraph's `create_react_agent`:

```python
from langgraph.prebuilt import create_react_agent   # pip install langgraph
from langchain_anthropic import ChatAnthropic
from nessgate_tool import discover_domain

agent = create_react_agent(ChatAnthropic(model="claude-sonnet-4-6"), [discover_domain])
result = agent.invoke({"messages": [("user",
    "Find Stripe's llms.txt and any agent card it publishes.")]})
print(result["messages"][-1].content)
```

Works with any tool-calling chat model (`ChatOpenAI`, `ChatAnthropic`, …) — the
tool is provider-agnostic.

## Prefer MCP?

NessGate also runs a remote MCP server with the same lookup as a tool
(`discover_domain`) at `https://nessgate.com/mcp` (Streamable HTTP). Connect it to
a LangGraph agent with [`langchain-mcp-adapters`](https://github.com/langchain-ai/langchain-mcp-adapters):

```python
from langchain_mcp_adapters.client import MultiServerMCPClient   # pip install langchain-mcp-adapters
client = MultiServerMCPClient({"nessgate": {"url": "https://nessgate.com/mcp", "transport": "streamable_http"}})
tools = await client.get_tools()   # includes discover_domain
```

## Notes

- The tool calls the hosted resolver `GET https://nessgate.com/discover/{domain}`.
  To run discovery inside your own process with no dependency on nessgate.com,
  use the embeddable library instead (`npm i @nessgate/resolver`, or
  `import { resolve } from "https://nessgate.com/resolver.mjs"`).
- Add `?fast=1` to the endpoint for a faster, non-exhaustive lookup (skips the
  optional alternate ARD locators; not fully ARD-conformant).
