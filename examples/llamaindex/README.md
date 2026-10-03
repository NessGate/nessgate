# NessGate + LlamaIndex

Give a LlamaIndex agent a domain **and its own capabilities**, and NessGate tells it
**how to connect** — one outcome (`ready` / `credentials-required` / `incomplete` /
`broken` / `no-compatible-method`) with a concrete connection plan (protocol,
endpoint, transport, version, auth metadata), read from the service's own published
metadata. Two tools:

- **`connect_domain(domain, client)`** — how this client connects.
- **`discover_domain(domain)`** — the normalized list of everything a domain
  publishes across the supported standards, each record linked to its source.

No API key, no account. Credentials stay with the caller and are never sent to
NessGate. Response fields are documented in
[`docs/data-model.md`](../../docs/data-model.md).

## Install

```bash
pip install llama-index-core     # the core functions themselves use only the standard library
```

## Run it standalone first (no LLM key needed)

```bash
python nessgate_tools.py supabase.com
```

```
connect_domain(supabase.com) -> credentials-required
  mcp  https://mcp.supabase.com/mcp  transport=streamable-http
  auth=oauth2  token=https://api.supabase.com/v1/oauth/token
discover_domain(supabase.com) -> found, 14 resources
  [verified-publisher-location] llms.txt: https://supabase.com/llms.txt
  ...
```

## Give it to an agent

```python
from llama_index.core.agent.workflow import FunctionAgent
from llama_index.llms.openai import OpenAI          # any tool-calling LLM works
from nessgate_tools import get_tools

agent = FunctionAgent(tools=get_tools(), llm=OpenAI(model="gpt-4.1"))
resp = await agent.run("How does my MCP client connect to Supabase, and what auth does it need?")
print(resp)
```

`get_tools()` returns the two functions wrapped as `FunctionTool`s; the docstrings
carry everything the model needs to pick the right tool and arguments.

## Prefer MCP?

NessGate also runs a remote MCP server exposing the same capabilities as three
read-only tools (`discover_domain`, `connect_domain`, `check_readiness`) at
`https://nessgate.com/mcp` (Streamable HTTP) — nothing to install or keep in sync.
Connect it with [`llama-index-tools-mcp`](https://pypi.org/project/llama-index-tools-mcp/):

```python
from llama_index.tools.mcp import BasicMCPClient, McpToolSpec   # pip install llama-index-tools-mcp

client = BasicMCPClient("https://nessgate.com/mcp")
tools = await McpToolSpec(client=client).to_tool_list_async()   # discover_domain, connect_domain, check_readiness
```

The same MCP server works from LangChain, Claude, or any MCP-aware client — see
[`examples/langchain/`](../langchain/) for the LangChain counterpart.

## Notes

- The tools call the hosted endpoints (`GET /discover/{domain}`,
  `POST /connect/{domain}`). To run everything inside your own process with no
  dependency on nessgate.com, use the embeddable library instead
  (`npm i @nessgate/resolver`; it exposes the same `plan()` / `resolve()` and
  supports opt-in registry federation and declared-pointer delegation).
- An empty `client` is answered with a broad default and labeled
  `clientAssumed: true`; pass `client.supports` for a real capability match.
