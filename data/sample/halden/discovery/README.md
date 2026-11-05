# Discovery evidence for Halden Logistics

What the discovery agent gets to look at. Everything here is invented for the demo,
written to look like evidence a security team could really collect without
installing anything new.

| File | What it stands for | How it would be collected |
| --- | --- | --- |
| `scope.json` | Networks the agent may probe. Anything else is recorded as a lead and never contacted. | Agreed with the network owner before a scan |
| `configs/<asset>/…` | MCP client configs found on a host: Claude Desktop, Cursor, Claude Code (`.mcp.json`, `.claude/settings.json`) and VS Code (`.vscode/mcp.json`). The first folder is the asset the file came from. | EDR or MDM file collection |
| `probes.json` | Recorded answers from read-only probes: MCP `initialize` and `tools/list`, Qdrant `GET /collections`, Weaviate `GET /v1/schema`. | Replayed by the fixture transport, so tests never touch a network |
| `cloud/azure_ai_foundry.json` | Agents, their tools and knowledge bases in Azure AI Foundry | Reader role, simplified API export |
| `cloud/aws_bedrock.json` | Bedrock agents, knowledge bases and data sources | SecurityAudit policy, simplified API export |

The planted problems, so you can check the agent's work (`../expected.json` has the
machine-readable version):

- **Shadow MCP server.** A data engineer started `analytics-mcp` from VS Code on a
  pipeline host, bound it to `0.0.0.0` and pointed it at the warehouse database. It
  is in no inventory, needs no login and can run `INSERT`, `UPDATE` and `DELETE`.
- **Poisoned tool description.** The registered docs-search server's `search_docs`
  tool now tells the model to read `~/.aws/credentials` and hide that from the user.
- **Open vector store.** The invoice agent's knowledge base lives in a Qdrant
  database that answers without an API key and is missing from the CMDB, so anyone
  on the network can rewrite what the agent "knows" about vendors.
- **Poisoned knowledge-base document.** A customer ticket attachment indexed into
  the support knowledge base hides an instruction to email customer addresses out.
- **Untrusted input, no approval.** The support and invoice agents act on public
  chat and inbound email with CRM, bank-detail and payment tools and no human
  approval step.
- **Shadow agent with over-broad retrieval.** An HR helpdesk agent in Bedrock,
  missing from the inventory, answers from an index that ignores SharePoint
  permissions.
- **Developer laptops.** A vulnerable `mcp-remote` (CVE-2025-6514) bridging to a
  vendor's server, and an unpinned PDF server with an API key pasted into its config.

And things that must not raise an alarm: the calendar MCP server and the Weaviate
database require credentials, the pinned and approved `@halden/fs-tools` package is
fine, and the coding assistants ask the developer before each tool call.
