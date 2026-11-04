# shadow-taint-path

Follows untrusted input (a chat message, an emailed invoice, a poisoned document) through shadow AI agents, MCP servers, knowledge bases and identities to the systems that matter.

**Status: in progress, week 1 of 3.** Product brief and sample environment are done; the discovery agent, prioritization engine and analyst agent are next.

Security teams can see thousands of exposures but can't tell which few actually lead to their critical assets. AI agents make this worse: they add tools, identities and MCP servers that most exposure tools don't model as attack surface.

This project uses two agents. A **discovery agent** finds the AI agents, MCP servers and RAG knowledge bases in use and flags their risks (no login, high-risk tools, vulnerable packages, poisoned tool descriptions, open vector stores, knowledge bases fed from untrusted sources). A prioritization engine then ranks **attack paths to crown-jewel assets** across infrastructure, identities and those agents, enriched with public threat intelligence, and an **analyst agent** explains the top risks, drafts remediation tickets and writes a one-page board brief.

## What's here so far

| Path | What it is |
| --- | --- |
| `data/sample/halden/` | **Halden Logistics**, a fictional 4,500-person freight company: 28 assets, 6 identities, 4 AI agents, 5 MCP servers, 82 findings |
| `data/sample/halden/expected.json` | Ground truth: six planted critical paths (three run through AI agents) and two decoys the ranking must ignore |
| `data/feeds/` | Real public threat data for every CVE in the sample: CISA KEV and CVE records |
| `scripts/build_sample_env.py` | Rebuilds the sample company |
| `scripts/refresh_feeds.py` | Downloads KEV, CVE records and EPSS scores |
| `tests/` | Checks the sample data is consistent and the planted paths really exist |

The company is invented; every CVE is real. Three of the six critical paths hinge on AI agent misconfigurations rather than CVEs, which is exactly what CVSS-only prioritization misses.

## Run it

```bash
pip install pytest
python scripts/build_sample_env.py   # rebuild the sample company
python scripts/refresh_feeds.py      # refresh threat intelligence
pytest -q                            # check the data
```

## Roadmap

- [x] Product requirements and go-to-market brief
- [x] Sample environment with planted ground truth
- [ ] Discovery agent: MCP config files, read-only MCP and vector database probes, cloud AI exports; OWASP agentic, OWASP LLM and MITRE ATLAS mapping
- [ ] Prioritization engine: enrichment, attack-path graph, explainable score, dashboard
- [ ] Analyst agent: explanations, remediation tickets, board brief, secured MCP server
- [ ] SOAR integration: JSON output with a published schema, REST API (OpenAPI), signed webhooks, example XSOAR or Sentinel playbook, integration guide
- [ ] Hosted demo, demo video, case study

## Frameworks used

[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [FIRST EPSS](https://www.first.org/epss/) · [MITRE ATT&CK](https://attack.mitre.org/) · [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) · [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) · [MITRE ATLAS](https://atlas.mitre.org/)
