"""Build the fictional sample company used by the demo and the tests.

Halden Logistics is invented. Its assets, identities, AI agents and findings
are made up, but every CVE it references is real, so the engine can enrich
them with real public threat intelligence (CISA KEV, CVE records).

Run:  python scripts/build_sample_env.py
Writes JSON files to data/sample/halden/.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "sample" / "halden"

COMPANY = {
    "name": "Halden Logistics",
    "fictional": True,
    "industry": "Freight and warehousing",
    "employees": 4500,
    "environments": ["aws", "azure", "on_prem"],
    "notes": "Invented company for demos. Any resemblance to a real organisation is coincidental.",
}

# --- Assets -----------------------------------------------------------------
# crown_jewel: what the board cares about. internet_facing: reachable by anyone.
# entry_point: "internet" (anyone can reach it) or "user_action" (reached when an
# employee opens a link, email or untrusted tool).
ASSETS = [
    # Crown jewels
    {"id": "aws-prod", "name": "AWS production account", "type": "cloud_account", "env": "aws", "crown_jewel": True, "business_service": "All customer-facing systems", "owner": "Cloud Platform"},
    {"id": "orders-db", "name": "Orders database (RDS)", "type": "database", "env": "aws", "crown_jewel": True, "business_service": "Order management", "owner": "Commerce Engineering"},
    {"id": "crm", "name": "Customer CRM", "type": "saas", "env": "azure", "crown_jewel": True, "business_service": "Customer records (PII)", "owner": "Sales Operations"},
    {"id": "dc-01", "name": "Active Directory domain controller", "type": "server", "env": "on_prem", "crown_jewel": True, "business_service": "Identity for all staff", "owner": "IT Infrastructure"},
    {"id": "finance-erp", "name": "Finance ERP", "type": "application", "env": "azure", "crown_jewel": True, "business_service": "Payments and invoicing", "owner": "Finance Systems"},
    {"id": "wms-db", "name": "Warehouse management database", "type": "database", "env": "azure", "crown_jewel": True, "business_service": "Warehouse operations", "owner": "Logistics Engineering"},
    # Internet-facing entry points
    {"id": "vpn-gw-01", "name": "Ivanti Connect Secure VPN gateway", "type": "network_appliance", "env": "on_prem", "internet_facing": True, "entry_point": "internet", "owner": "Network Team"},
    {"id": "fw-edge-01", "name": "FortiGate SSL-VPN (branch offices)", "type": "network_appliance", "env": "on_prem", "internet_facing": True, "entry_point": "internet", "owner": "Network Team"},
    {"id": "pan-gp-01", "name": "PAN-OS GlobalProtect gateway", "type": "network_appliance", "env": "on_prem", "internet_facing": True, "entry_point": "internet", "owner": "Network Team"},
    {"id": "citrix-adc-01", "name": "Citrix NetScaler ADC", "type": "network_appliance", "env": "on_prem", "internet_facing": True, "entry_point": "internet", "owner": "Network Team"},
    {"id": "tracking-portal", "name": "Shipment tracking portal (Spring)", "type": "web_app", "env": "aws", "internet_facing": True, "entry_point": "internet", "owner": "Commerce Engineering"},
    {"id": "moveit-01", "name": "MOVEit Transfer (partner file exchange)", "type": "application", "env": "on_prem", "internet_facing": True, "entry_point": "internet", "owner": "Integration Team"},
    {"id": "screenconnect-01", "name": "ScreenConnect remote support", "type": "application", "env": "on_prem", "internet_facing": True, "entry_point": "internet", "owner": "IT Service Desk"},
    {"id": "support-chat", "name": "Website customer support chat", "type": "web_app", "env": "azure", "internet_facing": True, "entry_point": "internet", "owner": "Customer Experience"},
    {"id": "finance-inbox", "name": "Accounts payable shared mailbox", "type": "mailbox", "env": "azure", "internet_facing": True, "entry_point": "internet", "owner": "Finance Operations"},
    {"id": "dev-laptops", "name": "Developer laptop fleet (120 devices)", "type": "endpoint_group", "env": "on_prem", "entry_point": "user_action", "owner": "Engineering IT"},
    # Internal systems
    {"id": "corp-net", "name": "Corporate network", "type": "network_segment", "env": "on_prem", "owner": "Network Team"},
    {"id": "build-01", "name": "CI build server", "type": "server", "env": "aws", "owner": "Platform Engineering"},
    {"id": "sharepoint-01", "name": "SharePoint Server (intranet)", "type": "server", "env": "on_prem", "owner": "Collaboration Team"},
    {"id": "reporting-app", "name": "Internal reporting app (Java)", "type": "application", "env": "on_prem", "owner": "Data Team"},
    {"id": "core-router-01", "name": "Cisco IOS XE core router", "type": "network_appliance", "env": "on_prem", "owner": "Network Team"},
    {"id": "file-share-01", "name": "Partner file share", "type": "storage", "env": "on_prem", "owner": "Integration Team"},
    {"id": "outlook-clients", "name": "Outlook desktop clients", "type": "endpoint_group", "env": "on_prem", "owner": "Workplace IT"},
    {"id": "confluence-lab", "name": "Confluence (isolated R&D lab)", "type": "application", "env": "on_prem", "isolated": True, "owner": "R&D"},
    {"id": "xz-test-vm", "name": "Linux test VM (lab)", "type": "server", "env": "on_prem", "isolated": True, "owner": "R&D"},
    {"id": "web-frontends", "name": "Public web front-ends (nginx)", "type": "server_group", "env": "aws", "internet_facing": True, "entry_point": "internet", "owner": "Commerce Engineering"},
    {"id": "data-pipelines", "name": "Python data pipelines", "type": "server_group", "env": "azure", "owner": "Data Team"},
    {"id": "ssh-bastion", "name": "SSH bastion host", "type": "server", "env": "aws", "owner": "Platform Engineering"},
]

# --- Identities (human and machine) ------------------------------------------
IDENTITIES = [
    {"id": "svc-ops-agent", "kind": "machine", "platform": "aws_iam_role", "name": "ops-agent-role", "permissions": ["AdministratorAccess"], "scope": "aws-prod", "notes": "Attached to the CI build server so the Ops agent can 'fix things'."},
    {"id": "svc-support-agent", "kind": "machine", "platform": "entra_service_principal", "name": "support-assistant-sp", "permissions": ["crm.records.read_all", "crm.records.write_all", "mail.send_as_company"], "scope": "crm"},
    {"id": "svc-finance-agent", "kind": "machine", "platform": "entra_service_principal", "name": "ap-reconciler-sp", "permissions": ["erp.invoices.write", "erp.payments.create"], "scope": "finance-erp"},
    {"id": "svc-backup", "kind": "machine", "platform": "aws_iam_user", "name": "backup-svc", "permissions": ["s3:GetObject", "rds:CreateDBSnapshot"], "scope": "orders-db", "access_key_age_days": 412},
    {"id": "it-admin", "kind": "human", "platform": "active_directory", "name": "IT admin (shared account)", "permissions": ["Domain Admins"], "scope": "dc-01", "mfa": False},
    {"id": "wms-app", "kind": "machine", "platform": "entra_managed_identity", "name": "wms-app-mi", "permissions": ["wms.db.read_write"], "scope": "wms-db"},
]

# --- AI agents and MCP servers ----------------------------------------------
AGENTS = [
    {
        "id": "agent-support",
        "name": "Customer Support Assistant",
        "model_provider": "Azure OpenAI",
        "exposed_via": "support-chat",
        "untrusted_input": "Anyone on the public website",
        "acts_as": "svc-support-agent",
        "mcp_servers": ["mcp-crm"],
        "human_approval": False,
        "owner": "Customer Experience",
    },
    {
        "id": "agent-ops",
        "name": "Ops Automation Agent",
        "model_provider": "Anthropic Claude",
        "exposed_via": "corp-net",
        "untrusted_input": "Chat messages from any employee",
        "acts_as": "svc-ops-agent",
        "mcp_servers": ["mcp-ops"],
        "human_approval": False,
        "owner": "Platform Engineering",
    },
    {
        "id": "agent-finance",
        "name": "Invoice Reconciliation Agent",
        "model_provider": "Azure OpenAI",
        "exposed_via": "finance-inbox",
        "untrusted_input": "Invoices emailed by any sender",
        "acts_as": "svc-finance-agent",
        "mcp_servers": ["mcp-erp"],
        "human_approval": False,
        "memory": "Keeps vendor bank details between runs",
        "owner": "Finance Systems",
    },
    {
        "id": "agent-dev-assistants",
        "name": "Developer coding assistants",
        "model_provider": "Various",
        "exposed_via": "dev-laptops",
        "untrusted_input": "Third-party MCP servers developers add themselves",
        "acts_as": None,
        "mcp_servers": ["mcp-remote-client", "mcp-inspector"],
        "human_approval": True,
        "owner": "Engineering",
    },
]

MCP_SERVERS = [
    {"id": "mcp-crm", "name": "CRM tools server", "hosted_on": "support-chat", "auth": "service_token", "listen": "internal",
     "tools": [{"name": "crm.read_customer", "access": "read"}, {"name": "crm.update_customer", "access": "write"}, {"name": "email.send", "access": "send_external"}]},
    {"id": "mcp-ops", "name": "Ops tools server", "hosted_on": "build-01", "auth": "none", "listen": "0.0.0.0:8080",
     "tools": [{"name": "shell.exec", "access": "execute"}, {"name": "aws.cli", "access": "admin"}, {"name": "k8s.apply", "access": "write"}]},
    {"id": "mcp-erp", "name": "ERP tools server", "hosted_on": "finance-erp", "auth": "service_token", "listen": "internal",
     "tools": [{"name": "erp.match_invoice", "access": "write"}, {"name": "erp.update_vendor_bank", "access": "write"}, {"name": "erp.schedule_payment", "access": "payment"}]},
    {"id": "mcp-remote-client", "name": "mcp-remote 0.1.15 (client proxy)", "hosted_on": "dev-laptops", "auth": "n/a", "listen": "local", "package": "mcp-remote@0.1.15",
     "tools": []},
    {"id": "mcp-inspector", "name": "MCP Inspector 0.13.0 (debug tool)", "hosted_on": "dev-laptops", "auth": "none", "listen": "0.0.0.0:6277", "package": "@modelcontextprotocol/inspector@0.13.0",
     "tools": []},
]

# --- Reachability: who can reach whom (attacker movement) --------------------
# kind: network (can connect), runs_as (asset uses identity), admin_of
# (identity controls asset), agent_tool (agent drives an MCP server), hosts.
EDGES = [
    # Internet-facing appliances lead into the corporate network
    ("vpn-gw-01", "corp-net", "network"),
    ("fw-edge-01", "corp-net", "network"),
    ("pan-gp-01", "corp-net", "network"),
    ("citrix-adc-01", "corp-net", "network"),
    ("screenconnect-01", "it-admin", "session_hijack"),
    ("dev-laptops", "corp-net", "network"),
    ("corp-net", "dc-01", "network"),
    ("corp-net", "sharepoint-01", "network"),
    ("corp-net", "reporting-app", "network"),
    ("corp-net", "core-router-01", "network"),
    ("corp-net", "outlook-clients", "network"),
    ("corp-net", "build-01", "network"),  # Direct Connect to the AWS VPC
    ("corp-net", "ssh-bastion", "network"),
    ("it-admin", "dc-01", "admin_of"),
    ("sharepoint-01", "dc-01", "network"),
    ("reporting-app", "wms-db", "network"),
    ("ssh-bastion", "orders-db", "network"),
    # Web
    ("tracking-portal", "orders-db", "network"),
    ("web-frontends", "tracking-portal", "network"),
    ("moveit-01", "file-share-01", "network"),
    # Machine identities
    ("build-01", "svc-ops-agent", "runs_as"),
    ("svc-ops-agent", "aws-prod", "admin_of"),
    ("aws-prod", "orders-db", "admin_of"),
    ("svc-backup", "orders-db", "admin_of"),
    ("data-pipelines", "svc-backup", "runs_as"),
    ("svc-support-agent", "crm", "admin_of"),
    ("svc-finance-agent", "finance-erp", "admin_of"),
    # AI agents
    ("support-chat", "agent-support", "agent_input"),
    ("agent-support", "mcp-crm", "agent_tool"),
    ("mcp-crm", "svc-support-agent", "runs_as"),
    ("corp-net", "agent-ops", "agent_input"),
    ("corp-net", "mcp-ops", "network"),  # listens on 0.0.0.0 with no auth
    ("agent-ops", "mcp-ops", "agent_tool"),
    ("mcp-ops", "build-01", "hosted_on"),
    ("finance-inbox", "agent-finance", "agent_input"),
    ("agent-finance", "mcp-erp", "agent_tool"),
    ("mcp-erp", "svc-finance-agent", "runs_as"),
    ("dev-laptops", "agent-dev-assistants", "agent_input"),
    ("agent-dev-assistants", "mcp-remote-client", "agent_tool"),
    ("agent-dev-assistants", "mcp-inspector", "agent_tool"),
    ("mcp-remote-client", "dev-laptops", "hosted_on"),
    ("mcp-inspector", "dev-laptops", "hosted_on"),
]

# --- Findings that matter (CVEs are real; their placement is invented) ------
SIGNAL_FINDINGS = [
    # Known-exploited CVEs on paths to crown jewels
    {"asset": "vpn-gw-01", "cve": "CVE-2024-21887", "source": "vuln_scanner", "status": "open"},
    {"asset": "dc-01", "cve": "CVE-2020-1472", "source": "vuln_scanner", "status": "open"},
    {"asset": "screenconnect-01", "cve": "CVE-2024-1709", "source": "vuln_scanner", "status": "open"},
    {"asset": "tracking-portal", "cve": "CVE-2022-22965", "source": "vuln_scanner", "status": "open"},
    {"asset": "sharepoint-01", "cve": "CVE-2025-53770", "source": "vuln_scanner", "status": "open"},
    {"asset": "reporting-app", "cve": "CVE-2021-44228", "source": "vuln_scanner", "status": "open"},
    {"asset": "moveit-01", "cve": "CVE-2023-34362", "source": "vuln_scanner", "status": "open"},
    {"asset": "outlook-clients", "cve": "CVE-2023-23397", "source": "vuln_scanner", "status": "open"},
    {"asset": "core-router-01", "cve": "CVE-2023-20198", "source": "vuln_scanner", "status": "open"},
    {"asset": "fw-edge-01", "cve": "CVE-2023-27997", "source": "vuln_scanner", "status": "open"},
    # Already fixed: should drop out of the ranking
    {"asset": "pan-gp-01", "cve": "CVE-2024-3400", "source": "vuln_scanner", "status": "fixed"},
    {"asset": "citrix-adc-01", "cve": "CVE-2023-4966", "source": "vuln_scanner", "status": "fixed"},
    # Decoys: scary scores, no path to anything that matters
    {"asset": "confluence-lab", "cve": "CVE-2023-22515", "source": "vuln_scanner", "status": "open"},
    {"asset": "xz-test-vm", "cve": "CVE-2024-3094", "source": "vuln_scanner", "status": "open"},
    # AI tooling CVEs
    {"asset": "dev-laptops", "cve": "CVE-2025-6514", "source": "sbom", "status": "open", "component": "mcp-remote@0.1.15"},
    {"asset": "dev-laptops", "cve": "CVE-2025-49596", "source": "sbom", "status": "open", "component": "@modelcontextprotocol/inspector@0.13.0"},
]

# Misconfigurations and agent risks have no CVE: CVSS-only tools miss them.
NON_CVE_FINDINGS = [
    {"asset": "mcp-ops", "type": "agent_risk", "title": "MCP server listens on all interfaces with no authentication", "owasp_agentic": ["ASI05", "ASI02"], "source": "agent_inventory", "status": "open"},
    {"asset": "svc-ops-agent", "type": "misconfig", "title": "Agent identity has AdministratorAccess on the production AWS account", "owasp_agentic": ["ASI03"], "source": "cspm", "status": "open"},
    {"asset": "agent-support", "type": "agent_risk", "title": "Public chat input reaches an agent with CRM write and external email tools, no human approval", "owasp_agentic": ["ASI01", "ASI02"], "source": "agent_inventory", "status": "open"},
    {"asset": "svc-support-agent", "type": "misconfig", "title": "Support agent can read and write all CRM records and send mail as the company", "owasp_agentic": ["ASI03"], "source": "identity_scan", "status": "open"},
    {"asset": "agent-finance", "type": "agent_risk", "title": "Agent acts on emailed invoices and can change vendor bank details and schedule payments without approval", "owasp_agentic": ["ASI01", "ASI06", "ASI09"], "source": "agent_inventory", "status": "open"},
    {"asset": "mcp-inspector", "type": "agent_risk", "title": "MCP Inspector proxy exposed on 0.0.0.0 on developer laptops", "owasp_agentic": ["ASI04", "ASI05"], "source": "agent_inventory", "status": "open"},
    {"asset": "it-admin", "type": "misconfig", "title": "Shared Domain Admin account without MFA", "source": "identity_scan", "status": "open"},
    {"asset": "svc-backup", "type": "misconfig", "title": "Access key not rotated in 412 days", "source": "cspm", "status": "open"},
]

# Background noise: real, mostly non-exploited CVEs spread across assets.
NOISE_CVES = [
    "CVE-2024-6387", "CVE-2022-0778", "CVE-2023-38545", "CVE-2022-3602", "CVE-2022-42889",
    "CVE-2023-48795", "CVE-2021-23017", "CVE-2024-2961", "CVE-2023-0464", "CVE-2023-39325",
    "CVE-2023-32681", "CVE-2024-35195", "CVE-2023-43804", "CVE-2024-37891", "CVE-2022-25883",
    "CVE-2024-4067", "CVE-2024-45337", "CVE-2022-40897", "CVE-2023-44487",
]
NOISE_ASSETS = [
    "web-frontends", "tracking-portal", "build-01", "reporting-app", "data-pipelines",
    "ssh-bastion", "sharepoint-01", "confluence-lab", "xz-test-vm", "moveit-01",
]


def build_findings(seed: int = 7) -> list[dict]:
    rng = random.Random(seed)
    findings = []
    for f in SIGNAL_FINDINGS:
        findings.append({"type": "cve", **f})
    for f in NON_CVE_FINDINGS:
        findings.append(f)
    for asset in NOISE_ASSETS:
        for cve in rng.sample(NOISE_CVES, k=rng.randint(4, 8)):
            findings.append({"type": "cve", "asset": asset, "cve": cve, "source": "vuln_scanner", "status": "open"})
    for i, f in enumerate(findings, start=1):
        f["id"] = f"F-{i:04d}"
        f.setdefault("first_seen", f"2026-{rng.randint(6, 10):02d}-{rng.randint(1, 28):02d}")
    return [{"id": f.pop("id"), **f} for f in findings]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    edges = [{"from": a, "to": b, "kind": k} for a, b, k in EDGES]
    files = {
        "company.json": COMPANY,
        "assets.json": ASSETS,
        "identities.json": IDENTITIES,
        "agents.json": AGENTS,
        "mcp_servers.json": MCP_SERVERS,
        "edges.json": edges,
        "findings.json": build_findings(),
    }
    for name, data in files.items():
        (OUT / name).write_text(json.dumps(data, indent=2) + "\n")
    print(f"Wrote {len(files)} files to {OUT}")
    print(f"  {len(ASSETS)} assets, {len(IDENTITIES)} identities, {len(AGENTS)} agents, "
          f"{len(MCP_SERVERS)} MCP servers, {len(edges)} edges, {len(files['findings.json'])} findings")


if __name__ == "__main__":
    main()
