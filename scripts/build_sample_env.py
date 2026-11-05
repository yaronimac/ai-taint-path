"""Build the fictional sample company used by the demo and the tests.

Halden Logistics is invented. Its assets, identities, AI agents and findings
are made up, but every CVE it references is real, so the engine can enrich
them with real public threat intelligence (CISA KEV, CVE records).

Run:  python scripts/build_sample_env.py
Writes the scanner-style JSON files in data/sample/halden/. The discovery
evidence in data/sample/halden/discovery/ (MCP client configs, recorded probe
responses, cloud AI exports) is written by hand, like real collected evidence,
and is not touched by this script. Neither is expected.json, the ground truth
the tests check the engine against.
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
# crown_jewel: what the board cares about; impact (0-1) weights how much.
# entry_point: "internet" (anyone can reach it) or "user_action" (reached when an
# employee opens a link, email or untrusted tool).
# open_channel: anyone can put content into it (a chat box, a shared mailbox, an
# upload form), so no exploit is needed to start a path there.
# addresses / hostnames: let discovery match the endpoints it finds to assets.
ASSETS = [
    # Crown jewels
    {"id": "aws-prod", "name": "AWS production account", "type": "cloud_account", "env": "aws", "crown_jewel": True, "impact": 1.0, "business_service": "All customer-facing systems", "owner": "Cloud Platform"},
    {"id": "orders-db", "name": "Orders database (RDS)", "type": "database", "env": "aws", "crown_jewel": True, "impact": 0.8, "business_service": "Order management", "owner": "Commerce Engineering"},
    {"id": "crm", "name": "Customer CRM", "type": "saas", "env": "azure", "crown_jewel": True, "impact": 0.9, "business_service": "Customer records (PII)", "owner": "Sales Operations"},
    {"id": "dc-01", "name": "Active Directory domain controller", "type": "server", "env": "on_prem", "crown_jewel": True, "impact": 1.0, "business_service": "Identity for all staff", "owner": "IT Infrastructure"},
    {"id": "finance-erp", "name": "Finance ERP", "type": "application", "env": "azure", "crown_jewel": True, "impact": 0.9, "hostnames": ["erp.halden.internal"], "business_service": "Payments and invoicing", "owner": "Finance Systems"},
    {"id": "wms-db", "name": "Warehouse management database", "type": "database", "env": "azure", "crown_jewel": True, "impact": 0.7, "hostnames": ["wms-db.halden.internal"], "business_service": "Warehouse operations", "owner": "Logistics Engineering"},
    # Internet-facing entry points
    {"id": "vpn-gw-01", "name": "Ivanti Connect Secure VPN gateway", "type": "network_appliance", "env": "on_prem", "internet_facing": True, "entry_point": "internet", "owner": "Network Team"},
    {"id": "fw-edge-01", "name": "FortiGate SSL-VPN (branch offices)", "type": "network_appliance", "env": "on_prem", "internet_facing": True, "entry_point": "internet", "owner": "Network Team"},
    {"id": "pan-gp-01", "name": "PAN-OS GlobalProtect gateway", "type": "network_appliance", "env": "on_prem", "internet_facing": True, "entry_point": "internet", "owner": "Network Team"},
    {"id": "citrix-adc-01", "name": "Citrix NetScaler ADC", "type": "network_appliance", "env": "on_prem", "internet_facing": True, "entry_point": "internet", "owner": "Network Team"},
    {"id": "tracking-portal", "name": "Shipment tracking portal (Spring)", "type": "web_app", "env": "aws", "internet_facing": True, "entry_point": "internet", "owner": "Commerce Engineering"},
    {"id": "moveit-01", "name": "MOVEit Transfer (partner file exchange)", "type": "application", "env": "on_prem", "internet_facing": True, "entry_point": "internet", "owner": "Integration Team"},
    {"id": "screenconnect-01", "name": "ScreenConnect remote support", "type": "application", "env": "on_prem", "internet_facing": True, "entry_point": "internet", "owner": "IT Service Desk"},
    {"id": "support-chat", "name": "Website customer support chat", "type": "web_app", "env": "azure", "internet_facing": True, "entry_point": "internet", "open_channel": True, "owner": "Customer Experience"},
    {"id": "finance-inbox", "name": "Accounts payable shared mailbox", "type": "mailbox", "env": "azure", "internet_facing": True, "entry_point": "internet", "open_channel": True, "owner": "Finance Operations"},
    {"id": "dev-laptops", "name": "Developer laptop fleet (120 devices)", "type": "endpoint_group", "env": "on_prem", "entry_point": "user_action", "owner": "Engineering IT"},
    # Internal systems
    {"id": "corp-net", "name": "Corporate network (10.20.0.0/16, AWS VPC joined over Direct Connect)", "type": "network_segment", "env": "on_prem", "cidr": "10.20.0.0/16", "owner": "Network Team"},
    {"id": "azure-apps", "name": "Azure application network (10.30.0.0/16)", "type": "network_segment", "env": "azure", "cidr": "10.30.0.0/16", "owner": "Cloud Platform"},
    {"id": "build-01", "name": "CI build server", "type": "server", "env": "aws", "addresses": ["10.20.1.15"], "owner": "Platform Engineering"},
    {"id": "sharepoint-01", "name": "SharePoint Server (intranet)", "type": "server", "env": "on_prem", "owner": "Collaboration Team"},
    {"id": "reporting-app", "name": "Internal reporting app (Java)", "type": "application", "env": "on_prem", "owner": "Data Team"},
    {"id": "core-router-01", "name": "Cisco IOS XE core router", "type": "network_appliance", "env": "on_prem", "owner": "Network Team"},
    {"id": "file-share-01", "name": "Partner file share", "type": "storage", "env": "on_prem", "owner": "Integration Team"},
    {"id": "outlook-clients", "name": "Outlook desktop clients", "type": "endpoint_group", "env": "on_prem", "owner": "Workplace IT"},
    {"id": "confluence-lab", "name": "Confluence (isolated R&D lab)", "type": "application", "env": "on_prem", "isolated": True, "owner": "R&D"},
    {"id": "xz-test-vm", "name": "Linux test VM (lab)", "type": "server", "env": "on_prem", "isolated": True, "owner": "R&D"},
    {"id": "web-frontends", "name": "Public web front-ends (nginx)", "type": "server_group", "env": "aws", "internet_facing": True, "entry_point": "internet", "owner": "Commerce Engineering"},
    {"id": "data-pipelines", "name": "Python data pipeline hosts", "type": "server_group", "env": "on_prem", "addresses": ["10.20.4.17", "10.20.4.21"], "owner": "Data Team"},
    {"id": "ssh-bastion", "name": "SSH bastion host", "type": "server", "env": "aws", "owner": "Platform Engineering"},
    {"id": "weaviate-01", "name": "Weaviate vector database (product search)", "type": "vector_store", "env": "on_prem", "product": "weaviate", "addresses": ["10.20.5.40"], "endpoint": "http://10.20.5.40:8080", "owner": "Data Team"},
    # Added for step 2: an upload channel that feeds the support knowledge base
    {"id": "support-portal", "name": "Customer support portal (ticket attachments)", "type": "web_app", "env": "azure", "internet_facing": True, "entry_point": "internet", "open_channel": True, "owner": "Customer Experience"},
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

# --- AI inventory (what the AI governance team has registered) -------------
# Discovery compares what it finds with this list. It holds names and owners,
# not wiring: which tools an agent really has, who can talk to it and what the
# servers really expose is what discovery has to find out.
AI_REGISTRY = {
    "description": "Halden's AI inventory, as kept by the AI governance team in a spreadsheet. Anything discovery finds that is not here is shadow AI.",
    "agents": [
        {"id": "agent-support", "name": "Customer Support Assistant", "platform": "azure_ai_foundry", "owner": "Customer Experience", "approved": "2026-03-14"},
        {"id": "agent-finance", "name": "Invoice Reconciliation Agent", "platform": "azure_ai_foundry", "owner": "Finance Systems", "approved": "2026-05-02"},
        {"id": "agent-ops", "name": "Ops Automation Agent", "platform": "claude_code", "clients": ["claude_code"], "hosts": ["build-01"], "owner": "Platform Engineering", "approved": "2026-06-20",
         "input_channel": {"asset": "corp-net", "audience": "internal", "description": "Requests from any employee in the #ops-requests chat channel"}},
        {"id": "agent-dev-assistants", "name": "Developer coding assistants (Claude Desktop, Cursor, VS Code)", "platform": "desktop", "clients": ["claude_desktop", "cursor", "vscode"], "owner": "Engineering IT", "approved": "2026-02-01",
         "input_channel": {"asset": "dev-laptops", "audience": "internal", "description": "The developer at the keyboard"}},
    ],
    "mcp_servers": [
        {"id": "mcp-ops", "name": "Ops tools server", "endpoint": "http://10.20.1.15:8080/mcp", "owner": "Platform Engineering"},
        {"id": "mcp-crm", "name": "CRM tools server", "endpoint": "https://10.30.2.8:8443/mcp", "owner": "Sales Operations"},
        {"id": "mcp-erp", "name": "ERP tools server", "endpoint": "https://10.30.2.9:8443/mcp", "owner": "Finance Systems"},
        {"id": "docs-search-mcp", "name": "Intranet docs search", "endpoint": "http://10.20.4.21:8000/mcp", "owner": "Data Team"},
        {"id": "calendar-mcp", "name": "Meeting room calendar", "endpoint": "https://10.20.6.12:8443/mcp", "owner": "Workplace IT"},
        {"id": "fs-tools-mcp", "name": "Halden file tools (internal package)", "package": "@halden/fs-tools", "approved_versions": ["1.4.0"], "owner": "Engineering IT"},
    ],
    "knowledge_bases": [],
}


# --- Reachability: who can reach whom (attacker movement) --------------------
# This is the "static" graph a CMDB, a network map and a cloud posture tool
# would give you. AI agents, MCP servers and knowledge bases are missing on
# purpose: discovery adds them and their wiring.
# kind: network (can connect; needs a foothold on the target unless it is a
# network segment), data_access (holds credentials to it), runs_as (uses the
# identity), admin_of (identity controls it), session_hijack.
EDGES = [
    # Internet-facing appliances lead into the corporate network
    ("vpn-gw-01", "corp-net", "network"),
    ("fw-edge-01", "corp-net", "network"),
    ("pan-gp-01", "corp-net", "network"),
    ("citrix-adc-01", "corp-net", "network"),
    ("screenconnect-01", "it-admin", "session_hijack"),
    ("dev-laptops", "corp-net", "network"),
    ("corp-net", "azure-apps", "network"),  # ExpressRoute to the Azure app network
    ("corp-net", "dc-01", "network"),
    ("corp-net", "sharepoint-01", "network"),
    ("corp-net", "reporting-app", "network"),
    ("corp-net", "core-router-01", "network"),
    ("corp-net", "outlook-clients", "network"),
    ("corp-net", "build-01", "network"),  # Direct Connect to the AWS VPC
    ("corp-net", "ssh-bastion", "network"),
    ("it-admin", "dc-01", "admin_of"),
    ("sharepoint-01", "dc-01", "network"),
    ("reporting-app", "wms-db", "data_access"),
    ("ssh-bastion", "orders-db", "network"),
    # Web
    ("tracking-portal", "orders-db", "data_access"),
    ("web-frontends", "tracking-portal", "network"),
    ("moveit-01", "file-share-01", "data_access"),
    # Machine identities
    ("build-01", "svc-ops-agent", "runs_as"),
    ("svc-ops-agent", "aws-prod", "admin_of"),
    ("aws-prod", "orders-db", "admin_of"),
    ("svc-backup", "orders-db", "admin_of"),
    ("data-pipelines", "svc-backup", "runs_as"),
    ("svc-support-agent", "crm", "admin_of"),
    ("svc-finance-agent", "finance-erp", "admin_of"),
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
    {"asset": "fw-edge-01", "cve": "CVE-2023-27997", "source": "vuln_scanner", "status": "fixed"},
    # Already fixed (fw-edge-01 above too): should drop out of the ranking
    {"asset": "pan-gp-01", "cve": "CVE-2024-3400", "source": "vuln_scanner", "status": "fixed"},
    {"asset": "citrix-adc-01", "cve": "CVE-2023-4966", "source": "vuln_scanner", "status": "fixed"},
    # Decoys: scary scores, no path to anything that matters
    {"asset": "confluence-lab", "cve": "CVE-2023-22515", "source": "vuln_scanner", "status": "open"},
    {"asset": "xz-test-vm", "cve": "CVE-2024-3094", "source": "vuln_scanner", "status": "open"},
    # AI tooling CVE the SBOM scanner already knows about. The vulnerable
    # mcp-remote client (CVE-2025-6514) is not in the SBOM: discovery finds it
    # in a laptop's Claude Desktop config.
    {"asset": "dev-laptops", "cve": "CVE-2025-49596", "source": "sbom", "status": "open", "component": "@modelcontextprotocol/inspector@0.13.0"},
]

# Misconfigurations have no CVE: CVSS-only tools miss them. Agent risks
# (no approval step, unauthenticated MCP servers, poisoned tools) are not
# here at all: discovery finds those.
NON_CVE_FINDINGS = [
    {"asset": "svc-ops-agent", "type": "misconfig", "title": "Agent identity has AdministratorAccess on the production AWS account", "source": "cspm", "status": "open", "severity": "high",
     "tags": ["excess_privilege"], "grants_edge": {"from": "svc-ops-agent", "to": "aws-prod"},
     "remediation": "Replace AdministratorAccess with a least-privilege policy limited to the build pipeline's resources."},
    {"asset": "svc-support-agent", "type": "misconfig", "title": "Support agent identity can read and write all CRM records and send mail as the company", "source": "identity_scan", "status": "open", "severity": "high",
     "remediation": "Limit the service principal to the records of the customer in the conversation and remove send-as rights."},
    {"asset": "it-admin", "type": "misconfig", "title": "Shared Domain Admin account without MFA", "source": "identity_scan", "status": "open", "severity": "high",
     "remediation": "Replace the shared account with named admin accounts that require phishing-resistant MFA."},
    {"asset": "svc-backup", "type": "misconfig", "title": "Access key not rotated in 412 days", "source": "cspm", "status": "open", "severity": "medium",
     "remediation": "Rotate the key and move the backup job to a role with short-lived credentials."},
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
        findings.append(dict(f))
    for asset in NOISE_ASSETS:
        for cve in rng.sample(NOISE_CVES, k=rng.randint(4, 8)):
            findings.append({"type": "cve", "asset": asset, "cve": cve, "source": "vuln_scanner", "status": "open"})
    for i, f in enumerate(findings, start=1):
        f["id"] = f"F-{i:04d}"
        f.setdefault("first_seen", f"2026-{rng.randint(6, 10):02d}-{rng.randint(1, 28):02d}")
    return [{"id": f.pop("id"), **f} for f in findings]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for stale in ("agents.json", "mcp_servers.json"):  # replaced by ai_registry.json in step 2
        (OUT / stale).unlink(missing_ok=True)
    edges = [{"from": a, "to": b, "kind": k} for a, b, k in EDGES]
    files = {
        "company.json": COMPANY,
        "assets.json": ASSETS,
        "identities.json": IDENTITIES,
        "ai_registry.json": AI_REGISTRY,
        "edges.json": edges,
        "findings.json": build_findings(),
    }
    for name, data in files.items():
        (OUT / name).write_text(json.dumps(data, indent=2) + "\n")
    print(f"Wrote {len(files)} files to {OUT}")
    print(f"  {len(ASSETS)} assets, {len(IDENTITIES)} identities, {len(AI_REGISTRY['agents'])} registered agents, "
          f"{len(AI_REGISTRY['mcp_servers'])} registered MCP servers, {len(edges)} edges, {len(files['findings.json'])} findings")


if __name__ == "__main__":
    main()
