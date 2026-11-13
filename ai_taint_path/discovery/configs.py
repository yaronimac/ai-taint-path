"""Read MCP client configuration files collected from hosts.

Understands Claude Desktop (claude_desktop_config.json), Cursor
(.cursor/mcp.json), Claude Code (.mcp.json and .claude/settings.json) and VS
Code (.vscode/mcp.json). The first folder under configs/ names the asset the
files came from.

Secret values are never kept. When a config holds a literal API key or
password, only the name of the variable that holds it is recorded.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

# (path suffix, client, key that holds the server map)
CLIENT_FILES = [
    ("claude_desktop_config.json", "claude_desktop", "mcpServers"),
    (".cursor/mcp.json", "cursor", "mcpServers"),
    (".vscode/mcp.json", "vscode", "servers"),
    (".mcp.json", "claude_code", "mcpServers"),
]
CLIENT_NAMES = {
    "claude_desktop": "Claude Desktop",
    "cursor": "Cursor",
    "vscode": "VS Code",
    "claude_code": "Claude Code",
}
# Clients that ask the user before each tool call unless told otherwise
ASKS_BEFORE_TOOL_CALLS = {"claude_desktop", "cursor", "vscode", "claude_code"}

SECRET_NAME = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE", re.I)
PLACEHOLDER = re.compile(r"^(\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|<[^>]*>|\*+|)$")
URL_WITH_PASSWORD = re.compile(r"^[a-z][a-z0-9+.\-]*://[^:/@\s]+:[^@/\s]+@", re.I)
LAUNCHERS_NPM = {"npx", "bunx", "pnpx"}
LAUNCHERS_PY = {"uvx", "pipx"}
UNPINNED = {"latest", "next", "*", ""}


@dataclass
class ConfiguredServer:
    host: str
    client: str
    config_path: str
    name: str
    transport: str  # stdio | http | sse
    url: str | None = None
    command: str | None = None
    package: str | None = None
    version: str | None = None
    pinned: bool = False
    remote_url: str | None = None  # server reached through a local proxy such as mcp-remote
    listen_host: str | None = None
    listen_port: int | None = None
    secret_vars: list[str] = field(default_factory=list)
    referenced_hosts: list[str] = field(default_factory=list)
    # target host -> variable, account, config file and the machine it is on (names only, never values)
    references: dict[str, dict] = field(default_factory=dict)
    auto_approved: bool = False

    @property
    def listens_on_network(self) -> bool:
        return self.listen_port is not None and self.listen_host not in ("127.0.0.1", "localhost", "::1")

    def where(self) -> str:
        return f"{self.host}/{self.config_path}"


@dataclass
class ConfigEvidence:
    servers: list[ConfiguredServer] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def split_npm_spec(spec: str) -> tuple[str, str | None]:
    """'@scope/pkg@1.2.3' -> ('@scope/pkg', '1.2.3'); 'pkg' -> ('pkg', None)."""
    at = spec.rfind("@")
    if at > 0:
        return spec[:at], spec[at + 1:]
    return spec, None


def split_pypi_spec(spec: str) -> tuple[str, str | None]:
    """'pkg==1.2.3' -> ('pkg', '1.2.3'); 'pkg>=1' -> ('pkg', '>=1'); 'pkg' -> ('pkg', None)."""
    m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*(==|>=|<=|~=|>|<)?\s*(.*)$", spec)
    if not m or not m.group(2):
        return spec, None
    return m.group(1), m.group(3) if m.group(2) == "==" else m.group(2) + m.group(3)


def is_pinned(version: str | None) -> bool:
    return bool(version) and version not in UNPINNED and not re.match(r"^[\^~<>=*]", version)


def parse_launch(command: str | None, args: list[str]) -> tuple[str | None, str | None, list[str]]:
    """Find the package a stdio server is launched from. Returns (package, version, remaining args)."""
    launcher = PurePosixPath(command or "").name
    if launcher in LAUNCHERS_NPM | LAUNCHERS_PY:
        rest = list(args)
        if launcher == "pipx" and rest[:1] == ["run"]:
            rest = rest[1:]
        while rest and rest[0].startswith("-"):
            flag = rest.pop(0)
            if flag in ("-p", "--package", "--from") and rest:  # 'npx -p pkg cmd' / 'uvx --from pkg cmd'
                spec = rest.pop(0)
                name, version = split_npm_spec(spec) if launcher in LAUNCHERS_NPM else split_pypi_spec(spec)
                return name, version, rest[1:]
        if not rest:
            return None, None, []
        spec = rest.pop(0)
        name, version = split_npm_spec(spec) if launcher in LAUNCHERS_NPM else split_pypi_spec(spec)
        return name, version, rest
    return None, None, list(args)


def flag_value(args: list[str], flag: str) -> str | None:
    for i, a in enumerate(args):
        if a == flag and i + 1 < len(args):
            return args[i + 1]
        if a.startswith(flag + "="):
            return a.split("=", 1)[1]
    return None


def scan_env(values: dict[str, str]) -> tuple[list[str], list[str], dict[str, dict]]:
    """Names of variables holding literal secrets, hostnames the values point at, and for each
    host the variable that points at it and the account name in its URL. Values are never kept."""
    secrets, hosts, references = [], [], {}
    for key, value in (values or {}).items():
        value = str(value)
        if URL_WITH_PASSWORD.match(value) or (SECRET_NAME.search(key) and not PLACEHOLDER.match(value.strip())):
            secrets.append(key)
        if "://" in value:
            url = urlparse(value)
            if url.hostname:
                hosts.append(url.hostname)
                ref = {"variable": key}
                if url.username:
                    ref["account"] = url.username
                references.setdefault(url.hostname, ref)
    return secrets, hosts, references


def parse_server(host: str, client: str, rel_path: str, name: str, entry: dict) -> ConfiguredServer:
    url = entry.get("url") or entry.get("serverUrl")
    transport = entry.get("type") or ("http" if url else "stdio")
    if transport == "streamable-http":
        transport = "http"
    command, args = entry.get("command"), [str(a) for a in entry.get("args", [])]
    package, version, rest = parse_launch(command, args)
    remote = next((a for a in rest if a.startswith(("http://", "https://"))), None) if package == "mcp-remote" else None
    port = flag_value(rest, "--port")
    secrets, hosts, references = scan_env(entry.get("env", {}))
    header_secrets, _, _ = scan_env({k: v for k, v in entry.get("headers", {}).items()})
    return ConfiguredServer(
        host=host, client=client, config_path=rel_path, name=name, transport=transport,
        url=url, command=command, package=package, version=version, pinned=is_pinned(version),
        remote_url=remote,
        listen_host=flag_value(rest, "--host") if port else None,
        listen_port=int(port) if port and port.isdigit() else None,
        secret_vars=sorted(set(secrets + [f"header {h}" for h in header_secrets])),
        referenced_hosts=sorted(set(hosts)),
        references={h: {**ref, "config": rel_path, "host": host} for h, ref in sorted(references.items())},
    )


def identify(rel_path: str) -> tuple[str, str] | None:
    for suffix, client, key in CLIENT_FILES:
        if rel_path == suffix or rel_path.endswith("/" + suffix):
            return client, key
    return None


def approved_servers(settings_file: Path) -> set[str]:
    """MCP servers whose tools Claude Code may call without asking ('mcp__<server>' in permissions.allow)."""
    if not settings_file.exists():
        return set()
    allow = json.loads(settings_file.read_text()).get("permissions", {}).get("allow", [])
    return {rule.split("__")[1] for rule in allow if rule.startswith("mcp__") and len(rule.split("__")) == 2}


def collect(config_root: Path) -> ConfigEvidence:
    evidence = ConfigEvidence()
    if not config_root.exists():
        return evidence
    for host_dir in sorted(p for p in config_root.iterdir() if p.is_dir()):
        host = host_dir.name
        auto = set()
        for settings in sorted(host_dir.rglob(".claude/settings*.json")):
            evidence.files.append(f"{host}/{settings.relative_to(host_dir).as_posix()}")
            auto |= approved_servers(settings)
        for f in sorted(host_dir.rglob("*.json")):
            rel = f.relative_to(host_dir).as_posix()
            kind = identify(rel)
            if not kind:
                continue
            client, key = kind
            evidence.files.append(f"{host}/{rel}")
            try:
                data = json.loads(f.read_text())
            except ValueError as exc:
                evidence.errors.append(f"{host}/{rel}: not valid JSON ({exc})")
                continue
            for name, entry in sorted((data.get(key) or {}).items()):
                server = parse_server(host, client, rel, name, entry)
                server.auto_approved = client == "claude_code" and name in auto
                evidence.servers.append(server)
    return evidence
