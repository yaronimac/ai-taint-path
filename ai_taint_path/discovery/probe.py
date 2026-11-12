"""Read-only probes, fenced in by a scope.

The discovery agent may ask a server to describe itself and nothing more:
MCP initialize and tools/list, and one read-only GET for each supported
vector database. It never calls a tool, never writes, never follows a
redirect and never contacts a host outside the scope. These limits are
enforced here, below the agent, so a confused or manipulated agent cannot
talk its way past them.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse

from .. import __version__

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "ai-taint-path-discovery", "version": __version__}
ALLOWED_RPC = ("initialize", "notifications/initialized", "tools/list")
VECTOR_PROBES = {"qdrant": "/collections", "weaviate": "/v1/schema"}
MAX_TOOL_PAGES = 5


class OutOfScope(Exception):
    """The target is outside the agreed scope, so nothing was sent."""


class NotAllowed(Exception):
    """The request is not on the read-only allowlist, so nothing was sent."""


@dataclass
class Response:
    status: int  # 0 when nothing answered
    headers: dict = field(default_factory=dict)
    body: object = None
    error: str | None = None

    def header(self, name: str) -> str | None:
        return next((v for k, v in self.headers.items() if k.lower() == name.lower()), None)


class Transport(Protocol):
    def send(self, method: str, url: str, body: dict | None = None, headers: dict | None = None) -> Response: ...


class Scope:
    def __init__(self, networks: list[dict], hosts: list[str] | None = None, max_requests: int = 60):
        self.networks = [(ipaddress.ip_network(n["cidr"]), n.get("segment")) for n in networks]
        self.hosts = {h.lower() for h in hosts or []}
        self.max_requests = max_requests

    @classmethod
    def load(cls, path: Path) -> "Scope":
        if not path.exists():
            return cls([], [], 0)
        data = json.loads(path.read_text())
        return cls(data.get("networks", []), data.get("hosts", []), int(data.get("max_requests", 60)))

    def check(self, url: str) -> tuple[bool, str]:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False, "not an http(s) URL"
        host = parsed.hostname.lower()
        if host in self.hosts:
            return True, "listed host"
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False, f"{host} is not in the scope list"
        for net, _ in self.networks:
            if ip in net:
                return True, f"inside {net}"
        return False, f"{host} is outside the scope networks"

    def segment_for(self, url: str) -> str | None:
        try:
            ip = ipaddress.ip_address(urlparse(url).hostname or "")
        except ValueError:
            return None
        return next((seg for net, seg in self.networks if ip in net), None)

    def describe(self) -> dict:
        return {"networks": [str(n) for n, _ in self.networks], "hosts": sorted(self.hosts), "max_requests": self.max_requests}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # a redirect could point outside the scope
        return None


def _parse_body(raw: bytes, content_type: str) -> object:
    text = raw.decode("utf-8", "replace")
    if "text/event-stream" in (content_type or ""):
        messages = []
        for line in text.splitlines():
            if line.startswith("data:") and line[5:].strip():
                try:
                    messages.append(json.loads(line[5:].strip()))
                except ValueError:
                    pass
        return messages[-1] if messages else None
    try:
        return json.loads(text) if text.strip() else None
    except ValueError:
        return text[:2000]


class HttpTransport:
    """Real network transport for live scans. Direct connections only (no
    proxy from the environment), no redirects, short timeouts."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def send(self, method, url, body=None, headers=None) -> Response:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return Response(r.status, dict(r.headers), _parse_body(r.read(), r.headers.get("Content-Type", "")))
        except urllib.error.HTTPError as e:
            hdrs = dict(e.headers or {})
            return Response(e.code, hdrs, _parse_body(e.read() or b"", hdrs.get("Content-Type", "")))
        except (urllib.error.URLError, OSError) as e:
            return Response(0, error=str(getattr(e, "reason", e)))


class FixtureTransport:
    """Replays recorded responses (discovery/probes.json). Anything without a
    recording behaves like a host that does not answer. Every request is kept
    in .sent so tests can check exactly what would have gone on the wire."""

    def __init__(self, responses: dict):
        self.responses = responses
        self.sent: list[str] = []

    @classmethod
    def load(cls, path: Path) -> "FixtureTransport":
        return cls(json.loads(path.read_text()).get("responses", {}) if path.exists() else {})

    def send(self, method, url, body=None, headers=None) -> Response:
        key = f"{method} {url}" + (f" {body['method']}" if isinstance(body, dict) and "method" in body else "")
        self.sent.append(key)
        rec = self.responses.get(key)
        if rec is None:
            return Response(0, error="no answer")
        return Response(rec["status"], dict(rec.get("headers", {})), rec.get("body"))


@dataclass
class McpProbe:
    url: str
    outcome: str  # answered | auth_required | no_answer | not_mcp
    auth: str  # none | required | unknown
    http_status: int = 0
    server_name: str | None = None
    server_version: str | None = None
    protocol_version: str | None = None
    instructions: str | None = None
    tools: list[dict] = field(default_factory=list)
    detail: str = ""


@dataclass
class VectorProbe:
    url: str
    product: str
    outcome: str  # answered | auth_required | no_answer | error | unsupported
    auth: str
    http_status: int = 0
    collections: list[str] = field(default_factory=list)
    detail: str = ""


class Prober:
    def __init__(self, transport: Transport, scope: Scope):
        self.transport = transport
        self.scope = scope
        self.requests = 0
        self.log: list[dict] = []

    def _send(self, method: str, url: str, body: dict | None = None, headers: dict | None = None) -> Response:
        ok, why = self.scope.check(url)
        if not ok:
            raise OutOfScope(why)
        rpc = body.get("method") if isinstance(body, dict) else None
        if method == "POST" and rpc not in ALLOWED_RPC:
            raise NotAllowed(f"MCP method {rpc!r} is not on the read-only allowlist")
        if method == "GET" and urlparse(url).path not in VECTOR_PROBES.values():
            raise NotAllowed(f"GET {urlparse(url).path} is not on the read-only allowlist")
        if method not in ("GET", "POST"):
            raise NotAllowed(f"HTTP {method} is never sent")
        if self.requests >= self.scope.max_requests:
            raise NotAllowed("request budget for this scan is used up")
        self.requests += 1
        resp = self.transport.send(method, url, body, headers)
        self.log.append({"request": f"{method} {url}" + (f" ({rpc})" if rpc else ""),
                         "result": resp.status or (resp.error or "no answer")})
        return resp

    def probe_mcp(self, url: str) -> McpProbe:
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": CLIENT_INFO}}
        r = self._send("POST", url, init, headers)
        if r.status == 0:
            return McpProbe(url, "no_answer", "unknown", detail=r.error or "no answer")
        if r.status in (401, 403):
            hint = r.header("WWW-Authenticate") or ""
            return McpProbe(url, "auth_required", "required", r.status, detail=f"HTTP {r.status} {hint}".strip())
        result = r.body.get("result") if isinstance(r.body, dict) else None
        if r.status != 200 or not isinstance(result, dict):
            return McpProbe(url, "not_mcp", "unknown", r.status, detail="no MCP initialize result")
        h2 = dict(headers, **{"MCP-Protocol-Version": result.get("protocolVersion", PROTOCOL_VERSION)})
        if r.header("Mcp-Session-Id"):
            h2["Mcp-Session-Id"] = r.header("Mcp-Session-Id")
        self._send("POST", url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, h2)
        tools, cursor = [], None
        for page in range(MAX_TOOL_PAGES):
            body = {"jsonrpc": "2.0", "id": 2 + page, "method": "tools/list"}
            if cursor:
                body["params"] = {"cursor": cursor}
            t = self._send("POST", url, body, h2)
            res = t.body.get("result") if isinstance(t.body, dict) else None
            if t.status != 200 or not isinstance(res, dict):
                break
            tools.extend(x for x in res.get("tools", []) if isinstance(x, dict) and x.get("name"))
            cursor = res.get("nextCursor")
            if not cursor:
                break
        info = result.get("serverInfo") or {}
        return McpProbe(url, "answered", "none", 200, info.get("name"), info.get("version"),
                        result.get("protocolVersion"), result.get("instructions"), tools,
                        detail="initialize answered without credentials")

    def probe_vector_store(self, base_url: str, product: str) -> VectorProbe:
        path = VECTOR_PROBES.get(product)
        if not path:
            return VectorProbe(base_url, product, "unsupported", "unknown", detail=f"no read-only probe for {product}")
        r = self._send("GET", base_url.rstrip("/") + path, headers={"Accept": "application/json"})
        if r.status == 0:
            return VectorProbe(base_url, product, "no_answer", "unknown", detail=r.error or "no answer")
        if r.status in (401, 403):
            return VectorProbe(base_url, product, "auth_required", "required", r.status, detail=f"HTTP {r.status}")
        if r.status != 200 or not isinstance(r.body, dict):
            return VectorProbe(base_url, product, "error", "unknown", r.status, detail=f"HTTP {r.status}")
        if product == "qdrant":
            names = [c.get("name") for c in (r.body.get("result") or {}).get("collections", [])]
        else:
            names = [c.get("class") for c in r.body.get("classes", [])]
        return VectorProbe(base_url, product, "answered", "none", 200, [n for n in names if n],
                           detail=f"GET {path} answered without credentials")
