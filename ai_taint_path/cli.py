"""Command line: ai-taint-path scan|discover <environment folder>."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .discovery.probe import HttpTransport
from .engine import scan
from .model import load_environment, load_feeds
from .output.report import build_report
from .output.table import render_discovery, render_scan


def _agent(args):
    if args.agent != "claude":
        return None
    from .discovery.agent import ClaudeDiscoveryAgent  # needs the optional 'anthropic' package

    return ClaudeDiscoveryAgent(model=args.model or os.environ.get("AI_TAINT_PATH_MODEL"))


def _write(text: str, out: str | None) -> None:
    if out:
        Path(out).write_text(text)
        print(f"Wrote {out}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ai-taint-path", description=(
        "Find AI agents, MCP servers and knowledge bases, then rank the attack paths "
        "that run through them to your crown jewels."))
    parser.add_argument("--version", action="version", version=f"ai-taint-path {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p):
        p.add_argument("environment", help="environment folder, e.g. data/sample/halden")
        p.add_argument("--out", help="write to this file instead of stdout")
        p.add_argument("--feeds", help="threat-intel feed folder (default: data/feeds)")
        p.add_argument("--live", action="store_true",
                       help="probe the network for real (read-only, inside discovery/scope.json); "
                            "default replays discovery/probes.json")
        p.add_argument("--agent", choices=["none", "claude"], default="none",
                       help="let a Claude agent choose which leads to probe (needs ANTHROPIC_API_KEY)")
        p.add_argument("--model", help="Claude model for --agent claude (default: claude-opus-5-5, or AI_TAINT_PATH_MODEL)")
        p.add_argument("--generated-at", help=argparse.SUPPRESS)

    s = sub.add_parser("scan", help="discover, then rank attack paths")
    common(s)
    s.add_argument("--format", choices=["table", "json", "html"], default="table")
    s.add_argument("--top", type=int, default=10)
    s.add_argument("--no-discovery", action="store_true", help="rank with scanner and CMDB data only (the baseline)")
    d = sub.add_parser("discover", help="run discovery only")
    common(d)
    d.add_argument("--format", choices=["table", "json"], default="table")

    args = parser.parse_args(argv)
    env = load_environment(args.environment)
    feeds = load_feeds(args.feeds)
    transport = HttpTransport() if args.live else None
    result = scan(env, feeds, use_discovery=not getattr(args, "no_discovery", False), transport=transport,
                  agent=_agent(args), transport_name="live network" if args.live else None)
    report = build_report(result, top=getattr(args, "top", 10), generated_at=args.generated_at)

    if args.command == "discover":
        if args.format == "json":
            payload = {k: report[k] for k in ("schema_version", "tool", "generated_at", "environment", "inventory", "discovery")}
            payload["flags"] = [f for f in report["findings"] if f.get("source") == "discovery"]
            _write(json.dumps(payload, indent=2) + "\n", args.out)
        else:
            _write(render_discovery(report), args.out)
        return 0

    if args.format == "json":
        _write(json.dumps(report, indent=2) + "\n", args.out)
    elif args.format == "html":
        from .output.html import render_html

        _write(render_html(report), args.out)
    else:
        _write(render_scan(report), args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
