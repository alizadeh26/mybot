from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import yaml

from subs import Node, fetch_text, node_from_clash_proxy, node_from_share_link, parse_subscription_payload
from singbox_runner import SingBoxRunner


@dataclass(frozen=True)
class CheckResult:
    healthy_links: list[str]
    healthy_clash_proxies: list[dict]


async def collect_nodes(urls: list[str]) -> list[Node]:
    nodes: list[Node] = []
    seen_tags: set[str] = set()

    for url in urls:
        try:
            text = await fetch_text(url)
        except Exception:
            continue

        links, proxies = parse_subscription_payload(text)

        for link in links:
            try:
                n = node_from_share_link(link)
            except Exception:
                continue
            if n is None:  # اصلاح شده: skip کردن nodeهای ناقص
                continue
            if n.tag in seen_tags:
                continue
            seen_tags.add(n.tag)
            nodes.append(n)

        for p in proxies:
            n = node_from_clash_proxy(p)
            if n is None:  # اصلاح شده: skip کردن nodeهای ناقص
                continue
            if n.tag in seen_tags:
                continue
            seen_tags.add(n.tag)
            nodes.append(n)

    return nodes


async def check_nodes(
    singbox_path: str,
    clash_api_host: str,
    clash_api_port: int,
    test_url: str,
    timeout_ms: int,
    max_concurrency: int,
    nodes: list[Node],
) -> CheckResult:
    outbounds = [n.outbound for n in nodes]
    sem = asyncio.Semaphore(max_concurrency)

    healthy_links: list[str] = []
    healthy_clash: list[dict] = []

    async with SingBoxRunner(singbox_path, clash_api_host, clash_api_port) as runner:
        api = await runner.start(outbounds)

        async def one(n: Node) -> None:
            async with sem:
                try:
                    d = await runner.delay_test(api, n.tag, test_url, timeout_ms)
                except Exception:
                    return
                if d is None:
                    return
                if n.export_link:
                    healthy_links.append(n.export_link)
                if n.export_clash_proxy:
                    healthy_clash.append(n.export_clash_proxy)

        await asyncio.gather(*(one(n) for n in nodes))

    return CheckResult(healthy_links=healthy_links, healthy_clash_proxies=healthy_clash)


def render_outputs(res: CheckResult) -> tuple[bytes, bytes]:
    txt = "\n".join(res.healthy_links).strip() + "\n"

    yaml_obj = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "Rule",
        "log-level": "silent",
        "proxies": res.healthy_clash_proxies,
        "proxy-groups": [
            {
                "name": "AUTO",
                "type": "url-test",
                "url": "https://cp.cloudflare.com/generate_204",
                "interval": 300,
                "proxies": [p.get("name") for p in res.healthy_clash_proxies if isinstance(p, dict) and p.get("name")],
            }
        ],
        "rules": ["MATCH,AUTO"],
    }
    yml = yaml.safe_dump(yaml_obj, allow_unicode=True, sort_keys=False).encode("utf-8")
    return txt.encode("utf-8"), yml


def build_commit_message(prefix: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    return f"{prefix} {ts}"