from __future__ import annotations

import asyncio
import os
from datetime import datetime

from checker import check_nodes, collect_nodes, render_outputs
from config import load_settings
from telegram_sender import send_document, send_message


def load_subscription_urls(path: str) -> list[str]:
    if not os.path.exists(path):
        raise RuntimeError(f"subscriptions file not found: {path}")
    urls: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            u = line.strip()
            if not u:
                continue
            urls.append(u)
    return urls


async def main() -> None:
    settings = load_settings()

    subs_file = os.environ.get("SUBSCRIPTIONS_FILE", "subscriptions.txt")
    urls = load_subscription_urls(subs_file)

    await send_message(settings.telegram_bot_token, settings.admin_chat_id, "شروع بررسی...")

    nodes = await collect_nodes(urls)
    if not nodes:
        await send_message(settings.telegram_bot_token, settings.admin_chat_id, "هیچ نودی استخراج نشد")
        return

    res = await check_nodes(
        singbox_path=settings.singbox_path,
        clash_api_host=settings.clash_api_host,
        clash_api_port=settings.clash_api_port,
        test_url=settings.test_url,
        timeout_ms=settings.test_timeout_ms,
        max_concurrency=settings.max_concurrency,
        nodes=nodes,
    )

    txt_bytes, yml_bytes = render_outputs(res)

    txt_path = settings.github_output_txt_path
    yml_path = settings.github_output_yaml_path

    os.makedirs(os.path.dirname(txt_path) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(yml_path) or ".", exist_ok=True)

    with open(txt_path, "wb") as f:
        f.write(txt_bytes)

    with open(yml_path, "wb") as f:
        f.write(yml_bytes)

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    await send_document(
        settings.telegram_bot_token,
        settings.admin_chat_id,
        filename=f"healthy_{ts}.txt",
        content=txt_bytes,
        caption=f"Healthy links: {len(res.healthy_links)}",
    )
    await send_document(
        settings.telegram_bot_token,
        settings.admin_chat_id,
        filename=f"healthy_{ts}.yaml",
        content=yml_bytes,
        caption=f"Healthy clash proxies: {len(res.healthy_clash_proxies)}",
    )

    await send_message(
        settings.telegram_bot_token,
        settings.admin_chat_id,
        f"تمام شد. links={len(res.healthy_links)} proxies={len(res.healthy_clash_proxies)}",
    )


if __name__ == "__main__":
    asyncio.run(main())
