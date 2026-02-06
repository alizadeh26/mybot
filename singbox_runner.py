from __future__ import annotations

import asyncio
import json
import os
import secrets
import shutil
import tempfile
import urllib.parse
import base64
from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class ClashApiConfig:
    host: str
    port: int
    secret: str

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


class SingBoxRunner:
    def __init__(self, singbox_path: str, host: str, port: int) -> None:
        self._singbox_path = singbox_path
        self._host = host
        self._port = port
        self._proc: asyncio.subprocess.Process | None = None
        self._tmpdir: str | None = None
        self._secret: str | None = None
        self._outbounds_snapshot: list[dict] = []

    async def __aenter__(self) -> "SingBoxRunner":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.stop()

    async def start(
        self,
        outbounds: list[dict],
        enable_selector: bool = False,
        selector_tag: str = "PROXY",
    ) -> ClashApiConfig:
        if self._proc is not None:
            raise RuntimeError("sing-box already started")

        def _is_valid_ss2022_key(method: str, password: str) -> bool:
            m = (method or "").strip().lower()
            if "2022" not in m:
                return True
            required_len: int | None = None
            if "aes-128-gcm" in m:
                required_len = 16
            elif "aes-256-gcm" in m or "chacha20" in m:
                required_len = 32
            if required_len is None:
                return False
            s = (password or "").strip()
            if ":" in s:
                s = s.split(":", 1)[0]
            if s:
                allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-=")
                cut = 0
                for ch in s:
                    if ch in allowed:
                        cut += 1
                    else:
                        break
                s = s[:cut]
            if not s:
                return False
            missing = (-len(s)) % 4
            if missing:
                s += "=" * missing
            try:
                raw = base64.b64decode(s.encode(), validate=True)
            except Exception:
                try:
                    raw = base64.urlsafe_b64decode(s.encode())
                except Exception:
                    return False
            return len(raw) == required_len

        filtered_outbounds: list[dict] = []
        for o in outbounds:
            if not isinstance(o, dict) or not o.get("tag"):
                continue
            if str(o.get("type") or "").lower() == "shadowsocks":
                method = str(o.get("method") or "")
                password = str(o.get("password") or "")
                if not _is_valid_ss2022_key(method, password):
                    continue
            filtered_outbounds.append(o)

        self._outbounds_snapshot = filtered_outbounds.copy()

        secret = secrets.token_urlsafe(24)
        self._secret = secret

        outbound_tags = [str(o.get("tag")) for o in filtered_outbounds if isinstance(o, dict) and o.get("tag")]

        config_outbounds: list[dict] = [
            {"type": "direct", "tag": "DIRECT"},
            *filtered_outbounds,
        ]
        final_outbound = "DIRECT"

        if enable_selector and outbound_tags:
            config_outbounds.append(
                {
                    "type": "selector",
                    "tag": selector_tag,
                    "outbounds": outbound_tags,
                    "default": outbound_tags[0],
                }
            )
            final_outbound = selector_tag

        config = {
            "log": {"level": "warn"},
            "inbounds": [
                {
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen": "127.0.0.1",
                    "listen_port": 10809,
                }
            ],
            "outbounds": config_outbounds,
            "route": {"final": final_outbound},
            "experimental": {
                "clash_api": {
                    "external_controller": f"{self._host}:{self._port}",
                    "secret": secret,
                    "access_control_allow_origin": "*",
                }
            },
        }

        tmpdir = tempfile.mkdtemp(prefix="sb-")
        self._tmpdir = tmpdir
        cfg_path = os.path.join(tmpdir, "config.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)

        self._proc = await asyncio.create_subprocess_exec(
            self._singbox_path,
            "run",
            "-c",
            cfg_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )

        await self._wait_ready(secret)
        return ClashApiConfig(host=self._host, port=self._port, secret=secret)

    async def _wait_ready(self, secret: str, max_retries: int = 3) -> None:
        for attempt in range(max_retries + 1):
            if self._proc is None:
                raise RuntimeError("sing-box process not started")
            ret = await self._proc.wait()
            if ret == 0:
                raise RuntimeError("sing-box exited unexpectedly before API ready")
            if ret != 1:
                raise RuntimeError(f"sing-box exited with code {ret}")
            stderr = await self._proc.stderr.read()
            stderr_text = stderr.decode(errors="ignore").strip()
            if "FATAL" in stderr_text:
                if attempt < max_retries and self._outbounds_snapshot:
                    # Simple fallback: drop the first outbound and retry
                    bad = self._outbounds_snapshot.pop(0)
                    tag = str(bad.get("tag") or "?")
                    await self._cleanup()
                    await self._start_with_snapshot(secret)
                    continue
                else:
                    await self._cleanup()
                    raise RuntimeError(f"sing-box FATAL (retries exhausted): {stderr_text}")
            else:
                await self._cleanup()
                raise RuntimeError(f"sing-box exited with code 1: {stderr_text}")
        await self._cleanup()
        raise RuntimeError("sing-box failed to start after retries")

    async def _start_with_snapshot(self, secret: str) -> None:
        outbound_tags = [str(o.get("tag")) for o in self._outbounds_snapshot if isinstance(o, dict) and o.get("tag")]
        config_outbounds: list[dict] = [
            {"type": "direct", "tag": "DIRECT"},
            *self._outbounds_snapshot,
        ]
        final_outbound = "DIRECT"
        if outbound_tags:
            config_outbounds.append(
                {
                    "type": "selector",
                    "tag": "PROXY",
                    "outbounds": outbound_tags,
                    "default": outbound_tags[0],
                }
            )
            final_outbound = "PROXY"
        config = {
            "log": {"level": "warn"},
            "inbounds": [
                {
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen": "127.0.0.1",
                    "listen_port": 10809,
                }
            ],
            "outbounds": config_outbounds,
            "route": {"final": final_outbound},
            "experimental": {
                "clash_api": {
                    "external_controller": f"{self._host}:{self._port}",
                    "secret": secret,
                    "access_control_allow_origin": "*",
                }
            },
        }
        tmpdir = tempfile.mkdtemp(prefix="sb-")
        self._tmpdir = tmpdir
        cfg_path = os.path.join(tmpdir, "config.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config, f)
        self._proc = await asyncio.create_subprocess_exec(
            self._singbox_path, "run", "-c", cfg_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def stop(self) -> None:
        if self._proc is None:
            return
        try:
            self._proc.terminate()
        except Exception:
            pass
        try:
            await asyncio.wait_for(self._proc.wait(), timeout=5)
        except Exception:
            try:
                self._proc.kill()
            except Exception:
                pass
        self._proc = None
        if self._tmpdir:
            try:
                shutil.rmtree(self._tmpdir, ignore_errors=True)
            except Exception:
                pass
            self._tmpdir = None

    @staticmethod
    async def delay_test(
        api: ClashApiConfig,
        proxy_name: str,
        url: str,
        timeout_ms: int,
    ) -> int | None:
        headers = {"Authorization": f"Bearer {api.secret}"}
        params = {"url": url, "timeout": timeout_ms}
        async with httpx.AsyncClient(timeout=(timeout_ms / 1000.0) + 2) as client:
            encoded_name = urllib.parse.quote(proxy_name, safe="")
            r = await client.get(
                f"{api.base_url}/proxies/{encoded_name}/delay",
                headers=headers,
                params=params,
            )
            if r.status_code != 200:
                return None
            data = r.json()
            if not isinstance(data, dict) or "delay" not in data:
                return None
            try:
                return int(data["delay"])
            except Exception:
                return None

    @staticmethod
    async def select_outbound(
        api: ClashApiConfig,
        selector_tag: str,
        selected_tag: str,
    ) -> bool:
        headers = {"Authorization": f"Bearer {api.secret}"}
        encoded_selector = urllib.parse.quote(selector_tag, safe="")
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.put(
                f"{api.base_url}/proxies/{encoded_selector}",
                headers=headers,
                json={"name": selected_tag},
            )
            return r.status_code in (200, 204)
