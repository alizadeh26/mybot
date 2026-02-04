from __future__ import annotations

import asyncio
import json
import os
import secrets
import shutil
import tempfile
import urllib.parse
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

    async def __aenter__(self) -> "SingBoxRunner":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.stop()

    async def start(self, outbounds: list[dict]) -> ClashApiConfig:
        if self._proc is not None:
            raise RuntimeError("sing-box already started")

        secret = secrets.token_urlsafe(24)
        self._secret = secret

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
            "outbounds": [
                {"type": "direct", "tag": "DIRECT"},
                *outbounds,
            ],
            "route": {"final": "DIRECT"},
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

    async def _wait_ready(self, secret: str) -> None:
        headers = {"Authorization": f"Bearer {secret}"}
        async with httpx.AsyncClient(timeout=2) as client:
            for _ in range(40):
                if self._proc is None:
                    raise RuntimeError("sing-box exited early")
                if self._proc.returncode is not None:
                    stderr = b""
                    try:
                        if self._proc.stderr:
                            stderr = await self._proc.stderr.read()
                    except Exception:
                        pass
                    raise RuntimeError(
                        f"sing-box exited with code {self._proc.returncode}: {stderr[:2000].decode(errors='ignore')}"
                    )
                try:
                    r = await client.get(
                        f"http://{self._host}:{self._port}/proxies",
                        headers=headers,
                    )
                    if r.status_code == 200:
                        return
                except Exception:
                    pass
                await asyncio.sleep(0.25)
        raise RuntimeError("sing-box clash api did not become ready")

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
