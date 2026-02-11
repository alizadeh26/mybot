from __future__ import annotations

import base64
import json
import re
import urllib.parse
from dataclasses import dataclass

import httpx
import yaml

@dataclass(frozen=True)
class Node:
    tag: str
    outbound: dict
    export_link: str | None
    export_clash_proxy: dict | None

_PROTOCOL_PREFIXES = ("vmess://", "vless://", "trojan://", "ss://")

def _normalize_ss_method(method: str) -> str:
    m = (method or "").strip().lower()
    if m == "chacha20-poly1305":
        return "chacha20-ietf-poly1305"
    if m == "chacha20":
        return "chacha20-ietf"
    return m

def _normalize_vless_flow(flow: str) -> str | None:
    f = (flow or "").strip().lower()
    if not f:
        return None
    if f == "xtls-rprx-vision":
        return f
    return None

def _is_valid_reality_public_key(pbk: str) -> bool:
    s = (pbk or "").strip()
    if not s:
        return False
    missing = (-len(s)) % 4
    if missing:
        s += "=" * missing
    try:
        raw = base64.urlsafe_b64decode(s.encode())
    except Exception:
        return False
    return len(raw) == 32

def _is_valid_ss2022_key(method: str, password: str) -> bool:
    m = (method or "").strip().lower()
    if not m.startswith("2022-"):
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
        allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-+/=")
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

def _sanitize_ss2022_password(method: str, password: str) -> str:
    m = (method or "").strip().lower()
    if not m.startswith("2022-"):
        return password
    s = (password or "").strip()
    if ":" in s:
        s = s.split(":", 1)[0]
    if s:
        allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-+/=")
        cut = 0
        for ch in s:
            if ch in allowed:
                cut += 1
            else:
                break
        s = s[:cut]
    return s

def _is_probably_yaml(text: str) -> bool:
    t = text.lstrip()
    return t.startswith("proxies:") or ("\nproxies:" in t) or ("proxy-groups:" in t)

def _try_b64_decode(text: str) -> str | None:
    s = text.strip()
    if not s:
        return None
    s = re.sub(r"\s+", "", s)
    missing = (-len(s)) % 4
    if missing:
        s += "=" * missing
    try:
        b = base64.urlsafe_b64decode(s.encode("utf-8"))
        out = b.decode("utf-8", errors="ignore")
        if any(p in out for p in _PROTOCOL_PREFIXES) or _is_probably_yaml(out):
            return out
        return None
    except Exception:
        return None

async def fetch_text(url: str) -> str:
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        r = await client.get(url)
        r.raise_for_status()
        return r.text

def parse_subscription_payload(payload: str) -> tuple[list[str], list[dict]]:
    payload = payload.strip()
    if _is_probably_yaml(payload):
        data = yaml.safe_load(payload)
        proxies = data.get("proxies") or []
        if isinstance(proxies, list):
            return [], [p for p in proxies if isinstance(p, dict)]
    decoded = _try_b64_decode(payload)
    if decoded is not None:
        return parse_subscription_payload(decoded)
    lines = [ln.strip() for ln in payload.splitlines() if ln.strip()]
    links = [ln for ln in lines if ln.startswith(_PROTOCOL_PREFIXES)]
    return links, []

def _safe_tag(s: str) -> str:
    s = s.strip()
    if not s:
        return "proxy"
    s = re.sub(r"\s+", " ", s)
    return s[:64]

def _decode_vmess(link: str) -> dict:
    raw = link[len("vmess://") :].strip()
    missing = (-len(raw)) % 4
    if missing:
        raw += "=" * missing
    data = json.loads(base64.b64decode(raw).decode("utf-8", errors="strict"))
    return data

def _parse_ss(link: str) -> tuple[str, int, str, str]:
    u = urllib.parse.urlsplit(link)
    name = urllib.parse.unquote(u.fragment) if u.fragment else ""
    netloc = u.netloc
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
        if ":" in userinfo:
            method, password = userinfo.split(":", 1)
        else:
            missing = (-len(userinfo)) % 4
            if missing:
                userinfo += "=" * missing
            dec = base64.urlsafe_b64decode(userinfo.encode()).decode()
            method, password = dec.split(":", 1)
    else:
        raw = u.path.lstrip("/")
        missing = (-len(raw)) % 4
        if missing:
            raw += "=" * missing
        dec = base64.urlsafe_b64decode(raw.encode()).decode()
        userinfo, hostport = dec.rsplit("@", 1)
        method, password = userinfo.split(":", 1)
    if ":" not in hostport:
        raise ValueError("Invalid ss link host:port")
    host, port_s = hostport.rsplit(":", 1)
    return host, int(port_s), _normalize_ss_method(method), password

def node_from_share_link(link: str) -> Node | None:
    try:
        if link.startswith("vmess://"):
            v = _decode_vmess(link)
            tag = _safe_tag(v.get("ps") or "vmess")
            outbound: dict = {
                "type": "vmess",
                "tag": tag,
                "server": v.get("add"),
                "server_port": int(v.get("port")),
                "uuid": v.get("id"),
                "security": (v.get("scy") or "auto").lower(),
            }
            tls_enabled = str(v.get("tls") or "").lower() in ("tls", "1", "true")
            if tls_enabled:
                outbound["tls"] = {"enabled": True, "server_name": v.get("sni") or v.get("host") or v.get("add")}
            transport = (v.get("net") or "tcp").lower()
            if transport == "ws":
                outbound["transport"] = {"type": "ws", "path": v.get("path") or "/", "headers": {"Host": v.get("host")} if v.get("host") else {}}
            return Node(tag=tag, outbound=outbound, export_link=link, export_clash_proxy=None)

        if link.startswith("ss://"):
            host, port, method, password = _parse_ss(link)
            password = _sanitize_ss2022_password(method, password)
            if not password or not _is_valid_ss2022_key(method, password):
                print(f"Skipping SS node due to missing/invalid password: {link}")
                return None
            tag = _safe_tag(urllib.parse.unquote(urllib.parse.urlsplit(link).fragment or "ss"))
            outbound = {"type": "shadowsocks", "tag": tag, "server": host, "server_port": port, "method": method, "password": password}
            return Node(tag=tag, outbound=outbound, export_link=link, export_clash_proxy=None)

        # سایر پروتکل‌ها مثل vless و trojan هم می‌توانند مشابه اضافه شوند...
        return None
    except Exception as e:
        print(f"Error parsing link {link}: {e}")
        return None

def node_from_clash_proxy(proxy: dict) -> Node | None:
    ptype = (proxy.get("type") or "").lower()
    tag = _safe_tag(proxy.get("name") or ptype)
    try:
        if ptype in ("ss", "shadowsocks"):
            server = proxy.get("server")
            port = int(proxy.get("port"))
            method = _normalize_ss_method(str(proxy.get("cipher") or proxy.get("method") or ""))
            password = _sanitize_ss2022_password(method, str(proxy.get("password") or ""))
            if not password or not _is_valid_ss2022_key(method, password):
                print(f"Skipping SS proxy due to missing/invalid password: {proxy}")
                return None
            outbound = {"type": "shadowsocks", "tag": tag, "server": server, "server_port": port, "method": method, "password": password}
            return Node(tag=tag, outbound=outbound, export_link=None, export_clash_proxy=proxy)
        # سایر پروتکل‌ها مثل vmess/vless/trojan هم مشابه بالا تبدیل شوند...
        return None
    except Exception as e:
        print(f"Error parsing Clash proxy {proxy}: {e}")
        return None