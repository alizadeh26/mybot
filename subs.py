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
    # Supports ss://BASE64(method:password)@host:port#name OR ss://method:password@host:port#name
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
        # ss://BASE64(method:password@host:port)
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
    return host, int(port_s), method, password


def node_from_share_link(link: str) -> Node:
    if link.startswith("vmess://"):
        v = _decode_vmess(link)
        tag = _safe_tag(v.get("ps") or "vmess")
        server = v.get("add")
        port = int(v.get("port"))
        uuid = v.get("id")
        security = (v.get("scy") or "auto").lower()
        tls_enabled = str(v.get("tls") or "").lower() in ("tls", "1", "true")
        transport = (v.get("net") or "tcp").lower()

        outbound: dict = {
            "type": "vmess",
            "tag": tag,
            "server": server,
            "server_port": port,
            "uuid": uuid,
            "security": security,
        }

        if tls_enabled:
            outbound["tls"] = {
                "enabled": True,
                "server_name": v.get("sni") or v.get("host") or server,
            }

        if transport == "ws":
            outbound["transport"] = {
                "type": "ws",
                "path": v.get("path") or "/",
                "headers": {"Host": v.get("host")} if v.get("host") else {},
            }

        return Node(tag=tag, outbound=outbound, export_link=link, export_clash_proxy=None)

    if link.startswith("vless://"):
        u = urllib.parse.urlsplit(link)
        uuid = u.username
        server = u.hostname
        port = u.port
        params = urllib.parse.parse_qs(u.query)
        name = urllib.parse.unquote(u.fragment) if u.fragment else "vless"
        tag = _safe_tag(name)

        tls_enabled = (params.get("security", [""])[0] or "").lower() in ("tls", "reality")
        sni = params.get("sni", [""])[0] or params.get("host", [""])[0]
        fp = params.get("fp", [""])[0]
        pbk = params.get("pbk", [""])[0]
        sid = params.get("sid", [""])[0]
        flow = params.get("flow", [""])[0]
        transport = (params.get("type", ["tcp"])[0] or "tcp").lower()

        outbound: dict = {
            "type": "vless",
            "tag": tag,
            "server": server,
            "server_port": int(port) if port else 443,
            "uuid": uuid,
        }
        if flow:
            outbound["flow"] = flow

        if tls_enabled:
            tls: dict = {"enabled": True}
            if sni:
                tls["server_name"] = sni
            if params.get("security", [""])[0].lower() == "reality":
                tls["reality"] = {"enabled": True}
                if pbk:
                    tls["reality"]["public_key"] = pbk
                if sid:
                    tls["reality"]["short_id"] = sid
                tls["utls"] = {"enabled": True, "fingerprint": fp or "chrome"}
            outbound["tls"] = tls

        if transport == "ws":
            path = params.get("path", ["/"])[0] or "/"
            host = params.get("host", [""])[0]
            outbound["transport"] = {
                "type": "ws",
                "path": path,
                "headers": {"Host": host} if host else {},
            }
        elif transport == "grpc":
            service_name = params.get("serviceName", [""])[0]
            outbound["transport"] = {"type": "grpc"}
            if service_name:
                outbound["transport"]["service_name"] = service_name

        return Node(tag=tag, outbound=outbound, export_link=link, export_clash_proxy=None)

    if link.startswith("trojan://"):
        u = urllib.parse.urlsplit(link)
        password = u.username
        server = u.hostname
        port = u.port
        params = urllib.parse.parse_qs(u.query)
        name = urllib.parse.unquote(u.fragment) if u.fragment else "trojan"
        tag = _safe_tag(name)

        sni = params.get("sni", [""])[0] or params.get("peer", [""])[0]
        transport = (params.get("type", ["tcp"])[0] or "tcp").lower()

        outbound: dict = {
            "type": "trojan",
            "tag": tag,
            "server": server,
            "server_port": int(port) if port else 443,
            "password": password,
            "tls": {"enabled": True, "server_name": sni or server},
        }

        if transport == "ws":
            path = params.get("path", ["/"])[0] or "/"
            host = params.get("host", [""])[0]
            outbound["transport"] = {
                "type": "ws",
                "path": path,
                "headers": {"Host": host} if host else {},
            }

        return Node(tag=tag, outbound=outbound, export_link=link, export_clash_proxy=None)

    if link.startswith("ss://"):
        u = urllib.parse.urlsplit(link)
        name = urllib.parse.unquote(u.fragment) if u.fragment else "ss"
        tag = _safe_tag(name)
        host, port, method, password = _parse_ss(link)
        outbound: dict = {
            "type": "shadowsocks",
            "tag": tag,
            "server": host,
            "server_port": int(port),
            "method": method,
            "password": password,
        }
        return Node(tag=tag, outbound=outbound, export_link=link, export_clash_proxy=None)

    raise ValueError("Unsupported link")


def node_from_clash_proxy(proxy: dict) -> Node | None:
    ptype = (proxy.get("type") or "").lower()
    name = proxy.get("name") or ptype
    tag = _safe_tag(str(name))

    # Convert common Clash proxy schema to sing-box outbounds
    if ptype in ("vmess", "vless", "trojan"):
        server = proxy.get("server")
        port = int(proxy.get("port"))

        outbound: dict = {
            "type": ptype,
            "tag": tag,
            "server": server,
            "server_port": port,
        }

        if ptype == "vmess":
            outbound["uuid"] = proxy.get("uuid") or proxy.get("id")
            outbound["security"] = (proxy.get("cipher") or proxy.get("security") or "auto").lower()
        elif ptype == "vless":
            outbound["uuid"] = proxy.get("uuid")
            if proxy.get("flow"):
                outbound["flow"] = proxy.get("flow")
        elif ptype == "trojan":
            outbound["password"] = proxy.get("password")

        tls_enabled = bool(proxy.get("tls")) or str(proxy.get("tls") or "").lower() == "true"
        if tls_enabled:
            tls: dict = {"enabled": True}
            if proxy.get("sni"):
                tls["server_name"] = proxy.get("sni")
            outbound["tls"] = tls

        if ptype == "vless":
            reality_opts = proxy.get("reality-opts")
            if isinstance(reality_opts, dict):
                tls = outbound.get("tls") or {"enabled": True}
                tls["reality"] = {"enabled": True}
                if reality_opts.get("public-key"):
                    tls["reality"]["public_key"] = reality_opts.get("public-key")
                if reality_opts.get("short-id"):
                    tls["reality"]["short_id"] = reality_opts.get("short-id")
                fp = proxy.get("client-fingerprint") or "chrome"
                tls["utls"] = {"enabled": True, "fingerprint": fp}
                outbound["tls"] = tls

        tls = outbound.get("tls")
        if isinstance(tls, dict) and isinstance(tls.get("reality"), dict) and tls.get("reality", {}).get("enabled"):
            if not isinstance(tls.get("utls"), dict):
                tls["utls"] = {"enabled": True, "fingerprint": "chrome"}

        network = (proxy.get("network") or "tcp").lower()
        if network == "ws":
            ws_opts = proxy.get("ws-opts") or {}
            path = "/"
            headers = {}
            if isinstance(ws_opts, dict):
                path = ws_opts.get("path") or "/"
                h = ws_opts.get("headers") or {}
                if isinstance(h, dict) and h.get("Host"):
                    headers["Host"] = h.get("Host")
            outbound["transport"] = {"type": "ws", "path": path, "headers": headers}
        elif network == "grpc":
            grpc_opts = proxy.get("grpc-opts") or {}
            outbound["transport"] = {"type": "grpc"}
            if isinstance(grpc_opts, dict) and grpc_opts.get("grpc-service-name"):
                outbound["transport"]["service_name"] = grpc_opts.get("grpc-service-name")

        return Node(tag=tag, outbound=outbound, export_link=None, export_clash_proxy=proxy)

    if ptype in ("ss", "shadowsocks"):
        server = proxy.get("server")
        port = int(proxy.get("port"))
        outbound = {
            "type": "shadowsocks",
            "tag": tag,
            "server": server,
            "server_port": port,
            "method": proxy.get("cipher") or proxy.get("method"),
            "password": proxy.get("password"),
        }
        return Node(tag=tag, outbound=outbound, export_link=None, export_clash_proxy=proxy)

    return None
