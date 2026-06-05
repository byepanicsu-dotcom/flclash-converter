import asyncio
import base64
import hashlib
import logging
import re
import urllib.parse
from functools import lru_cache
from typing import Dict, List, Optional

import aiohttp
import yaml
from aiohttp import web
from yarl import URL

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("clash-converter")

# ---------- Data models ----------
PROTO_TYPES = {"vless", "vmess", "trojan", "ss", "ssr", "http", "socks5"}
CLASH_KEYWORDS = {"proxies", "proxy-groups", "rules", "mixed-port", "mode", "dns", "tun"}
CACHE_TTL = 300  # seconds
TIMEOUT = aiohttp.ClientTimeout(total=20, connect=5)

# Simple in-memory cache: url_hash -> (timestamp, yaml_bytes)
_cache: Dict[str, tuple[float, bytes]] = {}

# ---------- Validators ----------
def is_valid_subscription_url(url: str) -> bool:
    try:
        parsed = URL(url)
        return parsed.scheme in ("http", "https") and bool(parsed.host)
    except Exception:
        return False

def is_clash_config(text: str) -> bool:
    """Detect if text is already a valid Clash config (YAML with proxies/proxy-groups)."""
    try:
        data = yaml.safe_load(text)
        return isinstance(data, dict) and any(k in data for k in CLASH_KEYWORDS)
    except yaml.YAMLError:
        return False

# ---------- Base64 decoding ----------
def decode_base64_tolerant(text: str) -> str:
    """Try to decode base64 content, adding padding and fixing chars if needed."""
    text = text.strip()
    for padding in ("", "=", "=="):
        try:
            padded = text + padding
            return base64.b64decode(padded, validate=True).decode("utf-8")
        except Exception:
            continue
    # Fallback: try urlsafe decode
    try:
        return base64.urlsafe_b64decode(text + "===").decode("utf-8")
    except Exception:
        return text  # assume it's plain text

# ---------- VLESS Parser (full spec) ----------
def parse_vless(uri: str) -> Optional[Dict]:
    """Parse VLESS URI according to XTLS/Xray/V2Ray format."""
    try:
        parsed = urllib.parse.urlparse(uri)
        if parsed.scheme != "vless":
            return None
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        proxy = {
            "name": urllib.parse.unquote(parsed.fragment or parsed.hostname or "VLESS"),
            "type": "vless",
            "server": parsed.hostname,
            "port": int(parsed.port) if parsed.port else 443,
            "uuid": parsed.username,
            "udp": True,
        }

        # Network
        net = params.get("type", ["tcp"])[0]
        proxy["network"] = net

        # Flow (only for tcp)
        flow = params.get("flow", [""])[0]
        if flow:
            proxy["flow"] = flow

        # TLS / Reality
        security = params.get("security", ["none"])[0]
        proxy["tls"] = security in ("tls", "reality")
        sni = params.get("sni", [""])[0] or params.get("peer", [""])[0]
        if sni:
            proxy["servername"] = sni
        fp = params.get("fp", [""])[0] or params.get("fingerprint", [""])[0]
        if fp:
            proxy["client-fingerprint"] = fp

        if security == "reality":
            proxy["reality-opts"] = {
                "public-key": params.get("pbk", [""])[0],
                "short-id": params.get("sid", [""])[0],
            }

        # Transport-specific options
        if net == "ws":
            host = params.get("host", [""])[0]
            path = urllib.parse.unquote(params.get("path", ["/"])[0])
            proxy["ws-opts"] = {
                "path": path,
                "headers": {"Host": host} if host else {},
            }
        elif net == "grpc":
            proxy["grpc-opts"] = {
                "grpc-service-name": params.get("serviceName", [""])[0] or params.get("mode", [""])[0]
            }
        elif net == "h2":
            host = params.get("host", [""])[0]
            path = urllib.parse.unquote(params.get("path", ["/"])[0])
            proxy["h2-opts"] = {
                "host": [host] if host else [],
                "path": path,
            }
        elif net == "tcp":
            # TCP header type (none/http)
            header_type = params.get("headerType", ["none"])[0]
            if header_type == "http":
                proxy["tcp-opts"] = {
                    "header": {
                        "type": "http",
                        "request": {
                            "path": urllib.parse.unquote(params.get("path", ["/"])[0]),
                            "headers": {"Host": params.get("host", [""])[0]},
                        }
                    }
                }
        elif net == "kcp":
            proxy["kcp-opts"] = {
                "seed": params.get("seed", [""])[0],
                "header-type": params.get("headerType", ["none"])[0],
            }

        return proxy
    except Exception as e:
        logger.debug(f"VLESS parse error: {e} | URI: {uri[:80]}")
        return None

# ---------- VMess Parser ----------
def parse_vmess_link(uri: str) -> Optional[Dict]:
    """Parse vmess:// link (base64 JSON)."""
    try:
        parsed = urllib.parse.urlparse(uri)
        if parsed.scheme != "vmess":
            return None
        b64 = parsed.netloc + (f"?{parsed.query}" if parsed.query else "")
        b64 = b64.strip()
        # Handle possible padding
        for pad in ("", "=", "=="):
            try:
                json_str = base64.b64decode(b64 + pad).decode("utf-8")
                break
            except Exception:
                continue
        else:
            json_str = base64.urlsafe_b64decode(b64 + "===").decode("utf-8")
        vmess = yaml.safe_load(json_str) if json_str.strip().startswith("{") else None
        if not vmess:
            return None
        proxy = {
            "name": vmess.get("ps", vmess.get("add", "VMess")),
            "type": "vmess",
            "server": vmess["add"],
            "port": int(vmess.get("port", 443)),
            "uuid": vmess["id"],
            "alterId": int(vmess.get("aid", 0)),
            "cipher": vmess.get("scy", "auto"),
            "udp": True,
        }
        net = vmess.get("net", "tcp")
        proxy["network"] = net
        tls = vmess.get("tls", "")
        proxy["tls"] = tls == "tls" or tls == "1"
        if vmess.get("sni"):
            proxy["servername"] = vmess["sni"]
        if vmess.get("fp"):
            proxy["client-fingerprint"] = vmess["fp"]
        # Transport
        if net == "ws":
            proxy["ws-opts"] = {
                "path": vmess.get("path", "/"),
                "headers": {"Host": vmess.get("host", "")},
            }
        elif net == "grpc":
            proxy["grpc-opts"] = {"grpc-service-name": vmess.get("path", "")}
        elif net == "h2":
            proxy["h2-opts"] = {
                "host": [vmess.get("host", "")] if vmess.get("host") else [],
                "path": vmess.get("path", "/"),
            }
        return proxy
    except Exception as e:
        logger.debug(f"VMess parse error: {e}")
        return None

# ---------- Trojan Parser ----------
def parse_trojan_link(uri: str) -> Optional[Dict]:
    try:
        parsed = urllib.parse.urlparse(uri)
        if parsed.scheme != "trojan":
            return None
        params = urllib.parse.parse_qs(parsed.query)
        proxy = {
            "name": urllib.parse.unquote(parsed.fragment or parsed.hostname or "Trojan"),
            "type": "trojan",
            "server": parsed.hostname,
            "port": int(parsed.port) if parsed.port else 443,
            "password": parsed.username,
            "udp": True,
            "sni": params.get("sni", [""])[0] or params.get("peer", [""])[0],
        }
        # Transport
        net = params.get("type", ["tcp"])[0]
        proxy["network"] = net
        if net == "ws":
            proxy["ws-opts"] = {
                "path": params.get("path", ["/"])[0],
                "headers": {"Host": params.get("host", [""])[0]},
            }
        elif net == "grpc":
            proxy["grpc-opts"] = {"grpc-service-name": params.get("serviceName", [""])[0]}
        return proxy
    except Exception as e:
        logger.debug(f"Trojan parse error: {e}")
        return None

# ---------- Shadowsocks Parser ----------
def parse_ss_link(uri: str) -> Optional[Dict]:
    try:
        parsed = urllib.parse.urlparse(uri)
        if parsed.scheme != "ss":
            return None
        # ss://BASE64(method:password)@server:port or ss://BASE64(method:password@server:port)
        user_info = parsed.netloc.split("@")
        if len(user_info) == 1:
            # everything in userinfo
            decoded = base64.b64decode(user_info[0]).decode("utf-8")
            parts = decoded.rsplit("@", 1)
            if len(parts) == 2:
                method_pwd, hostport = parts
            else:
                method_pwd = parts[0]
                hostport = parsed.hostname + (":" + str(parsed.port) if parsed.port else "")
        else:
            method_pwd = base64.b64decode(user_info[0]).decode("utf-8")
            hostport = user_info[1]
        method, password = method_pwd.split(":", 1)
        host, port = (hostport.split(":") + ["443"])[:2]
        params = urllib.parse.parse_qs(parsed.query)
        proxy = {
            "name": urllib.parse.unquote(parsed.fragment or f"SS-{host}"),
            "type": "ss",
            "server": host,
            "port": int(port),
            "cipher": method,
            "password": password,
            "udp": True,
        }
        # Plugin support (simple-obfs)
        if "plugin" in params:
            proxy["plugin"] = params["plugin"][0]
            proxy["plugin-opts"] = params.get("plugin-opts", [""])[0]
        return proxy
    except Exception as e:
        logger.debug(f"SS parse error: {e}")
        return None

# ---------- URI dispatcher ----------
PARSERS = {
    "vless": parse_vless,
    "vmess": parse_vmess_link,
    "trojan": parse_trojan_link,
    "ss": parse_ss_link,
    # add ssr, socks5, http if needed
}

def parse_any_uri(line: str) -> Optional[Dict]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # Detect scheme
    scheme = line.split("://", 1)[0].lower()
    parser = PARSERS.get(scheme)
    if parser:
        return parser(line)
    else:
        logger.debug(f"Unsupported scheme: {scheme}")
        return None

# ---------- Core subscription converter ----------
async def fetch_subscription(session: aiohttp.ClientSession, url: str) -> str:
    headers = {
        "User-Agent": "ClashMeta/1.18.0",
        "Accept": "text/plain, application/octet-stream",
    }
    try:
        async with session.get(url, headers=headers, timeout=TIMEOUT) as resp:
            resp.raise_for_status()
            text = await resp.text(encoding="utf-8", errors="replace")
            return text
    except Exception as e:
        raise Exception(f"Failed to fetch {url}: {e}")

def process_subscription(raw_text: str) -> List[Dict]:
    """Process raw subscription text (may be base64, plain URIs, or Clash YAML)."""
    # If already Clash config, extract proxies
    if is_clash_config(raw_text):
        try:
            data = yaml.safe_load(raw_text)
            return data.get("proxies", [])
        except Exception:
            return []

    # Try decoding base64 if it looks encoded
    if not any(line.strip().startswith(tuple(PARSERS.keys())) for line in raw_text.splitlines()):
        decoded = decode_base64_tolerant(raw_text)
    else:
        decoded = raw_text

    proxies = []
    for line in decoded.splitlines():
        proxy = parse_any_uri(line)
        if proxy:
            proxies.append(proxy)
    return proxies

def deduplicate_proxies(proxies: List[Dict]) -> List[Dict]:
    seen = set()
    unique = []
    for p in proxies:
        # key = (type, server, port, uuid/password)
        key = (p.get("type"), p["server"], p["port"], p.get("uuid") or p.get("password"))
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique

def build_clash_config(proxies: List[Dict]) -> dict:
    names = [p["name"] for p in proxies]
    # Group by type for nicer organization
    type_groups = {}
    for p in proxies:
        typ = p.get("type", "unknown")
        type_groups.setdefault(typ, []).append(p["name"])

    proxy_groups = [
        {
            "name": "🚀 Auto Select",
            "type": "url-test",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "proxies": names,
        }
    ]
    # Add group per protocol
    for proto, members in sorted(type_groups.items()):
        proxy_groups.append({
            "name": f"🔹 {proto.upper()}",
            "type": "select",
            "proxies": ["🚀 Auto Select"] + members,
        })
    # Final select
    all_groups = ["🚀 Auto Select"] + [f"🔹 {p.upper()}" for p in type_groups]
    proxy_groups.append({
        "name": "🌍 Final Proxy",
        "type": "select",
        "proxies": all_groups + names,
    })

    config = {
        "allow-lan": True,
        "mode": "rule",
        "dns": {
            "enable": True,
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "nameserver": [
                "https://1.1.1.1/dns-query",
                "https://8.8.8.8/dns-query",
            ],
            "fallback": ["tls://8.8.4.4"],
        },
        "proxies": proxies,
        "proxy-groups": proxy_groups,
        "rules": [
            "GEOIP,RU,DIRECT",
            "MATCH,🌍 Final Proxy",
        ],
    }
    return config

# ---------- Web Handlers ----------
async def home(request):
    return web.Response(
        text="""
<h2>🚀 Clash VLESS/VMess/Trojan/SS Converter</h2>
<form action="/config.yaml">
    <input type="text" name="url" placeholder="Subscription URL" style="width:500px" required>
    <button type="submit">Generate</button>
</form>
<p>Поддерживаются подписки в форматах: base64, plain URI, Clash YAML.</p>
""",
        content_type="text/html",
    )

async def generate_config(request: web.Request):
    url = request.query.get("url", "").strip()
    if not url:
        return web.Response(status=400, text="Missing 'url' parameter")
    if not is_valid_subscription_url(url):
        return web.Response(status=400, text="Invalid subscription URL")

    cache_key = hashlib.md5(url.encode()).hexdigest()
    now = asyncio.get_event_loop().time()
    if cache_key in _cache:
        ts, data = _cache[cache_key]
        if now - ts < CACHE_TTL:
            return web.Response(body=data, content_type="text/yaml; charset=utf-8")

    try:
        connector = aiohttp.TCPConnector(force_close=True, limit_per_host=10)
        async with aiohttp.ClientSession(connector=connector) as session:
            raw = await fetch_subscription(session, url)
    except Exception as e:
        logger.error(f"Fetch error: {e}")
        return web.Response(status=502, text=f"Upstream error: {e}")

    try:
        proxies = process_subscription(raw)
        if not proxies:
            return web.Response(status=400, text="No valid proxies found in subscription")
        proxies = deduplicate_proxies(proxies)
        config = build_clash_config(proxies)
        yaml_out = yaml.dump(config, allow_unicode=True, sort_keys=False, width=1000)
        # Cache
        _cache[cache_key] = (now, yaml_out.encode("utf-8"))
        return web.Response(body=yaml_out.encode("utf-8"), content_type="text/yaml; charset=utf-8")
    except Exception as e:
        logger.exception("Config build error")
        return web.Response(status=500, text=f"Internal error: {e}")

# ---------- App runner ----------
def create_app():
    app = web.Application()
    app.router.add_get("/", home)
    app.router.add_get("/config.yaml", generate_config)
    return app

if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=5000)
