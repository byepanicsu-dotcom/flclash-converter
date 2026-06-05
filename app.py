from flask import Flask, Response, request
import requests, base64, urllib.parse, yaml

app = Flask(__name__)

def fetch_sub(url):
    try:
        req = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
        req.raise_for_status()
        raw = req.text.strip()
        try: return base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8").splitlines()
        except: return raw.splitlines()
    except: return []

def parse_vless(link):
    try:
        parsed = urllib.parse.urlparse(link)
        netloc = parsed.netloc.split("@")[-1]
        server, port = netloc.split(":")
        params = urllib.parse.parse_qs(parsed.query)
        name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else server
        proxy = {"name": name, "type": "vless", "server": server, "port": int(port), "uuid": parsed.username, "udp": True, "tls": params.get("security", [""])[0] in ["tls", "reality"], "network": params.get("type", ["tcp"])[0]}
        if params.get("security", [""])[0] == "reality":
            proxy["servername"] = params.get("sni", [""])[0]
            proxy["reality-opts"] = {"public-key": params.get("pbk", [""])[0], "short-id": params.get("sid", [""])[0]}
            if params.get("fp", [""]): proxy["client-fingerprint"] = params.get("fp", [""])[0]
        return proxy
    except: return None

def generate_clash_config(proxies):
    ru_proxies = [p["name"] for p in proxies if any(w in p["name"].lower() for w in ["russia", "ru", "россия", "рф"])]
    foreign = [p["name"] for p in proxies if p["name"] not in ru_proxies] or [p["name"] for p in proxies]
    return {
        "allow-lan": True, "mode": "rule", "log-level": "info",
        "dns": {"enable": True, "enhanced-mode": "fake-ip", "listen": "0.0.0.0:1053", "nameserver": ["https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"]},
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["AUTO"] + [p["name"] for p in proxies]},
            {"name": "AUTO", "type": "url-test", "proxies": foreign, "url": "http://www.gstatic.com/generate_204", "interval": 150},
            {"name": "RUSSIA", "type": "select", "proxies": ["DIRECT"] + (ru_proxies if ru_proxies else [])}
        ],
        "rules": [
            "SRC-IP-CIDR,192.168.0.0/16,DIRECT", "SRC-IP-CIDR,10.0.0.0/8,DIRECT",
            "DOMAIN-SUFFIX,ru,RUSSIA", "DOMAIN-SUFFIX,su,RUSSIA", "DOMAIN-KEYWORD,gosuslugi,RUSSIA",
            "DOMAIN-KEYWORD,sberbank,RUSSIA", "DOMAIN-KEYWORD,tinkoff,RUSSIA",
            "DOMAIN-KEYWORD,youtube,PROXY", "DOMAIN-KEYWORD,instagram,PROXY", "DOMAIN-KEYWORD,telegram,PROXY",
            "DOMAIN-KEYWORD,discord,PROXY", "DOMAIN-KEYWORD,openai,PROXY", "MATCH,DIRECT"
        ]
    }

# Главная страница теперь просто выдает краткую инструкцию текстом
@app.route("/")
def index():
    return "Использование: https://твой-сайт.onrender.com/config.yaml?url=ССЫЛКА_ОТ_ПРОВАЙДЕРА", 200

# Этот роут обрабатывает ссылку для FlClash
@app.route("/config.yaml")
def get_config():
    sub_url = request.args.get("url")
    if not sub_url: 
        return "Error: Missing 'url' parameter в ссылке", 400
        
    lines = fetch_sub(sub_url)
    all_proxies = [p for p in (parse_vless(l.strip()) for l in lines if l.strip().startswith("vless://")) if p]
    
    if not all_proxies: 
        return "Error: No valid servers found", 500
        
    config = generate_clash_config(all_proxies)
    return Response(yaml.dump(config, allow_unicode=True, sort_keys=False), mimetype="text/yaml")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port
            =5000)
