from flask import Flask, Response, render_template_string
import requests, base64, urllib.parse, yaml

app = Flask(__name__)

# --- ВСТАВЬ СВОИ ССЫЛКИ СЮДА ---
SUBSCRIPTION_URLS = [
    "ТВОЯ_ПЕРВАЯ_ССЫЛКА_ЗДЕСЬ",
    "ТВОЯ_ВТОРАЯ_ССЫЛКА_ЗДЕСЬ" 
]

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Умный Конвертер</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #121212; color: #ffffff; padding: 20px; display: flex; justify-content: center; }
        .container { background: #1e1e1e; padding: 25px; border-radius: 12px; width: 100%; max-width: 400px; text-align: center; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }
        h2 { color: #4CAF50; margin-top: 0; }
        .result-box { margin-top: 20px; padding: 15px; background: #252525; border-left: 4px solid #4CAF50; border-radius: 6px; }
        input { width: 100%; box-sizing: border-box; padding: 10px; margin-top: 10px; border-radius: 6px; border: 1px solid #333; background: #2d2d2d; color: #fff; font-size: 14px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h2>FlClash API 🚀</h2>
        <p>Конвертер успешно запущен в облаке!</p>
        <div class="result-box">
            <p>Вставь эту ссылку во FlClash (URL профиль):</p>
            <input type="text" value="{{ host_url }}config.yaml" readonly onclick="this.select();">
        </div>
    </div>
</body>
</html>
"""

def fetch_sub(url):
    if "ТВОЯ_" in url: return []
    try:
        req = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
        req.raise_for_status()
        raw = req.text.strip()
        try:
            return base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8").splitlines()
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

from flask import request
@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE, host_url=request.url_root)

@app.route("/config.yaml")
def get_config():
    all_proxies = []
    for url in SUBSCRIPTION_URLS:
        lines = fetch_sub(url)
        for l in lines:
            if l.startswith("vless://"):
                node = parse_vless(l)
                if node: all_proxies.append(node)
    
    if not all_proxies:
        return "Error: No valid servers found", 500
        
    config = generate_clash_config(all_proxies)
    yaml_data = yaml.dump(config, allow_unicode=True, sort_keys=False)
    return Response(yaml_data, mimetype="text/yaml")

if __name__ == "__main__":
    app.run(host="0.0.0.0", po
            rt=5000)
