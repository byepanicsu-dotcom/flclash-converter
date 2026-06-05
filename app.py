from flask import Flask, Response, render_template_string, request
import requests, base64, urllib.parse, yaml

app = Flask(__name__)

# Красивый интерфейс сайта
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FlClash Конвертер</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root { --bg: #0b0f19; --card-bg: rgba(22, 28, 45, 0.6); --accent: #10b981; --accent-glow: rgba(16, 185, 129, 0.2); --text: #f3f4f6; --text-muted: #9ca3af; --border: rgba(255, 255, 255, 0.05); }
        body { font-family: 'Plus Jakarta Sans', sans-serif; background: linear-gradient(135deg, #0b0f19 0%, #111827 100%); color: var(--text); margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .sphere { position: absolute; width: 300px; height: 300px; background: radial-gradient(circle, var(--accent-glow) 0%, transparent 70%); top: 20%; left: 10%; z-index: 0; pointer-events: none; }
        .sphere-2 { top: 60%; left: 60%; background: radial-gradient(circle, rgba(99, 102, 241, 0.15) 0%, transparent 70%); }
        .container { background: var(--card-bg); backdrop-filter: blur(16px); border: 1px solid var(--border); padding: 40px 30px; border-radius: 24px; width: 90%; max-width: 440px; text-align: center; box-shadow: 0 20px 40px rgba(0,0,0,0.3); z-index: 1; }
        .logo-area { font-size: 50px; margin-bottom: 10px; }
        h2 { font-size: 26px; margin: 0 0 10px 0; color: #fff; }
        p { color: var(--text-muted); font-size: 15px; margin: 0 0 25px 0; }
        input[type="text"] { width: 100%; box-sizing: border-box; padding: 14px; border-radius: 12px; border: 1px solid var(--border); background: rgba(0,0,0,0.2); color: #fff; font-size: 15px; outline: none; margin-bottom: 15px; }
        input[type="text"]:focus { border-color: var(--accent); }
        .btn { background: var(--accent); color: #0b0f19; border: none; padding: 14px; width: 100%; border-radius: 12px; font-size: 16px; font-weight: bold; cursor: pointer; transition: 0.2s; }
        .btn:hover { transform: scale(1.02); box-shadow: 0 0 15px rgba(16,185,129,0.4); }
        .result-box { display: none; background: rgba(0,0,0,0.3); border: 1px solid var(--border); padding: 20px; border-radius: 16px; margin-top: 20px; text-align: left; }
        .result-title { font-size: 13px; color: var(--accent); margin-bottom: 10px; text-transform: uppercase; font-weight: bold; }
        .copy-group { display: flex; gap: 10px; }
        .copy-group input { margin: 0; flex: 1; font-family: monospace; font-size: 13px; }
        .copy-btn { background: #fff; color: #000; border: none; padding: 0 15px; border-radius: 10px; font-weight: bold; cursor: pointer; }
    </style>
</head>
<body>
    <div class="sphere"></div><div class="sphere sphere-2"></div>
    <div class="container">
        <div class="logo-area">⚡</div>
        <h2>Умный Конвертер</h2>
        <p>Вставьте ссылку от провайдера, чтобы получить готовый URL для FlClash</p>
        
        <input type="text" id="subUrl" placeholder="https://ваша-ссылка...">
        <button class="btn" onclick="generate()">Сгенерировать ссылку</button>
        
        <div class="result-box" id="resultBox">
            <div class="result-title">Готово! Добавьте это во FlClash:</div>
            <div class="copy-group">
                <input type="text" id="finalUrl" readonly>
                <button class="copy-btn" onclick="copyIt()">Копировать</button>
            </div>
        </div>
    </div>

    <script>
        function generate() {
            let input = document.getElementById('subUrl').value.trim();
            if(!input) return alert('Пожалуйста, вставьте ссылку!');
            let baseUrl = window.location.origin + "/config.yaml?url=";
            document.getElementById('finalUrl').value = baseUrl + encodeURIComponent(input);
            document.getElementById('resultBox').style.display = 'block';
        }
        function copyIt() {
            let el = document.getElementById('finalUrl');
            el.select();
            document.execCommand('copy');
            let btn = document.querySelector('.copy-btn');
            btn.innerText = 'Скопировано!';
            setTimeout(() => btn.innerText = 'Копировать', 2000);
        }
    </script>
</body>
</html>
"""

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
            # Локальная сеть
            "SRC-IP-CIDR,192.168.0.0/16,DIRECT",
            "SRC-IP-CIDR,10.0.0.0/8,DIRECT",

            # === РОССИЯ И ЛОКАЛЬНЫЕ СЕРВИСЫ (напрямую) ===
            "DOMAIN-SUFFIX,ru,RUSSIA",
            "DOMAIN-SUFFIX,su,RUSSIA",
            "DOMAIN-SUFFIX,рф,RUSSIA",
            "DOMAIN-KEYWORD,gosuslugi,RUSSIA",
            "DOMAIN-KEYWORD,sberbank,RUSSIA",
            "DOMAIN-KEYWORD,tinkoff,RUSSIA",
            "DOMAIN-KEYWORD,yandex,RUSSIA",
            "DOMAIN-SUFFIX,vk.com,RUSSIA",
            "DOMAIN-SUFFIX,mail.ru,RUSSIA",
            "DOMAIN-KEYWORD,playerok,RUSSIA",
            "DOMAIN-KEYWORD,ggsel,RUSSIA",
            "DOMAIN-KEYWORD,boosty,RUSSIA",

            # === ИГРЫ (через VPN) ===
            "DOMAIN-KEYWORD,roblox,PROXY",
            "DOMAIN-KEYWORD,axlebolt,PROXY",
            "DOMAIN-KEYWORD,standoff2,PROXY",
            "DOMAIN-KEYWORD,supercell,PROXY",
            "DOMAIN-KEYWORD,epicgames,PROXY",
            "DOMAIN-KEYWORD,steampowered,PROXY",

            # === СОЦСЕТИ И МЕДИА (через VPN) ===
            "DOMAIN-KEYWORD,youtube,PROXY",
            "DOMAIN-KEYWORD,googlevideo,PROXY",
            "DOMAIN-KEYWORD,instagram,PROXY",
            "DOMAIN-KEYWORD,telegram,PROXY",
            "DOMAIN-KEYWORD,discord,PROXY",
            "DOMAIN-KEYWORD,pinterest,PROXY",
            "DOMAIN-KEYWORD,twitter,PROXY",
            "DOMAIN-KEYWORD,twimg,PROXY",
            "DOMAIN-KEYWORD,facebook,PROXY",
            "DOMAIN-KEYWORD,spotify,PROXY",
            "DOMAIN-KEYWORD,netflix,PROXY",

            # === ИНСТРУМЕНТЫ, РАЗРАБОТКА И ИИ (через VPN) ===
            "DOMAIN-KEYWORD,openai,PROXY",
            "DOMAIN-KEYWORD,chatgpt,PROXY",
            "DOMAIN-KEYWORD,anthropic,PROXY",
            "DOMAIN-KEYWORD,claude,PROXY",
            "DOMAIN-KEYWORD,gemini,PROXY",
            "DOMAIN-KEYWORD,aistudio,PROXY",
            "DOMAIN-KEYWORD,github,PROXY",
            "DOMAIN-KEYWORD,supabase,PROXY",
            "DOMAIN-KEYWORD,oracle,PROXY",
            "DOMAIN-KEYWORD,vercel,PROXY",

            # === ВСЁ ОСТАЛЬНОЕ (по умолчанию напрямую) ===
            "MATCH,DIRECT"
        ]
    }

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/config.yaml")
def get_config():
    sub_url = request.args.get("url")
    if not sub_url: 
        return "Error: Missing 'url' parameter", 400
        
    lines = fetch_sub(sub_url)
    all_proxies = [p for p in (parse_vless(l.strip()) for l in lines if l.strip().startswith("vless://")) if p]
    
    if not all_proxies: 
        return "Error: No valid servers found", 500
        
    config = generate_clash_config(all_proxies)
    return Response(yaml.dump(config, allow_unicode=True, sort_keys=False), mimetype="text/yaml")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
    
