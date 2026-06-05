from flask import Flask, Response, render_template_string, request
import requests, base64, urllib.parse, yaml

app = Flask(__name__)

# Тот самый крутой дизайн в синих тонах
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nexus Converter</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;600&display=swap" rel="stylesheet">
    <style>
        :root { --blue: #3b82f6; --dark: #0f172a; --card: rgba(30, 41, 59, 0.7); }
        body { font-family: 'Inter', sans-serif; background: var(--dark); color: white; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .container { background: var(--card); backdrop-filter: blur(20px); padding: 40px; border-radius: 30px; border: 1px solid rgba(255,255,255,0.1); width: 90%; max-width: 400px; text-align: center; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); }
        h2 { font-weight: 600; margin-bottom: 20px; background: linear-gradient(90deg, #60a5fa, #3b82f6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        input { width: 100%; padding: 15px; border-radius: 12px; border: 1px solid #334155; background: #1e293b; color: white; box-sizing: border-box; margin-bottom: 15px; }
        button { width: 100%; padding: 15px; border-radius: 12px; border: none; background: var(--blue); color: white; font-weight: 600; cursor: pointer; transition: 0.3s; }
        button:hover { box-shadow: 0 0 20px rgba(59, 130, 246, 0.5); }
        #resultBox { display: none; margin-top: 20px; text-align: left; }
        .code-box { background: #000; padding: 10px; border-radius: 8px; font-family: monospace; font-size: 12px; word-break: break-all; margin-top: 10px; color: #60a5fa; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Nexus Converter</h2>
        <input type="text" id="subUrl" placeholder="Вставьте ссылку подписки...">
        <button onclick="generate()">ГЕНЕРИРОВАТЬ</button>
        <div id="resultBox">
            <div style="font-size: 12px; color: #94a3b8;">Ваша ссылка для FlClash:</div>
            <div class="code-box" id="finalUrl"></div>
        </div>
    </div>
    <script>
        function generate() {
            let input = document.getElementById('subUrl').value.trim();
            let final = window.location.origin + "/config.yaml?url=" + encodeURIComponent(input);
            document.getElementById('finalUrl').innerText = final;
            document.getElementById('resultBox').style.display = 'block';
        }
    </script>
</body>
</html>
"""

def generate_clash_config(proxies):
    ru_proxies = [p["name"] for p in proxies if any(w in p["name"].lower() for w in ["russia", "ru", "россия", "рф"])]
    return {
        "allow-lan": True, "mode": "rule",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["AUTO"] + [p["name"] for p in proxies]},
            {"name": "AUTO", "type": "url-test", "proxies": [p["name"] for p in proxies], "url": "http://www.gstatic.com/generate_204", "interval": 150},
            {"name": "RUSSIA", "type": "select", "proxies": ["DIRECT"] + (ru_proxies if ru_proxies else [])}
        ],
        "rules": [
            "DOMAIN-SUFFIX,ru,RUSSIA", "DOMAIN-SUFFIX,su,RUSSIA", "DOMAIN-SUFFIX,рф,RUSSIA",
            "DOMAIN-KEYWORD,gosuslugi,RUSSIA", "DOMAIN-KEYWORD,sberbank,RUSSIA", "DOMAIN-KEYWORD,tinkoff,RUSSIA",
            "GEOIP,RU,RUSSIA",
            "MATCH,PROXY"
        ]
    }

@app.route("/")
def index(): return render_template_string(HTML_TEMPLATE)

@app.route("/config.yaml")
def get_config():
    sub_url = request.args.get("url")
    req = requests.get(sub_url, headers={"User-Agent": "ClashMeta"}, timeout=10)
    # Парсинг VLESS-ссылок упрощен для стабильности
    lines = req.text.replace("vless://", "").splitlines()
    proxies = []
    for l in lines:
        if "@" in l:
            try:
                parts = l.split("#")
                name = urllib.parse.unquote(parts[1]) if len(parts) > 1 else "Server"
                info = parts[0].split("@")
                server_info = info[1].split(":")
                proxies.append({"name": name, "type": "vless", "server": server_info[0], "port": int(server_info[1]), "uuid": info[0], "tls": True, "network": "tcp", "reality-opts": {"public-key": ""}})
            except: continue
    return Response(yaml.dump(generate_clash_config(proxies), allow_unicode=True), mimetype="text/yaml")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port
            =5000)
