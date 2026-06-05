from flask import Flask, Response, request
import requests, yaml

app = Flask(__name__)

@app.route("/config.yaml")
def get_config():
    sub_url = request.args.get("url")
    if not sub_url: return "No URL", 400
    try:
        # Получаем данные
        res = requests.get(sub_url, timeout=15)
        # Если это просто список ссылок, превращаем в Clash конфиг
        lines = res.text.splitlines()
        proxies = [{"name": f"Server_{i}", "type": "vless", "server": "1.1.1.1", "port": 443, "uuid": "uuid", "tls": True} for i, l in enumerate(lines) if "vless://" in l]
        
        config = {
            "proxies": proxies,
            "rules": ["GEOIP,RU,DIRECT", "MATCH,PROXY"]
        }
        return Response(yaml.dump(config), mimetype="text/yaml")
    except Exception as e:
        return str(e), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=50
            00)
