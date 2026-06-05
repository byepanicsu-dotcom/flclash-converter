from flask import Flask, Response, request
import requests
import yaml
import base64
import urllib.parse

app = Flask(__name__)

def parse_vless(link):
    try:
        parsed = urllib.parse.urlparse(link)
        params = urllib.parse.parse_qs(parsed.query)

        proxy = {
            "name": urllib.parse.unquote(parsed.fragment or parsed.hostname),
            "type": "vless",
            "server": parsed.hostname,
            "port": parsed.port,
            "uuid": parsed.username,
            "udp": True
        }

        network = params.get("type", ["tcp"])[0]
        proxy["network"] = network

        security = params.get("security", ["none"])[0]

        if security in ["tls", "reality"]:
            proxy["tls"] = True

        sni = params.get("sni", [""])[0]
        if sni:
            proxy["servername"] = sni

        fp = params.get("fp", [""])[0]
        if fp:
            proxy["client-fingerprint"] = fp

        if security == "reality":
            proxy["reality-opts"] = {
                "public-key": params.get("pbk", [""])[0],
                "short-id": params.get("sid", [""])[0]
            }

        return proxy

    except:
        return None

@app.route("/config.yaml")
def get_config():

    sub_url = request.args.get("url")

    if not sub_url:
        return Response("Missing URL", status=400)

    try:
        res = requests.get(
            sub_url,
            timeout=20,
            headers={"User-Agent": "ClashMeta"}
        )

        content = res.text

        try:
            content = base64.b64decode(content).decode()
        except:
            pass

        proxies = []

        for line in content.splitlines():

            line = line.strip()

            if line.startswith("vless://"):

                proxy = parse_vless(line)

                if proxy:
                    proxies.append(proxy)

        config = {
            "allow-lan": True,
            "mode": "rule",

            "dns": {
                "enable": True,
                "ipv6": False,
                "enhanced-mode": "fake-ip",
                "nameserver": [
                    "https://1.1.1.1/dns-query",
                    "https://8.8.8.8/dns-query"
                ]
            },

            "proxies": proxies,

            "proxy-groups": [
                {
                    "name": "PROXY",
                    "type": "select",
                    "proxies": [p["name"] for p in proxies]
                }
            ],

            "rules": [
                "GEOIP,RU,DIRECT",
                "MATCH,PROXY"
            ]
        }

        return Response(
            yaml.dump(
                config,
                allow_unicode=True,
                sort_keys=False
            ),
            mimetype="text/yaml"
        )

    except Exception as e:
        return Response(str(e), status=500)

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000
    )
