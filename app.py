from flask import Flask, Response, request, render_template_string
import requests
import yaml
import base64
import urllib.parse

app = Flask(name)

HTML = """

<!DOCTYPE html><html>
<head>
<title>FlClash Converter</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{
    font-family:sans-serif;
    background:#0f172a;
    color:white;
    display:flex;
    justify-content:center;
    align-items:center;
    min-height:100vh;
}
.box{
    background:#1e293b;
    padding:25px;
    border-radius:16px;
    width:90%;
    max-width:500px;
}
input{
    width:100%;
    padding:12px;
    border:none;
    border-radius:8px;
    margin-bottom:10px;
}
button{
    width:100%;
    padding:12px;
    border:none;
    border-radius:8px;
    background:#3b82f6;
    color:white;
}
</style>
</head>
<body>
<div class="box">
<h2>FlClash Converter</h2>
<form action="/config.yaml">
<input
name="url"
placeholder="Subscription URL"
required
>
<button type="submit">
Generate
</button>
</form>
</div>
</body>
</html>
"""@app.route("/")
def home():
return render_template_string(HTML)

def decode_subscription(content):
try:
return base64.b64decode(content).decode("utf-8")
except:
return content

def parse_vless(link):
try:

    parsed = urllib.parse.urlparse(link)
    params = urllib.parse.parse_qs(parsed.query)

    proxy = {
        "name": urllib.parse.unquote(
            parsed.fragment or parsed.hostname
        ),
        "type": "vless",
        "server": parsed.hostname,
        "port": parsed.port,
        "uuid": parsed.username,
        "udp": True
    }

    network = params.get(
        "type",
        ["tcp"]
    )[0]

    proxy["network"] = network

    flow = params.get(
        "flow",
        [""]
    )[0]

    if flow:
        proxy["flow"] = flow

    security = params.get(
        "security",
        ["none"]
    )[0]

    if security in ["tls", "reality"]:
        proxy["tls"] = True

    sni = params.get(
        "sni",
        [""]
    )[0]

    if sni:
        proxy["servername"] = sni

    fp = params.get(
        "fp",
        [""]
    )[0]

    if fp:
        proxy["client-fingerprint"] = fp

    if security == "reality":

        proxy["reality-opts"] = {
            "public-key":
                params.get("pbk", [""])[0],
            "short-id":
                params.get("sid", [""])[0]
        }

    if network == "ws":

        proxy["ws-opts"] = {
            "path":
                urllib.parse.unquote(
                    params.get("path", ["/"])[0]
                ),
            "headers": {
                "Host":
                    params.get("host", [""])[0]
            }
        }

    if network == "grpc":

        proxy["grpc-opts"] = {
            "grpc-service-name":
                params.get(
                    "serviceName",
                    [""]
                )[0]
        }

    return proxy

except Exception:
    return None

@app.route("/config.yaml")
def get_config():

sub_url = request.args.get("url")

if not sub_url:
    return Response(
        "Missing URL",
        status=400
    )

try:

    response = requests.get(
        sub_url,
        timeout=20,
        headers={
            "User-Agent":
                "ClashMeta"
        }
    )

    response.raise_for_status()

    content = decode_subscription(
        response.text
    )

    if (
        "proxies:" in content
        and "proxy-groups:" in content
    ):
        return Response(
            content,
            mimetype="text/yaml"
        )

    proxies = []

    for line in content.splitlines():

        line = line.strip()

        if line.startswith(
            "vless://"
        ):

            proxy = parse_vless(
                line
            )

            if proxy:
                proxies.append(
                    proxy
                )

    unique = {}

    for proxy in proxies:

        key = (
            proxy.get("server"),
            proxy.get("port"),
            proxy.get("uuid")
        )

        unique[key] = proxy

    proxies = list(
        unique.values()
    )

    if not proxies:
        return Response(
            "No valid VLESS nodes found",
            status=400
        )

    names = [
        p["name"]
        for p in proxies
    ]

    config = {

        "allow-lan": True,

        "mode": "rule",

        "dns": {
            "enable": True,
            "ipv6": False,
            "enhanced-mode":
                "fake-ip",
            "nameserver": [
                "https://1.1.1.1/dns-query",
                "https://8.8.8.8/dns-query"
            ]
        },

        "proxies": proxies,

        "proxy-groups": [

            {
                "name": "AUTO",
                "type": "url-test",
                "url":
                    "http://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": names
            },

            {
                "name": "PROXY",
                "type": "select",
                "proxies":
                    ["AUTO"] + names
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

    return Response(
        str(e),
        status=500
    )

if name == "main":
app.run(
host="0.0.0.0",
port=5000
    )
