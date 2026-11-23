#!/usr/bin/env python3
"""
Nodaroo python-generic launcher for sing-box
- Downloads sing-box (once), generates and PERSISTS credentials on first run
- Serves VLESS+Reality (TCP) and Hysteria2 (UDP) on the SAME allocated port
- Prints vless:// and hysteria2:// share links to the console on every start

Just upload this file as app.py (that is the file the Nodaroo python
runtime tries to start) and press Start.
"""
import json
import os
import platform
import secrets
import subprocess
import sys
import tarfile
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE)

SINGBOX_VERSION = "1.14.2"
PORT = int(os.environ.get("SERVER_PORT") or os.environ.get("PORT") or "2522")
HOST_FOR_LINKS = os.environ.get("NODE_HOST", "au2.nodaroo.fun")
SNI = "www.microsoft.com"

BIN = os.path.join(BASE, "sing-box")
STATE_FILE = os.path.join(BASE, "node_state.json")
CONFIG_FILE = os.path.join(BASE, "config.json")
CERT_FILE = os.path.join(BASE, "cert.pem")
KEY_FILE = os.path.join(BASE, "key.pem")


def run(cmd, **kw):
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kw)


def ensure_singbox():
    if os.path.isfile(BIN) and os.access(BIN, os.X_OK):
        return
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("aarch64", "arm64") else "amd64"
    name = f"sing-box-{SINGBOX_VERSION}-linux-{arch}"
    url = (f"https://github.com/SagerNet/sing-box/releases/download/"
           f"v{SINGBOX_VERSION}/{name}.tar.gz")
    tar_path = os.path.join(BASE, f"{name}.tar.gz")
    print(f"Downloading sing-box {SINGBOX_VERSION} ({arch}) ...", flush=True)
    urllib.request.urlretrieve(url, tar_path)
    with tarfile.open(tar_path, "r:gz") as tf:
        tf.extractall(BASE)
    os.replace(os.path.join(BASE, name, "sing-box"), BIN)
    os.chmod(BIN, 0o755)
    os.remove(tar_path)
    print("sing-box ready:", run([BIN, "version"]).stdout.strip(), flush=True)


def gen_reality_keypair():
    out = run([BIN, "generate", "reality-keypair"]).stdout
    priv = pub = None
    for line in out.splitlines():
        if "PrivateKey" in line:
            priv = line.split()[-1]
        if "PublicKey" in line:
            pub = line.split()[-1]
    if not priv or not pub:
        raise RuntimeError("Could not parse reality-keypair output:\n" + out)
    return priv, pub


def ensure_state():
    if os.path.isfile(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    priv, pub = gen_reality_keypair()
    state = {
        "uuid": run([BIN, "generate", "uuid"]).stdout.strip(),
        "reality_private": priv,
        "reality_public": pub,
        "short_id": secrets.token_hex(4),
        "hy2_password": secrets.token_urlsafe(18),
    }
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)
    print("Generated new credentials and saved them to node_state.json", flush=True)
    return state


def ensure_cert():
    if os.path.isfile(CERT_FILE) and os.path.isfile(KEY_FILE):
        return
    # Preferred: openssl self-signed cert (present in the python yolk images)
    try:
        run(["openssl", "req", "-x509", "-newkey", "ec",
             "-pkeyopt", "ec_paramgen_curve:P-256",
             "-days", "3650", "-nodes",
             "-keyout", KEY_FILE, "-out", CERT_FILE,
             "-subj", f"/CN={SNI}",
             "-addext", f"subjectAltName=DNS:{SNI}"])
        print("Self-signed certificate created with openssl", flush=True)
        return
    except Exception as e:
        print("openssl failed, trying sing-box tls-keypair:", e, flush=True)
    out = run([BIN, "generate", "tls-keypair", SNI]).stdout
    blocks, current = [], []
    for line in out.splitlines():
        current.append(line)
        if "-----END" in line:
            blocks.append("\n".join(current) + "\n")
            current = []
    cert = next((b for b in blocks if "CERTIFICATE" in b), None)
    key = next((b for b in blocks if "PRIVATE KEY" in b), None)
    if not cert or not key:
        raise RuntimeError("Could not parse tls-keypair output:\n" + out)
    with open(CERT_FILE, "w") as f:
        f.write(cert)
    with open(KEY_FILE, "w") as f:
        f.write(key)
    print("Certificate created with sing-box generate tls-keypair", flush=True)


def write_config(state):
    config = {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [
            {
                "type": "vless",
                "tag": "vless-in",
                "listen": "::",
                "listen_port": PORT,
                "users": [{"uuid": state["uuid"], "flow": "xtls-rprx-vision"}],
                "tls": {
                    "enabled": True,
                    "server_name": SNI,
                    "reality": {
                        "enabled": True,
                        "handshake": {"server": SNI, "server_port": 443},
                        "private_key": state["reality_private"],
                        "short_id": [state["short_id"]],
                    },
                },
            },
            {
                "type": "hysteria2",
                "tag": "hy2-in",
                "listen": "::",
                "listen_port": PORT,
                "users": [{"password": state["hy2_password"]}],
                "tls": {
                    "enabled": True,
                    "alpn": ["h3"],
                    "certificate_path": CERT_FILE,
                    "key_path": KEY_FILE,
                },
            },
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def print_links(state):
    vless = (
        f"vless://{state['uuid']}@{HOST_FOR_LINKS}:{PORT}"
        f"?encryption=none&security=reality&sni={SNI}&fp=chrome"
        f"&pbk={state['reality_public']}&sid={state['short_id']}"
        f"&type=tcp&flow=xtls-rprx-vision#Nodaroo-AU-VLESS"
    )
    hy2 = (
        f"hysteria2://{state['hy2_password']}@{HOST_FOR_LINKS}:{PORT}"
        f"?insecure=1&sni={SNI}#Nodaroo-AU-HY2"
    )
    print("\n================ NODE LINKS (copy into Shadowrocket / Clash) ================", flush=True)
    print(vless, flush=True)
    print(hy2, flush=True)
    print("=============================================================================\n", flush=True)


def main():
    ensure_singbox()
    state = ensure_state()
    ensure_cert()
    write_config(state)
    run([BIN, "check", "-c", CONFIG_FILE])
    print_links(state)
    print(f"Starting sing-box on port {PORT} (VLESS/TCP + Hysteria2/UDP) ...", flush=True)
    os.execv(BIN, [BIN, "run", "-c", CONFIG_FILE])


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        print("Command failed:", e, flush=True)
        if e.stdout:
            print(e.stdout, flush=True)
        if e.stderr:
            print(e.stderr, flush=True)
        sys.exit(1)
