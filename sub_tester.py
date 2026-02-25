import socket
import ssl
import time
import urllib.request
import base64
import json
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 3
MAX_WORKERS = 80

SUB_URL = "PUT_YOUR_SUB_LINK_HERE"


def download_sub():
    with urllib.request.urlopen(SUB_URL, timeout=15) as response:
        data = response.read().decode("utf-8", errors="ignore")
    return data


def parse_vmess(line):
    try:
        raw = base64.b64decode(line[8:] + "==").decode()
        j = json.loads(raw)
        host = j["add"]
        port = int(j["port"])
        tls = j.get("tls") == "tls"
        sni = j.get("sni") or host
        return host, port, tls, sni
    except:
        return None


def parse_vless_trojan(line):
    try:
        u = urlparse(line)
        qs = parse_qs(u.query)

        host = u.hostname
        port = u.port

        security = qs.get("security", ["none"])[0]
        tls = security in ["tls", "reality"]

        sni = qs.get("sni", [host])[0]

        return host, port, tls, sni
    except:
        return None


def parse_ss(line):
    try:
        if "@“ in line:
            base = line[5:]
        else:
            base = line[5:]

        decoded = base64.b64decode(base + "==").decode()
        method_pass, server = decoded.split("@")
        host, port = server.split(":")
        return host, int(port), False, host
    except:
        return None


def parse_line(line):
    if line.startswith("vmess://"):
        return parse_vmess(line)

    if line.startswith("vless://") or line.startswith("trojan://"):
        return parse_vless_trojan(line)

    if line.startswith("ss://"):
        return parse_ss(line)

    return None


def tcp_check(host, port):
    start = time.time()
    try:
        s = socket.create_connection((host, port), timeout=TIMEOUT)
        latency = time.time() - start

        if latency > 3:
            s.close()
            return False

        time.sleep(1)

        try:
            s.send(b"\x00")
        except:
            s.close()
            return False

        s.close()
        return True

    except:
        return False


def tls_check(host, port, sni):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=sni) as s:
            s.settimeout(TIMEOUT)
            s.connect((host, port))
        return True
    except:
        return False


def test_node(node):
    host, port, tls, sni = node

    for _ in range(2):
        if not tcp_check(host, port):
            continue
        if tls:
            if not tls_check(host, port, sni):
                continue
        return True

    return False


def main():
    raw = download_sub()
    lines = [l.strip() for l in raw.splitlines() if l.strip()]

    parsed = {}
    for line in lines:
        p = parse_line(line)
        if p:
            parsed[f"{p[0]}:{p[1]}"] = (p, line)

    alive_keys = set()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(test_node, parsed[k][0]): k
            for k in parsed
        }

        for future in as_completed(futures):
            if future.result():
                alive_keys.add(futures[future])

    alive_lines = [parsed[k][1] for k in alive_keys]

    with open("alive_sub.txt", "w") as f:
        f.write("\n".join(alive_lines))

    print("Total lines:", len(lines))
    print("Parsed nodes:", len(parsed))
    print("Alive:", len(alive_lines))


if __name__ == "__main__":
    main()
