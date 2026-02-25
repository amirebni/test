import base64
import socket
import ssl
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 3
MAX_WORKERS = 80

# 🔻 اینجا لینک ساب رو بذار
SUB_URL = "PUT_YOUR_SUB_LINK_HERE"


def download_sub():
    with urllib.request.urlopen(SUB_URL, timeout=10) as response:
        data = response.read()
    return base64.b64decode(data).decode("utf-8", errors="ignore")


def parse_line(line):
    try:
        if line.startswith("vmess://"):
            raw = base64.b64decode(line[8:]).decode()
            import json
            j = json.loads(raw)
            return j["add"], int(j["port"]), j.get("tls") == "tls", j.get("sni") or j["add"]

        if line.startswith("vless://") or line.startswith("trojan://"):
            from urllib.parse import urlparse, parse_qs
            u = urlparse(line)
            qs = parse_qs(u.query)
            tls = qs.get("security", [""])[0] in ["tls", "reality"]
            sni = qs.get("sni", [u.hostname])[0]
            return u.hostname, u.port, tls, sni

    except:
        return None

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
    decoded = download_sub()
    lines = [l.strip() for l in decoded.splitlines() if l.strip()]

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

    alive_lines = [
        parsed[k][1] for k in alive_keys
    ]

    final_sub = base64.b64encode("\n".join(alive_lines).encode()).decode()

    with open("alive_sub.txt", "w") as f:
        f.write(final_sub)

    print("Total:", len(lines))
    print("Alive:", len(alive_lines))


if __name__ == "__main__":
    main()
