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

# 🔻 لینک ساب خام خودت رو اینجا بذار
SUB_URL = "https://raw.githubusercontent.com/punez/Repo-5/refs/heads/main/final.txt"


# دانلود ساب
def download_sub():
    with urllib.request.urlopen(SUB_URL, timeout=15) as response:
        data = response.read().decode("utf-8", errors="ignore")
    return data


# ---------------- Parsers ---------------- #

def parse_vmess(line):
    try:
        raw = line.replace("vmess://", "")
        padded = raw + "=" * (-len(raw) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        j = json.loads(decoded)

        host = j.get("add")
        port = int(j.get("port"))
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
        content = line.replace("ss://", "")

        if "#" in content:
            content = content.split("#")[0]

        # مدل جدید: base64@host:port
        if "@" in content:
            method_pass, server = content.split("@", 1)
            host, port = server.split(":")
            return host, int(port), False, host

        # مدل قدیمی: کلش base64
        padded = content + "=" * (-len(content) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
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


# ---------------- Tests ---------------- #

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

    for _ in range(2):  # یک retry
        if not tcp_check(host, port):
            continue

        if tls:
            if not tls_check(host, port, sni):
                continue

        return True

    return False


# ---------------- Main ---------------- #

def main():
    raw = download_sub()
    lines = [l.strip() for l in raw.splitlines() if l.strip()]

    parsed = {}
    for line in lines:
        p = parse_line(line)
        if p and p[0] and p[1]:
            parsed[f"{p[0]}:{p[1]}"] = (p, line)

    alive_keys = set()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(test_node, parsed[k][0]): k
            for k in parsed
        }

        for future in as_completed(futures):
            key = futures[future]
            try:
                if future.result():
                    alive_keys.add(key)
            except:
                pass

    alive_lines = [parsed[k][1] for k in alive_keys]

    with open("alive_sub.txt", "w") as f:
        f.write("\n".join(alive_lines))

    print("Total lines:", len(lines))
    print("Parsed nodes:", len(parsed))
    print("Alive:", len(alive_lines))


if __name__ == "__main__":
    main()
