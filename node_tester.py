import socket
import ssl
import time
import base64
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 3
MAX_WORKERS = 80  # برای 8000 نود مناسبه

def tcp_connect(host, port):
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


def tls_check(host, port, server_name):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=server_name) as s:
            s.settimeout(TIMEOUT)
            s.connect((host, port))
        return True
    except:
        return False


def test_node(node):
    host = node["host"]
    port = node["port"]
    tls = node.get("tls", False)
    sni = node.get("sni", host)

    for _ in range(2):  # retry once
        if not tcp_connect(host, port):
            continue

        if tls:
            if not tls_check(host, port, sni):
                continue

        return True

    return False


def main():
    with open("nodes.json", "r") as f:
        nodes = json.load(f)

    unique_nodes = {}
    for n in nodes:
        key = f"{n['host']}:{n['port']}"
        unique_nodes[key] = n

    alive_keys = set()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_node, node): key for key, node in unique_nodes.items()}

        for future in as_completed(futures):
            key = futures[future]
            if future.result():
                alive_keys.add(key)

    final_nodes = [n for n in nodes if f"{n['host']}:{n['port']}" in alive_keys]

    with open("alive_nodes.json", "w") as f:
        json.dump(final_nodes, f, indent=2)

    print(f"Total: {len(nodes)}")
    print(f"Alive: {len(final_nodes)}")


if __name__ == "__main__":
    main()
