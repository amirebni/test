import requests
import random
from datetime import datetime

SUB_URL = "https://raw.githubusercontent.com/punez/Repo-5/main/alive.txt"
OUTPUT_FILE = "good_2000.txt"
MAX_OUTPUT = 2000

def log(msg):
    print(f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}] {msg}")

def download():
    try:
        r = requests.get(SUB_URL, timeout=15)
        r.raise_for_status()
        return [l.strip() for l in r.text.splitlines() if l.strip()]
    except Exception as e:
        log(f"خطا دانلود: {e}")
        return []

def get_protocol_score(line):
    lower = line.lower()
    if "hysteria2" in lower or "hy2://" in lower:
        return 10
    if "tuic" in lower:
        return 9
    if "reality" in lower:
        return 8
    if "vision" in lower or "xtls" in lower:
        return 7
    if "trojan://" in lower:
        return 6
    if "vless://" in lower:
        return 5
    if "vmess://" in lower:
        return 4
    return 1  # ss و بقیه

def main():
    log("شروع فیلتر سبک‌تر")
    lines = download()
    log(f"ورودی: {len(lines):,}")

    # امتیازدهی ساده
    scored = [(get_protocol_score(line), line) for line in lines]
    scored.sort(key=lambda x: x[0], reverse=True)

    # بهترین‌ها رو بگیر (حداکثر ۲۰۰۰)
    final = [line for _, line in scored[:MAX_OUTPUT]]

    random.shuffle(final)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(final) + "\n")

    log(f"تمام شد → {len(final):,} نود → {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
