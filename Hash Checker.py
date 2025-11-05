import requests
import time
import random
import threading
from queue import Queue
import os
import sys

# Ensure UTF-8 output for Windows consoles
sys.stdout.reconfigure(encoding='utf-8')

# ==========================
# CONFIGURATION
# ==========================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ← Your VirusTotal API key
API_KEY = input("Enter your Virus Total API Key: ").strip()

# Use absolute paths for files
INPUT_FILE = os.path.join(BASE_DIR, "hashes.txt")
CLEAN_FILE = os.path.join(BASE_DIR, "clean_hashes.txt")
MALICIOUS_FILE = os.path.join(BASE_DIR, "malicious_hashes.txt")
UNKNOWN_FILE = os.path.join(BASE_DIR, "unknown_hashes.txt")

VT_URL = "https://www.virustotal.com/api/v3/files/"
MAX_RETRIES = 3
THREAD_COUNT = 4
RATE_LIMIT = 4            # VirusTotal Free API = 4 requests/minute
RATE_LIMIT_INTERVAL = 65  # seconds between allowed groups
PROXIES = None            # Optional: {"https": "http://127.0.0.1:8080"}

headers = {"x-apikey": API_KEY}

# Locks for multi-threaded safety
print_lock = threading.Lock()
file_lock = threading.Lock()
rate_lock = threading.Lock()
request_times = []

# Counters
count_clean = 0
count_malicious = 0
count_unknown = 0

# ==========================
# FUNCTIONS
# ==========================


def enforce_rate_limit():
    """Ensure we don't exceed VirusTotal's 4 lookups/min limit."""
    with rate_lock:
        now = time.time()
        request_times.append(now)

        # Keep only timestamps within the last 60 seconds
        while request_times and request_times[0] < now - 60:
            request_times.pop(0)

        if len(request_times) >= RATE_LIMIT:
            sleep_time = RATE_LIMIT_INTERVAL - (now - request_times[0])
            if sleep_time > 0:
                with print_lock:
                    print(
                        f"[INFO] Rate limit reached — sleeping {sleep_time:.1f}s...")
                time.sleep(sleep_time)


def check_hash(hash_value):
    """Query VirusTotal for a given hash with retry logic."""
    for attempt in range(1, MAX_RETRIES + 1):
        enforce_rate_limit()
        try:
            response = requests.get(
                VT_URL + hash_value, headers=headers, proxies=PROXIES, timeout=20)
            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                undetected = stats.get("undetected", 0)

                if malicious > 0 or suspicious > 0:
                    return "Malicious", malicious, suspicious, undetected
                else:
                    return "Clean", malicious, suspicious, undetected

            elif response.status_code == 404:
                return "Not Found in VT", 0, 0, 0
            elif response.status_code == 429:
                with print_lock:
                    print("[WARN] Rate limit hit (429) — sleeping 65s...")
                time.sleep(65)
            else:
                with print_lock:
                    print(
                        f"[WARN] Unexpected response ({response.status_code}) for {hash_value}")
        except requests.exceptions.RequestException as e:
            with print_lock:
                print(
                    f"[WARN] Network error on attempt {attempt}/{MAX_RETRIES} for {hash_value}: {e}")

        # Exponential backoff before retry
        sleep_time = 2 ** attempt + random.uniform(0, 1)
        time.sleep(sleep_time)

    return "Error (Max retries exceeded)", 0, 0, 0


def write_result(filename, text):
    """Safely append text to a file."""
    with file_lock:
        with open(filename, "a", encoding="utf-8") as f:
            f.write(text + "\n")


def worker(q):
    """Thread worker to process hashes."""
    global count_clean, count_malicious, count_unknown

    while not q.empty():
        hash_value = q.get()
        status, malicious, suspicious, undetected = check_hash(hash_value)

        with print_lock:
            print(f"[RESULT] {hash_value} → {status}")

        if status == "Clean":
            write_result(
                CLEAN_FILE, f"{hash_value} : Clean ({undetected} undetected)")
            with file_lock:
                count_clean += 1
        elif status == "Malicious":
            write_result(
                MALICIOUS_FILE, f"{hash_value} : Malicious ({malicious} malicious, {suspicious} suspicious)")
            with file_lock:
                count_malicious += 1
        else:
            write_result(UNKNOWN_FILE, f"{hash_value} : {status}")
            with file_lock:
                count_unknown += 1

        q.task_done()


# ==========================
# MAIN
# ==========================

def main():
    global count_clean, count_malicious, count_unknown

    # Create empty hashes.txt if missing
    if not os.path.exists(INPUT_FILE):
        open(INPUT_FILE, "w").close()
        print(f"[ERROR] '{INPUT_FILE}' not found — an empty one was created.")
        print("→ Please add your hashes (one per line) and re-run the script.")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        hashes = [line.strip() for line in f if line.strip()]

    if not hashes:
        print(
            f"[ERROR] No hashes found in {INPUT_FILE}. Please add them and re-run.")
        return

    # Reset output files
    for file in [CLEAN_FILE, MALICIOUS_FILE, UNKNOWN_FILE]:
        open(file, "w", encoding="utf-8").close()

    print(f"[INFO] Starting VirusTotal lookup for {len(hashes)} hashes...\n")

    q = Queue()
    for h in hashes:
        q.put(h)

    threads = []
    for _ in range(min(THREAD_COUNT, len(hashes))):
        t = threading.Thread(target=worker, args=(q,))
        t.start()
        threads.append(t)

    q.join()

    print("\n[INFO] All done!")
    print(f"[FILE] Clean hashes saved to: {CLEAN_FILE}")
    print(f"[FILE] Malicious hashes saved to: {MALICIOUS_FILE}")
    print(f"[FILE] Unknown/Not Found hashes saved to: {UNKNOWN_FILE}")
    print("\n[SUMMARY]")
    print(f"   Clean: {count_clean}")
    print(f"   Malicious: {count_malicious}")
    print(f"   Unknown/Not Found: {count_unknown}")


# ==========================
# ENTRY POINT
# ==========================
if __name__ == "__main__":
    main()
