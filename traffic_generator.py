import requests
import csv
import time
import subprocess
import threading
import sys

TARGET = "http://localhost/rest/products/search?q="
OUTPUT_DIR_PL1 = "logs/pl1/"
OUTPUT_DIR_PL2 = "logs/pl2/"

stop_stats = False

def collect_docker_stats(output_file):
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Container", "CPU_Percent", "Memory_MB"])
    while not stop_stats:
        try:
            result = subprocess.run(
                ["docker", "stats", "--no-stream", "--format",
                 "{{.Name}},{{.CPUPerc}},{{.MemUsage}}"],
                capture_output=True, text=True, timeout=5
            )
            timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                parts = line.split(",")
                if len(parts) < 3:
                    continue
                name = parts[0]
                cpu = parts[1].replace("%", "").strip()
                mem_raw = parts[2].split("/")[0].strip()
                if "GiB" in mem_raw:
                    mem_mb = round(float(mem_raw.replace("GiB", "").strip()) * 1024, 2)
                elif "MiB" in mem_raw:
                    mem_mb = round(float(mem_raw.replace("MiB", "").strip()), 2)
                elif "kB" in mem_raw:
                    mem_mb = round(float(mem_raw.replace("kB", "").strip()) / 1024, 2)
                else:
                    mem_mb = mem_raw
                with open(output_file, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([timestamp, name, cpu, mem_mb])
        except Exception:
            pass
        time.sleep(3)

def load_payloads(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]

def send_request(payload, label, category, subcategory, output_file):
    url = TARGET + requests.utils.quote(payload, safe='')
    start = time.time()
    try:
        r = requests.get(url, timeout=3)
        latency = round((time.time() - start) * 1000, 2)
        status = r.status_code
    except Exception:
        latency = -1
        status = -1
    result = "BLOCKED" if status == 403 else "ALLOWED"
    with open(output_file, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([label, category, subcategory, payload[:80], status, result, latency])
    print(f"[{result}] {category}/{subcategory} | {status} | {latency}ms | {payload[:50]}")

def run_experiment(output_dir):
    global stop_stats
    results_file = output_dir + "results.csv"
    stats_file = output_dir + "docker_stats.csv"

    with open(results_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "Category", "Subcategory", "Payload", "Status", "Result", "Latency_ms"])

    stop_stats = False
    stats_thread = threading.Thread(target=collect_docker_stats, args=(stats_file,), daemon=True)
    stats_thread.start()
    print("Docker stats collection started...")

    # SQLi payloads -- 100 total across 5 subcategories
    sqli_files = [
        ("payloads/sqli/sqli_basic.txt",      "Basic"),
        ("payloads/sqli/sqli_boolean.txt",     "Boolean"),
        ("payloads/sqli/sqli_union.txt",       "Union"),
        ("payloads/sqli/sqli_time.txt",        "Time-Based"),
        ("payloads/sqli/sqli_obfuscated.txt",  "Obfuscated"),
    ]
    counter = 1
    for filepath, subcategory in sqli_files:
        payloads = load_payloads(filepath)
        for p in payloads:
            send_request(p, f"SQLI_{counter}", "SQLi", subcategory, results_file)
            counter += 1
            time.sleep(0.1)

    # XSS payloads -- 100 total across 5 subcategories
    xss_files = [
        ("payloads/xss/xss_basic.txt",         "Basic"),
        ("payloads/xss/xss_event.txt",          "Event-Based"),
        ("payloads/xss/xss_mixed_evasion.txt",  "Mixed-Evasion"),
        ("payloads/xss/xss_obfuscated.txt",     "Obfuscated"),
        ("payloads/xss/xss_advanced.txt",       "Advanced"),
    ]
    counter = 1
    for filepath, subcategory in xss_files:
        payloads = load_payloads(filepath)
        for p in payloads:
            send_request(p, f"XSS_{counter}", "XSS", subcategory, results_file)
            counter += 1
            time.sleep(0.1)

    # Benign requests -- 500 total across 4 subcategories
    benign_files = [
        ("payloads/benign/benign_sql_keywords.txt",      "SQL-Keyword"),
        ("payloads/benign/benign_scripting_keywords.txt","Scripting-Keyword"),
        ("payloads/benign/benign_special_chars.txt",     "Special-Chars"),
        ("payloads/benign/benign_neutral.txt",           "Neutral"),
    ]
    counter = 1
    for filepath, subcategory in benign_files:
        payloads = load_payloads(filepath)
        for p in payloads:
            send_request(p, f"BENIGN_{counter}", "Benign", subcategory, results_file)
            counter += 1
            time.sleep(0.1)

    stop_stats = True
    time.sleep(4)

    # Parse results and print summary
    malicious_blocked = []
    malicious_missed = []
    benign_blocked = []
    benign_allowed = 0

    with open(results_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['Category'] == 'Benign':
                if row['Result'] == 'BLOCKED':
                    benign_blocked.append(row)
                else:
                    benign_allowed += 1
            else:
                if row['Result'] == 'BLOCKED':
                    malicious_blocked.append(row)
                else:
                    malicious_missed.append(row)

    total_malicious = len(malicious_blocked) + len(malicious_missed)
    total_benign = len(benign_blocked) + benign_allowed
    tpr = round(len(malicious_blocked) / total_malicious * 100, 2)
    fpr = round(len(benign_blocked) / total_benign * 100, 2)

    print(f"\n{'='*60}")
    config = "PL2" if "pl2" in output_dir else "PL1"
    print(f"EXPERIMENT SUMMARY -- {config}")
    print(f"{'='*60}")
    print(f"\nMALICIOUS PAYLOADS")
    print(f"  Total sent:    {total_malicious}")
    print(f"  Blocked:       {len(malicious_blocked)}")
    print(f"  Missed:        {len(malicious_missed)}")
    print(f"  TPR:           {tpr}%")

    if malicious_missed:
        print(f"\n  !! MISSED PAYLOADS (note these):")
        for r in malicious_missed:
            print(f"     [{r['ID']}] {r['Subcategory']} | Status {r['Status']} | {r['Payload'][:60]}")

    print(f"\nBENIGN REQUESTS")
    print(f"  Total sent:    {total_benign}")
    print(f"  Allowed:       {benign_allowed}")
    print(f"  Blocked (FP):  {len(benign_blocked)}")
    print(f"  FPR:           {fpr}%")

    if benign_blocked:
        print(f"\n  !! FALSE POSITIVES (note these):")
        for r in benign_blocked:
            print(f"     [{r['ID']}] {r['Subcategory']} | Status {r['Status']} | {r['Payload'][:60]}")

    print(f"\n{'='*60}")
    print(f"Results CSV:  {results_file}")
    print(f"Docker stats: {stats_file}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "pl2":
        print("Running PL2 experiment...")
        run_experiment(OUTPUT_DIR_PL2)
    else:
        print("Running PL1 experiment...")
        run_experiment(OUTPUT_DIR_PL1)
