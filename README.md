# ModSecurity CRS Paranoia Level Evaluation

A controlled empirical comparison of ModSecurity Core Rule Set (CRS) 3.3.8 at **Paranoia Level 1** (inbound anomaly threshold T=5) versus **Paranoia Level 2** (inbound anomaly threshold T=3), evaluated against structured SQLi and XSS attack payloads and deliberately designed benign traffic.

Submitted as an MSc Cybersecurity dissertation at Wrexham University, April 2026.

---

## Key Finding

Raising the CRS paranoia level from PL1 to PL2 produced **zero improvement in detection rate** (TPR remained 97.0%) while **doubling the false positive rate** from 1.0% to 2.0%.

Audit log analysis confirmed that no PL2-specific rules fired in either configuration. All 37 active rules carried `paranoia-level/1` tags. Every difference between configurations was attributable solely to **threshold arithmetic**, not additional detection logic — a mechanism termed the *threshold-not-rules* effect.

---

## Experiment Overview

| Metric | PL1 | PL2 |
|---|---|---|
| True Positive Rate | 97.0% | 97.0% |
| False Positive Rate | 1.0% | 2.0% |
| Precision | 97.5% | 95.1% |
| F1 Score | 97.2% | 96.0% |
| MCC | 0.9614 | 0.9444 |
| Mean Latency | 46.66ms | 41.93ms |

**700 requests total per configuration:** 200 malicious (100 SQLi + 100 XSS across 5 subcategories each) and 500 benign (SQL-Keyword, Scripting-Keyword, Special-Chars, Neutral).

---

## Repository Structure

```
├── config/
│   ├── pl1/               # Docker Compose for PL1 configuration
│   └── pl2/               # Docker Compose for PL2 configuration
├── payloads/
│   ├── sqli/              # 100 SQLi payloads (Basic, Boolean, Union, Time-Based, Obfuscated)
│   ├── xss/               # 100 XSS payloads (Basic, Event-Based, Mixed-Evasion, Obfuscated, Advanced)
│   └── benign/            # 500 benign requests (SQL-Keyword, Scripting-Keyword, Special-Chars, Neutral)
├── logs/
│   ├── pl1/               # Results CSV, ModSecurity audit log, rule analysis
│   └── pl2/               # Results CSV, ModSecurity audit log, rule analysis
├── figures_output/        # Generated figures (PNG)
├── traffic_generator.py   # Sends payloads, records HTTP status and latency, collects Docker stats
├── log_parser.py          # Parses ModSecurity audit logs, extracts rule firing data
└── figures.py             # Generates all dissertation figures from results data
```

---

## Testbed

- **WAF:** ModSecurity v3.0.14 + NGINX + OWASP CRS 3.3.8 (`owasp/modsecurity-crs:nginx`)
- **Target:** OWASP Juice Shop (`/rest/products/search?q=`)
- **Environment:** Docker Desktop with WSL2 backend on Windows 11
- **Traffic generator:** Python 3.12 (`requests` library)

---

## Reproducing the Experiment

**Prerequisites:** Docker Desktop, Python 3.12, `requests` library

```bash
# Start PL1 environment
docker-compose -f config/pl1/docker-compose.yml up -d

# Run PL1 experiment
python traffic_generator.py

# Stop and start PL2 environment
docker-compose -f config/pl1/docker-compose.yml down
docker-compose -f config/pl2/docker-compose.pl2.yml up -d

# Run PL2 experiment
python traffic_generator.py pl2

# Parse audit logs
python log_parser.py

# Generate figures
python figures.py
```

---

## Bypasses Identified

Six payloads evaded detection at both paranoia levels (zero rules fired, zero anomaly score):

| ID | Evasion Technique | Payload |
|---|---|---|
| SQLI_18 | MySQL `#` comment terminator | `admin'#` |
| SQLI_33 | CASE WHEN structural gap | `1 AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1` |
| SQLI_34 | CASE WHEN with column reference | `' AND (SELECT CASE WHEN (username='admin')...)` |
| SQLI_91 | Inline comment keyword splitting | `' UN/**/ION SEL/**/ECT 1,2--` |
| SQLI_94 | Double URL encoding | `'%2527OR%25271%3D1--` |
| XSS_79 | Double URL encoding | `%2522%253E%253Cscript%253Ealert(1)%253C%252Fscript%253E` |

All bypasses represent **complete signature absence** (not threshold-dependent near-misses) and are identical across PL1 and PL2.

---

## Related Work

The WAF logs from this experiment were subsequently ingested into **Microsoft Sentinel** to build detection-engineering content on top of the research — including a KQL `leftanti`-join hunt that independently re-discovers the `SQLI_33` boolean-blind bypass as an `HTTP 200` request with no matching WAF rule hit.

➡️ **[WAF Bypass Detection in Microsoft Sentinel](https://github.com/Bill-Benson/sentinel-waf-detection)** — operational SIEM follow-on to this dissertation.

---

## References

Payloads derived from publicly documented sources:
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP Web Security Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
- [CRS Regression Test Suite](https://github.com/coreruleset/coreruleset/tree/v3.3.8/tests/regression)
