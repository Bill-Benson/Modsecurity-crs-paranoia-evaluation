import json
import csv
from collections import defaultdict
import urllib.parse

def parse_audit_log(log_file, output_file, config_label):
    
    rule_counts = defaultdict(lambda: {"msg": "", "count": 0})
    blocked_requests = []
    
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            transaction = entry.get("transaction", {})
            request = transaction.get("request", {})
            response = transaction.get("response", {})
            messages = transaction.get("messages", [])
            
            uri = request.get("uri", "")
            http_code = response.get("http_code", 0)
            
            # Only process search endpoint blocks
            if "/rest/products/search" not in uri:
                continue
            if http_code != 403:
                continue
            
            # Extract query string
            query = ""
            if "?" in uri:
                qs = uri.split("?", 1)[1]
                for param in qs.split("&"):
                    if param.startswith("q="):
                        query = urllib.parse.unquote(param[2:])[:80]
                        break
            
            # Extract detection rules (exclude blocking rules)
            fired_rules = []
            anomaly_score = ""
            
            for msg in messages:
                details = msg.get("details", {})
                rule_id = details.get("ruleId", "")
                rule_msg = msg.get("message", "")
                tags = details.get("tags", [])
                
                if rule_id in ("949110", "980130"):
                    # Extract anomaly score from blocking rule message
                    if "Total Score:" in rule_msg:
                        try:
                            anomaly_score = rule_msg.split("Total Score:")[1].strip().rstrip(")")
                        except:
                            pass
                    continue
                
                if rule_id:
                    fired_rules.append(rule_id)
                    rule_counts[rule_id]["msg"] = rule_msg
                    rule_counts[rule_id]["count"] += 1
                    
                    # Extract paranoia level from tags
                    for tag in tags:
                        if "paranoia-level" in tag:
                            rule_counts[rule_id]["paranoia"] = tag
            
            blocked_requests.append({
                "config": config_label,
                "query": query,
                "anomaly_score": anomaly_score.strip(),
                "rules_fired": ", ".join(fired_rules)
            })
    
    # Write rule frequency summary
    summary_file = output_file.replace(".csv", "_rule_summary.csv")
    with open(summary_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Config", "Rule_ID", "Rule_Message", 
                        "Paranoia_Level", "Times_Fired"])
        for rule_id, data in sorted(rule_counts.items(),
                                     key=lambda x: x[1]["count"],
                                     reverse=True):
            writer.writerow([
                config_label,
                rule_id,
                data["msg"],
                data.get("paranoia", ""),
                data["count"]
            ])
    
    # Write per-request detail
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Config", "Query", "Anomaly_Score", "Rules_Fired"])
        for req in blocked_requests:
            writer.writerow([
                req["config"],
                req["query"],
                req["anomaly_score"],
                req["rules_fired"]
            ])
    
    print(f"\n{'='*60}")
    print(f"LOG ANALYSIS -- {config_label}")
    print(f"{'='*60}")
    print(f"Blocked requests on search endpoint: {len(blocked_requests)}")
    print(f"\nTop detection rules fired:")
    sorted_rules = sorted(rule_counts.items(),
                         key=lambda x: x[1]["count"], reverse=True)
    if sorted_rules:
        for rule_id, data in sorted_rules[:15]:
            paranoia = data.get('paranoia', '')
            print(f"  [{rule_id}] {data['msg'][:55]} | {paranoia} | {data['count']}x")
    else:
        print("  No detection rules found")
    print(f"\nOutput: {output_file}")
    print(f"Rule summary: {summary_file}")

if __name__ == "__main__":
    parse_audit_log(
        "logs/pl1/modsec_audit.log",
        "logs/pl1/rule_analysis.csv",
        "PL1"
    )
    parse_audit_log(
        "logs/pl2/modsec_audit.log",
        "logs/pl2/rule_analysis.csv",
        "PL2"
    )