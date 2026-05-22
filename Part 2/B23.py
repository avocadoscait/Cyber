"""
B23 - Python Intrusion Detection System (IDS)
==============================================
A signature-based and anomaly-based IDS that analyses
simulated network log entries to detect common attacks.

Detection capabilities:
  - Port scanning (SYN flood / sweep)
  - Brute force login attempts
  - SQL injection attempts in HTTP logs
  - XSS attempts in HTTP logs
  - Directory traversal attacks
  - Anomalous traffic volume (threshold-based)
"""

import re
import datetime
from collections import defaultdict

# ─────────────────────────────────────────────
# SIGNATURE RULES
# ─────────────────────────────────────────────

SIGNATURES = [
    {
        "id": "SIG-001",
        "name": "SQL Injection Attempt",
        "pattern": re.compile(r"(union\s+select|'\s*or\s+'1'='1|drop\s+table|insert\s+into|1=1|--\s*$)", re.IGNORECASE),
        "field": "request",
        "severity": "HIGH",
        "category": "Web Attack",
    },
    {
        "id": "SIG-002",
        "name": "XSS Attempt",
        "pattern": re.compile(r"(<script|javascript:|onerror=|onload=|<iframe|alert\()", re.IGNORECASE),
        "field": "request",
        "severity": "HIGH",
        "category": "Web Attack",
    },
    {
        "id": "SIG-003",
        "name": "Directory Traversal",
        "pattern": re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e)", re.IGNORECASE),
        "field": "request",
        "severity": "HIGH",
        "category": "Web Attack",
    },
    {
        "id": "SIG-004",
        "name": "Suspicious User Agent",
        "pattern": re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|dirbuster|hydra|metasploit)", re.IGNORECASE),
        "field": "user_agent",
        "severity": "MEDIUM",
        "category": "Reconnaissance",
    },
    {
        "id": "SIG-005",
        "name": "Admin Path Probe",
        "pattern": re.compile(r"/(admin|wp-admin|phpmyadmin|manager|administrator|shell|backdoor)", re.IGNORECASE),
        "field": "request",
        "severity": "MEDIUM",
        "category": "Reconnaissance",
    },
]

# ─────────────────────────────────────────────
# ANOMALY THRESHOLDS
# ─────────────────────────────────────────────

BRUTE_FORCE_THRESHOLD = 5      # failed logins per IP per window
PORT_SCAN_THRESHOLD   = 10     # unique ports per IP per window
RATE_LIMIT_THRESHOLD  = 50     # requests per IP per window

# ─────────────────────────────────────────────
# ALERT STORE
# ─────────────────────────────────────────────

alerts = []

def raise_alert(rule_id, name, severity, category, src_ip, detail, log_entry=None):
    alert = {
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
        "rule_id":   rule_id,
        "name":      name,
        "severity":  severity,
        "category":  category,
        "src_ip":    src_ip,
        "detail":    detail,
    }
    alerts.append(alert)
    sev_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
    print(f"  {sev_icon} [{alert['timestamp']}] [{rule_id}] {name} | IP={src_ip} | {detail}")

# ─────────────────────────────────────────────
# ANALYSIS ENGINES
# ─────────────────────────────────────────────

def analyse_signature(log):
    for sig in SIGNATURES:
        value = log.get(sig["field"], "")
        if sig["pattern"].search(value):
            raise_alert(
                sig["id"], sig["name"], sig["severity"], sig["category"],
                log.get("src_ip", "unknown"),
                f"{sig['field']}={repr(value[:60])}",
                log
            )


def analyse_anomaly(logs):
    failed_logins  = defaultdict(int)
    port_contacts  = defaultdict(set)
    request_counts = defaultdict(int)

    for log in logs:
        ip = log.get("src_ip", "unknown")

        # Brute force: count failed auth attempts
        if log.get("status") in (401, 403) and log.get("request", "").startswith("/login"):
            failed_logins[ip] += 1

        # Port scan: count unique destination ports
        if "dst_port" in log:
            port_contacts[ip].add(log["dst_port"])

        # Rate limiting: count all requests
        request_counts[ip] += 1

    for ip, count in failed_logins.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            raise_alert("ANO-001", "Brute Force Login", "HIGH", "Authentication Attack",
                        ip, f"{count} failed login attempts detected")

    for ip, ports in port_contacts.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            raise_alert("ANO-002", "Port Scan Detected", "MEDIUM", "Reconnaissance",
                        ip, f"Contacted {len(ports)} unique ports: {sorted(list(ports))[:10]}")

    for ip, count in request_counts.items():
        if count >= RATE_LIMIT_THRESHOLD:
            raise_alert("ANO-003", "High Request Rate", "LOW", "Possible DoS",
                        ip, f"{count} requests in analysis window")

# ─────────────────────────────────────────────
# SIMULATED LOG DATA
# ─────────────────────────────────────────────

SIMULATED_LOGS = [
    # Normal traffic
    {"src_ip": "10.0.0.1", "request": "/index.html", "status": 200, "user_agent": "Mozilla/5.0"},
    {"src_ip": "10.0.0.2", "request": "/products", "status": 200, "user_agent": "Chrome/120"},
    {"src_ip": "10.0.0.3", "request": "/about", "status": 200, "user_agent": "Safari/17"},

    # SQL injection attempts
    {"src_ip": "192.168.1.100", "request": "/login?user=admin'--&pass=x", "status": 400, "user_agent": "curl/7.8"},
    {"src_ip": "192.168.1.100", "request": "/search?q=1 UNION SELECT username,password FROM users", "status": 400, "user_agent": "curl/7.8"},

    # XSS attempts
    {"src_ip": "172.16.0.50", "request": "/comment?text=<script>alert('xss')</script>", "status": 400, "user_agent": "Mozilla/5.0"},
    {"src_ip": "172.16.0.50", "request": "/profile?name=<iframe src=evil.com>", "status": 400, "user_agent": "Mozilla/5.0"},

    # Directory traversal
    {"src_ip": "10.10.10.5", "request": "/download?file=../../etc/passwd", "status": 403, "user_agent": "Python-requests"},

    # Automated scanner
    {"src_ip": "203.0.113.10", "request": "/", "status": 200, "user_agent": "sqlmap/1.7"},
    {"src_ip": "203.0.113.10", "request": "/admin", "status": 404, "user_agent": "nikto/2.1"},

    # Admin probing
    {"src_ip": "198.51.100.5", "request": "/wp-admin/login.php", "status": 404, "user_agent": "Mozilla/5.0"},
    {"src_ip": "198.51.100.5", "request": "/phpmyadmin/", "status": 404, "user_agent": "Mozilla/5.0"},

    # Brute force login (5 failed attempts from same IP)
    {"src_ip": "10.20.30.40", "request": "/login", "status": 401, "user_agent": "hydra"},
    {"src_ip": "10.20.30.40", "request": "/login", "status": 401, "user_agent": "hydra"},
    {"src_ip": "10.20.30.40", "request": "/login", "status": 401, "user_agent": "hydra"},
    {"src_ip": "10.20.30.40", "request": "/login", "status": 401, "user_agent": "hydra"},
    {"src_ip": "10.20.30.40", "request": "/login", "status": 401, "user_agent": "hydra"},

    # Port scan (same IP hitting many ports)
    {"src_ip": "192.0.2.99", "dst_port": 22,   "request": "", "status": 0, "user_agent": ""},
    {"src_ip": "192.0.2.99", "dst_port": 80,   "request": "", "status": 0, "user_agent": ""},
    {"src_ip": "192.0.2.99", "dst_port": 443,  "request": "", "status": 0, "user_agent": ""},
    {"src_ip": "192.0.2.99", "dst_port": 3306, "request": "", "status": 0, "user_agent": ""},
    {"src_ip": "192.0.2.99", "dst_port": 5432, "request": "", "status": 0, "user_agent": ""},
    {"src_ip": "192.0.2.99", "dst_port": 6379, "request": "", "status": 0, "user_agent": ""},
    {"src_ip": "192.0.2.99", "dst_port": 8080, "request": "", "status": 0, "user_agent": ""},
    {"src_ip": "192.0.2.99", "dst_port": 8443, "request": "", "status": 0, "user_agent": ""},
    {"src_ip": "192.0.2.99", "dst_port": 9200, "request": "", "status": 0, "user_agent": ""},
    {"src_ip": "192.0.2.99", "dst_port": 27017,"request": "", "status": 0, "user_agent": ""},
    {"src_ip": "192.0.2.99", "dst_port": 11211,"request": "", "status": 0, "user_agent": ""},
]

# ─────────────────────────────────────────────
# MAIN IDS ENGINE
# ─────────────────────────────────────────────

def run_ids(logs):
    print("=" * 60)
    print("PYTHON IDS — ANALYSIS STARTED")
    print(f"Analysing {len(logs)} log entries...")
    print("=" * 60 + "\n")

    print("── Signature-Based Detection ──")
    for log in logs:
        analyse_signature(log)

    print("\n── Anomaly-Based Detection ──")
    analyse_anomaly(logs)

    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETE — ALERT SUMMARY")
    print("=" * 60)

    high   = [a for a in alerts if a["severity"] == "HIGH"]
    medium = [a for a in alerts if a["severity"] == "MEDIUM"]
    low    = [a for a in alerts if a["severity"] == "LOW"]

    print(f"  Total alerts:  {len(alerts)}")
    print(f"  🔴 HIGH:       {len(high)}")
    print(f"  🟡 MEDIUM:     {len(medium)}")
    print(f"  🟢 LOW:        {len(low)}")

    unique_ips = set(a["src_ip"] for a in alerts)
    print(f"  Suspicious IPs: {len(unique_ips)} — {', '.join(unique_ips)}")
    print("=" * 60)

    return alerts


if __name__ == "__main__":
    run_ids(SIMULATED_LOGS)
