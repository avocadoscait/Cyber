"""
B25 - Threat Intelligence Module
=================================
A threat intelligence module that:
  - Maintains a local threat intelligence database (known malicious IPs,
    suspicious CIDR ranges, malicious domains, and IOC patterns)
  - Scores indicators of compromise (IoCs) on a 0-100 threat scale
  - Categorises threats (C2, scanner, phishing, malware distribution)
  - Generates structured threat reports
  - Demonstrates integration with simulated network events
"""

import ipaddress
import re
import datetime
from dataclasses import dataclass, field
from typing import Optional

# ─────────────────────────────────────────────
# THREAT INTELLIGENCE DATABASE
# ─────────────────────────────────────────────

# Known malicious IP addresses (simulated TI feed)
MALICIOUS_IPS = {
    "185.220.101.45":  {"category": "Tor Exit Node",        "score": 75, "source": "TorProject"},
    "194.165.16.11":   {"category": "C2 Server",            "score": 95, "source": "AbuseIPDB"},
    "45.142.212.100":  {"category": "Malware Distribution", "score": 90, "source": "MalwareBazaar"},
    "91.92.136.20":    {"category": "Brute Force Scanner",  "score": 80, "source": "AbuseIPDB"},
    "203.0.113.10":    {"category": "Reconnaissance",       "score": 70, "source": "Internal"},
    "192.0.2.99":      {"category": "Port Scanner",         "score": 72, "source": "Internal"},
    "10.20.30.40":     {"category": "Brute Force",          "score": 85, "source": "Internal IDS"},
}

# Suspicious CIDR ranges (e.g. known hosting ranges used for attacks)
SUSPICIOUS_RANGES = [
    ("185.220.0.0/16",  "Tor/VPN hosting range",       55),
    ("45.142.0.0/16",   "Bulletproof hosting",         65),
    ("91.92.0.0/16",    "Known scanner network",       60),
    ("194.165.0.0/16",  "Malicious hosting provider",  70),
]

# Known malicious domains
MALICIOUS_DOMAINS = {
    "evil-malware.ru":      {"category": "Malware C2",       "score": 95},
    "phishing-bank.tk":     {"category": "Phishing",         "score": 90},
    "free-bitcoin.xyz":     {"category": "Scam",             "score": 80},
    "update-flash.net":     {"category": "Malware Dropper",  "score": 85},
    "secure-login-au.com":  {"category": "Phishing",         "score": 88},
}

# Suspicious TLD list (higher base risk)
SUSPICIOUS_TLDS = {".tk": 30, ".ru": 20, ".xyz": 25, ".top": 20, ".click": 25}

# Known malicious URL patterns
MALICIOUS_URL_PATTERNS = [
    (re.compile(r"\/[a-z0-9]{32,}\.exe", re.I),     "Malware download path",  80),
    (re.compile(r"\/gate\.php",          re.I),       "Known C2 gate endpoint", 85),
    (re.compile(r"wp-content.*base64",   re.I),       "Webshell indicator",     75),
    (re.compile(r"\/shell\.(php|aspx)",  re.I),       "Webshell file",          90),
    (re.compile(r"cmd\.exe|\/bin\/sh",   re.I),       "Command injection IoC",  88),
]

# ─────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────

@dataclass
class ThreatReport:
    indicator:   str
    ioc_type:    str
    threat_score: int
    category:    str
    confidence:  str
    sources:     list
    description: str
    timestamp:   str = field(default_factory=lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    @property
    def risk_level(self):
        if self.threat_score >= 80: return "CRITICAL"
        if self.threat_score >= 60: return "HIGH"
        if self.threat_score >= 40: return "MEDIUM"
        if self.threat_score >= 20: return "LOW"
        return "CLEAN"

# ─────────────────────────────────────────────
# INTELLIGENCE ANALYSIS ENGINE
# ─────────────────────────────────────────────

def analyse_ip(ip_str: str) -> ThreatReport:
    score    = 0
    sources  = []
    categories = []

    # Check exact match
    if ip_str in MALICIOUS_IPS:
        entry = MALICIOUS_IPS[ip_str]
        score = max(score, entry["score"])
        categories.append(entry["category"])
        sources.append(entry["source"])

    # Check CIDR ranges
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for cidr, label, range_score in SUSPICIOUS_RANGES:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                score = max(score, range_score)
                categories.append(label)
                sources.append(f"CIDR:{cidr}")
    except ValueError:
        pass

    # Private IP — clean
    try:
        if ipaddress.ip_address(ip_str).is_private and score == 0:
            return ThreatReport(ip_str, "IP", 0, "Private/Internal", "HIGH", ["RFC1918"], "Internal network address — not evaluated against external threat feeds")
    except ValueError:
        pass

    category = ", ".join(categories) if categories else "No threat data"
    confidence = "HIGH" if ip_str in MALICIOUS_IPS else ("MEDIUM" if sources else "LOW")
    desc = f"IP found in {len(sources)} threat feed(s)." if sources else "No matching threat intelligence found."

    return ThreatReport(ip_str, "IP", score, category, confidence, sources or ["None"], desc)


def analyse_domain(domain: str) -> ThreatReport:
    score    = 0
    sources  = []
    categories = []

    domain_lower = domain.lower()

    # Exact match
    if domain_lower in MALICIOUS_DOMAINS:
        entry = MALICIOUS_DOMAINS[domain_lower]
        score = max(score, entry["score"])
        categories.append(entry["category"])
        sources.append("Domain Blocklist")

    # Check parent domain
    parts = domain_lower.split(".")
    if len(parts) > 2:
        parent = ".".join(parts[-2:])
        if parent in MALICIOUS_DOMAINS:
            entry = MALICIOUS_DOMAINS[parent]
            score = max(score, entry["score"] - 10)
            categories.append(f"Subdomain of known-bad domain ({parent})")
            sources.append("Domain Blocklist (parent)")

    # Suspicious TLD
    for tld, tld_score in SUSPICIOUS_TLDS.items():
        if domain_lower.endswith(tld):
            score += tld_score
            categories.append(f"Suspicious TLD ({tld})")
            sources.append("TLD Reputation")
            break

    score = min(score, 100)
    category = ", ".join(categories) if categories else "No threat data"
    confidence = "HIGH" if domain_lower in MALICIOUS_DOMAINS else ("MEDIUM" if score > 0 else "LOW")
    desc = f"Domain scored {score}/100 across {len(sources)} check(s)." if sources else "No matching threat intelligence found."

    return ThreatReport(domain, "Domain", score, category, confidence, sources or ["None"], desc)


def analyse_url(url: str) -> ThreatReport:
    score = 0
    sources = []
    categories = []

    for pattern, label, pat_score in MALICIOUS_URL_PATTERNS:
        if pattern.search(url):
            score = max(score, pat_score)
            categories.append(label)
            sources.append("URL Pattern Match")

    category = ", ".join(categories) if categories else "No threat data"
    desc = f"URL matched {len(categories)} malicious pattern(s)." if categories else "No suspicious patterns detected."

    return ThreatReport(url[:60], "URL", score, category, "MEDIUM" if score > 0 else "LOW", sources or ["None"], desc)


# ─────────────────────────────────────────────
# REPORT PRINTER
# ─────────────────────────────────────────────

def print_report(r: ThreatReport):
    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "CLEAN": "✅"}
    icon = icons.get(r.risk_level, "⚪")
    print(f"  {icon} [{r.risk_level:8s}] Score={r.threat_score:3d}/100 | {r.ioc_type:7s} | {r.indicator}")
    print(f"            Category:   {r.category}")
    print(f"            Confidence: {r.confidence} | Sources: {', '.join(r.sources)}")
    print(f"            {r.description}")


# ─────────────────────────────────────────────
# EVALUATION / DEMO
# ─────────────────────────────────────────────

def run_demo():
    print("=" * 65)
    print("THREAT INTELLIGENCE MODULE — ANALYSIS DEMO")
    print("=" * 65)

    test_ips = [
        "194.165.16.11",   # known C2
        "185.220.101.45",  # Tor exit node
        "45.142.212.100",  # malware distribution
        "91.92.200.5",     # suspicious range (not exact match)
        "8.8.8.8",         # Google DNS — clean
        "10.20.30.40",     # brute force (from IDS)
        "192.168.1.1",     # private IP
    ]

    test_domains = [
        "evil-malware.ru",
        "login.phishing-bank.tk",
        "secure-login-au.com",
        "google.com",
        "free-bitcoin.xyz",
    ]

    test_urls = [
        "http://evil.com/gate.php?id=abc123",
        "https://legit-site.com/page",
        "http://hacked-site.com/wp-content/uploads/base64encoded.php",
        "http://malware.ru/payload_a1b2c3d4e5f6g7h8.exe",
    ]

    print("\n── IP Address Intelligence ──")
    for ip in test_ips:
        r = analyse_ip(ip)
        print_report(r)

    print("\n── Domain Intelligence ──")
    for domain in test_domains:
        r = analyse_domain(domain)
        print_report(r)

    print("\n── URL Pattern Analysis ──")
    for url in test_urls:
        r = analyse_url(url)
        print_report(r)

    print("\n" + "=" * 65)
    print("DEMO COMPLETE")
    print("=" * 65)


if __name__ == "__main__":
    run_demo()
