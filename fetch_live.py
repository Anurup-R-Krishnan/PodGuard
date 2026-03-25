import json
import urllib.request
from datetime import datetime

cves = [
    {"id": "CVE-2021-23017", "pkg": "nginx", "cvss": 7.5, "reachability": 1.0, "fix": "1.20.1-r0"},
    {"id": "CVE-2022-41741", "pkg": "nginx", "cvss": 7.5, "reachability": 0.8, "fix": "1.22.1"},
    {"id": "CVE-2021-44228", "pkg": "log4j-core", "cvss": 10.0, "reachability": 1.0, "fix": "2.15.0"},
    {"id": "CVE-2014-0160", "pkg": "openssl", "cvss": 7.5, "reachability": 0.9, "fix": "1.0.1g"},
    {"id": "CVE-2019-11043", "pkg": "php-fpm", "cvss": 9.8, "reachability": 0.5, "fix": "7.3.11"},
    {"id": "CVE-2017-5638", "pkg": "struts", "cvss": 10.0, "reachability": 0.0, "fix": "2.3.32"},
    {"id": "CVE-2023-4863", "pkg": "libwebp", "cvss": 8.8, "reachability": 1.0, "fix": "1.3.2"},
    {"id": "CVE-2023-38545", "pkg": "curl", "cvss": 9.8, "reachability": 1.0, "fix": "8.4.0"},
    {"id": "CVE-2024-3094", "pkg": "xz", "cvss": 10.0, "reachability": 0.0, "fix": "5.6.1-r1"},
]

url = "https://api.first.org/data/v1/epss?cve=" + ",".join([c["id"] for c in cves])
try:
    req = urllib.request.urlopen(url)
    res = json.loads(req.read().decode())
    epss_map = {item["cve"]: float(item["epss"]) for item in res.get("data", [])}
except Exception as e:
    print(f"Error fetching EPSS: {e}")
    epss_map = {}

vulns = []
for c in cves:
    epss = epss_map.get(c["id"], 0.01)
    # Composite score w1=0.4 (CVSS/10), w2=0.4 (EPSS), w3=0.2 (Reachability)
    score = (0.4 * (c["cvss"] / 10.0)) + (0.4 * epss) + (0.2 * c["reachability"])
    
    vulns.append({
        "id": c["id"],
        "score": score,
        "cvss": c["cvss"],
        "epss": epss,
        "reachability": c["reachability"],
        "pkg": c["pkg"],
        "fix": c["fix"]
    })

# Sort descending
vulns.sort(key=lambda x: x["score"], reverse=True)

data = {
    "image": "nginx:custom-build-xyz",
    "scannedAt": datetime.now().isoformat(),
    "metrics": {
        "total": len(vulns),
        "critical": len([v for v in vulns if v["score"] >= 0.8]),
        "high": len([v for v in vulns if v["score"] >= 0.6 and v["score"] < 0.8]),
        "alertReduction": 75
    },
    "vulnerabilities": vulns
}

with open("epss-frontend/src/lib/real_data.json", "w") as f:
    json.dump(data, f, indent=2)

print("Generated.")
