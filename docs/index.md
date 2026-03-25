# EPSS Framework Docs

This project prioritizes container vulnerabilities using:

- CVSS severity
- EPSS exploit probability
- Reachability (heuristic in Phase 1, deeper analysis in Phase 2)

## Core Pipeline

1. Scan image with Trivy
2. Enrich CVEs with EPSS
3. Compute composite score
4. Rank vulnerabilities and generate reports

## CLI

```bash
epss-triage scan nginx:latest
epss-triage info
```
