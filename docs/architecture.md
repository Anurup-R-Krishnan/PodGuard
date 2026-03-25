# Architecture

## Modules

- `scanner`: Trivy adapter and JSON parsing
- `enrichment`: EPSS API client and KEV ingestion
- `pipeline`: scan -> enrich -> score orchestration
- `scoring`: composite score and ranking logic
- `reports`: JSON/HTML report generation
- `utils`: data models, logging, and persistence

## Phase 1 Scoring

```text
Composite = 0.4 * normalize(CVSS) + 0.4 * EPSS + 0.2 * Reachability
```

Severity thresholds:

- CRITICAL: >= 0.8
- HIGH: >= 0.6
- MEDIUM: >= 0.4
- LOW: < 0.4
