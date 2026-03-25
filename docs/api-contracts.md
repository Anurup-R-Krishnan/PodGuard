# API Contracts

## Scanner -> Pipeline

`ImageScanner.scan(image)` returns `ScanResult`:

- `image_name: str`
- `image_digest: str`
- `scan_timestamp: datetime`
- `vulnerabilities: list[Vulnerability]`

`Vulnerability` includes:

- `cve_id`
- `cvss_v3_score`
- `severity`
- package/version metadata

## EPSS -> Pipeline

`EPSSClient.get_scores(cve_ids)` returns:

- `dict[str, EPSSScore]` keyed by CVE ID
- fallback score is returned for unknown CVEs

## Pipeline -> Reports

`EnrichmentPipeline.run(image)` returns `EnrichedScanResult`:

- ordered `vulnerabilities` by descending `composite_score`
- score metadata and weight profile
- summary helpers (`severity_summary`, `alert_fatigue_reduction`)
