# Phase 1 Demo Report

- Generated: 2026-03-25T22:02:25.037890
- Images scanned successfully: 12
- Total vulnerabilities across demo set: 425
- Average vulnerabilities per image: 35.42

## Image Set
- `alpine:3.18`
- `alpine:3.19`
- `busybox:1.36`
- `busybox:latest`
- `debian:11`
- `debian:12`
- `nginx:1.27-alpine`
- `node:20-alpine`
- `python:3.11-alpine`
- `redis:7-alpine`
- `ubuntu:20.04`
- `ubuntu:22.04`

## Per-Image Results

| Image | Total | Critical | High | Medium | Low | Alert Reduction % | Top Composite CVEs | Report File |
|---|---:|---:|---:|---:|---:|---:|---|---|
| `alpine:3.18` | 0 | 0 | 0 | 0 | 0 | 0 |  | `epss_report_alpine_3.18_20260325_215713.json` |
| `alpine:3.19` | 6 | 0 | 0 | 3 | 3 | 0.0 | CVE-2024-58251 (0.400), CVE-2024-58251 (0.400), CVE-2024-58251 (0.400) | `epss_report_alpine_3.19_20260325_215707.json` |
| `busybox:1.36` | 0 | 0 | 0 | 0 | 0 | 0 |  | `epss_report_busybox_1.36_20260325_215718.json` |
| `busybox:latest` | 0 | 0 | 0 | 0 | 0 | 0 |  | `epss_report_busybox_latest_20260325_215724.json` |
| `debian:11` | 126 | 0 | 1 | 79 | 46 | 85.71 | CVE-2019-8457 (0.699), CVE-2023-45853 (0.597), CVE-2019-1010022 (0.593) | `epss_report_debian_11_20260325_215842.json` |
| `debian:12` | 95 | 0 | 0 | 56 | 39 | 100.0 | CVE-2023-45853 (0.597), CVE-2019-1010022 (0.593), CVE-2019-1010022 (0.593) | `epss_report_debian_12_20260325_215845.json` |
| `nginx:1.27-alpine` | 66 | 0 | 0 | 46 | 20 | 100.0 | CVE-2025-15467 (0.595), CVE-2025-15467 (0.595), CVE-2026-32767 (0.592) | `epss_report_nginx_1.27-alpine_20260325_215903.json` |
| `node:20-alpine` | 15 | 0 | 0 | 14 | 1 | 100.0 | CVE-2026-23950 (0.552), CVE-2026-24842 (0.528), CVE-2026-22184 (0.512) | `epss_report_node_20-alpine_20260325_220012.json` |
| `python:3.11-alpine` | 6 | 0 | 0 | 5 | 1 | 100.0 | CVE-2026-23949 (0.544), CVE-2026-22184 (0.512), CVE-2026-24049 (0.484) | `epss_report_python_3.11-alpine_20260325_215923.json` |
| `redis:7-alpine` | 83 | 0 | 2 | 74 | 7 | 95.12 | CVE-2023-45288 (0.786), CVE-2025-68121 (0.600), CVE-2023-24538 (0.595) | `epss_report_redis_7-alpine_20260325_220030.json` |
| `ubuntu:20.04` | 2 | 0 | 0 | 2 | 0 | 0.0 | CVE-2025-4802 (0.480), CVE-2025-4802 (0.480) | `epss_report_ubuntu_20.04_20260325_215748.json` |
| `ubuntu:22.04` | 26 | 0 | 0 | 20 | 6 | 0.0 | CVE-2025-8941 (0.512), CVE-2025-8941 (0.512), CVE-2025-8941 (0.512) | `epss_report_ubuntu_22.04_20260325_215752.json` |
