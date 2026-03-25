"""
JSON and HTML Report Generation Module.

Generates structured reports from enriched scan results in multiple formats:
- JSON: Machine-readable structured output
- HTML: Human-readable interactive report with visualizations
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from epss_framework.utils.logging import get_logger
from epss_framework.utils.models import EnrichedScanResult

logger = get_logger()


class ReportGenerator:
    """
    Generates vulnerability reports in multiple formats.

    Usage:
        generator = ReportGenerator(output_dir="./reports")
        generator.generate_json(result, "scan_report.json")
        generator.generate_html(result, "scan_report.html")
    """

    def __init__(self, output_dir: str | Path = "./epss-reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_json(
        self,
        result: EnrichedScanResult,
        filename: Optional[str] = None,
    ) -> Path:
        """Generate a JSON report."""
        if filename is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = result.image_name.replace("/", "_").replace(":", "_")
            filename = f"epss_report_{safe_name}_{ts}.json"

        output_path = self.output_dir / filename

        report_data = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "framework_version": result.framework_version,
                "scoring_method": result.scoring_method,
                "scoring_weights": result.scoring_weights,
            },
            "image": {
                "name": result.image_name,
                "digest": result.image_digest,
                "os_family": result.os_family,
                "os_name": result.os_name,
                "scan_timestamp": result.scan_timestamp.isoformat(),
            },
            "summary": {
                "total_vulnerabilities": result.total_vulns,
                "severity_breakdown": result.severity_summary(),
                "alert_fatigue_metrics": result.alert_fatigue_reduction(),
            },
            "vulnerabilities": [
                {
                    "rank": i + 1,
                    "cve_id": v.cve_id,
                    "composite_score": v.composite_score,
                    "composite_severity": v.composite_severity.value,
                    "cvss_v3_score": v.cvss_v3_score,
                    "cvss_severity": v.cvss_severity.value,
                    "epss_score": v.epss_score,
                    "epss_percentile": v.epss_percentile,
                    "reachability_score": v.reachability_score,
                    "affected_package": v.affected_package,
                    "installed_version": v.installed_version,
                    "fixed_version": v.fixed_version,
                    "title": v.title,
                    "score_explanation": v.score_explanation,
                    "cwe_ids": v.cwe_ids,
                    "has_fix": v.has_fix,
                }
                for i, v in enumerate(result.vulnerabilities)
            ],
        }

        with open(output_path, "w") as f:
            json.dump(report_data, f, indent=2, default=str)

        logger.info(f"[green]📄 JSON report saved:[/green] {output_path}")
        return output_path

    def generate_html(
        self,
        result: EnrichedScanResult,
        filename: Optional[str] = None,
    ) -> Path:
        """Generate an interactive HTML report."""
        if filename is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = result.image_name.replace("/", "_").replace(":", "_")
            filename = f"epss_report_{safe_name}_{ts}.html"

        output_path = self.output_dir / filename
        summary = result.severity_summary()
        fatigue = result.alert_fatigue_reduction()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EPSS CVE Triage Report - {result.image_name}</title>
    <style>
        :root {{
            --bg-primary: #0f0f23;
            --bg-secondary: #1a1a3e;
            --bg-card: #1e1e42;
            --text-primary: #e0e0ff;
            --text-secondary: #a0a0cc;
            --accent-blue: #4fc3f7;
            --accent-purple: #b388ff;
            --accent-green: #69f0ae;
            --accent-red: #ff5252;
            --accent-orange: #ffab40;
            --accent-yellow: #ffd740;
            --border: rgba(255,255,255,0.08);
            --glass: rgba(30, 30, 66, 0.7);
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}
        .header {{
            background: linear-gradient(135deg, #1a1a3e 0%, #2d1b69 50%, #1a1a3e 100%);
            border-radius: 16px;
            padding: 2.5rem;
            margin-bottom: 2rem;
            border: 1px solid var(--border);
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }}
        .header h1 {{
            font-size: 1.8rem;
            background: linear-gradient(90deg, var(--accent-blue), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}
        .header .subtitle {{ color: var(--text-secondary); font-size: 0.95rem; }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1.5rem;
        }}
        .meta-item {{
            background: var(--glass);
            border-radius: 10px;
            padding: 1rem;
            border: 1px solid var(--border);
        }}
        .meta-item .label {{ font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; }}
        .meta-item .value {{ font-size: 1.1rem; font-weight: 600; margin-top: 0.25rem; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid var(--border);
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .stat-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0,0,0,0.3);
        }}
        .stat-card .number {{ font-size: 2rem; font-weight: 700; }}
        .stat-card .label {{ font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem; }}
        .stat-critical {{ border-left: 3px solid var(--accent-red); }}
        .stat-critical .number {{ color: var(--accent-red); }}
        .stat-high {{ border-left: 3px solid var(--accent-orange); }}
        .stat-high .number {{ color: var(--accent-orange); }}
        .stat-medium {{ border-left: 3px solid var(--accent-yellow); }}
        .stat-medium .number {{ color: var(--accent-yellow); }}
        .stat-low {{ border-left: 3px solid var(--accent-green); }}
        .stat-low .number {{ color: var(--accent-green); }}
        .stat-reduction {{ border-left: 3px solid var(--accent-purple); }}
        .stat-reduction .number {{ color: var(--accent-purple); }}

        .section-title {{
            font-size: 1.3rem;
            margin: 2rem 0 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border);
        }}
        thead {{ background: var(--bg-secondary); }}
        th {{
            padding: 0.9rem 1rem;
            text-align: left;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            cursor: pointer;
            user-select: none;
        }}
        th:hover {{ color: var(--accent-blue); }}
        td {{ padding: 0.8rem 1rem; border-top: 1px solid var(--border); font-size: 0.9rem; }}
        tr:hover {{ background: rgba(79, 195, 247, 0.05); }}

        .badge {{
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: rgba(255,82,82,0.15); color: var(--accent-red); border: 1px solid rgba(255,82,82,0.3); }}
        .badge-high {{ background: rgba(255,171,64,0.15); color: var(--accent-orange); border: 1px solid rgba(255,171,64,0.3); }}
        .badge-medium {{ background: rgba(255,215,64,0.15); color: var(--accent-yellow); border: 1px solid rgba(255,215,64,0.3); }}
        .badge-low {{ background: rgba(105,240,174,0.15); color: var(--accent-green); border: 1px solid rgba(105,240,174,0.3); }}

        .score-bar {{
            width: 80px;
            height: 6px;
            background: rgba(255,255,255,0.1);
            border-radius: 3px;
            overflow: hidden;
            display: inline-block;
            vertical-align: middle;
            margin-left: 0.5rem;
        }}
        .score-bar-fill {{
            height: 100%;
            border-radius: 3px;
            transition: width 0.3s;
        }}

        .filter-bar {{
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            padding: 0.4rem 1rem;
            border-radius: 8px;
            border: 1px solid var(--border);
            background: var(--bg-card);
            color: var(--text-primary);
            cursor: pointer;
            font-size: 0.85rem;
            transition: all 0.2s;
        }}
        .filter-btn:hover, .filter-btn.active {{
            background: var(--accent-blue);
            color: var(--bg-primary);
            border-color: var(--accent-blue);
        }}

        .search-box {{
            width: 100%;
            max-width: 400px;
            padding: 0.6rem 1rem;
            border-radius: 8px;
            border: 1px solid var(--border);
            background: var(--bg-secondary);
            color: var(--text-primary);
            font-size: 0.9rem;
            margin-bottom: 1rem;
        }}
        .search-box::placeholder {{ color: var(--text-secondary); }}
        .search-box:focus {{ outline: none; border-color: var(--accent-blue); }}

        .footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            font-size: 0.8rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ EPSS-Augmented CVE Triage Report</h1>
            <p class="subtitle">Multi-factor vulnerability prioritization using CVSS + EPSS + Reachability</p>
            <div class="meta-grid">
                <div class="meta-item">
                    <div class="label">Container Image</div>
                    <div class="value">{result.image_name}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Scan Time</div>
                    <div class="value">{result.scan_timestamp.strftime('%Y-%m-%d %H:%M')}</div>
                </div>
                <div class="meta-item">
                    <div class="label">OS</div>
                    <div class="value">{result.os_name or result.os_family or 'N/A'}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Scoring Method</div>
                    <div class="value">{result.scoring_method} (w₁={result.scoring_weights.get('cvss', 0):.1f}, w₂={result.scoring_weights.get('epss', 0):.1f}, w₃={result.scoring_weights.get('reachability', 0):.1f})</div>
                </div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card stat-critical">
                <div class="number">{summary.get('CRITICAL', 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card stat-high">
                <div class="number">{summary.get('HIGH', 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card stat-medium">
                <div class="number">{summary.get('MEDIUM', 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card stat-low">
                <div class="number">{summary.get('LOW', 0)}</div>
                <div class="label">Low</div>
            </div>
            <div class="stat-card stat-reduction">
                <div class="number">{fatigue.get('alert_reduction_pct', 0):.0f}%</div>
                <div class="label">Alert Reduction</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: var(--accent-blue)">{result.total_vulns}</div>
                <div class="label">Total CVEs</div>
            </div>
        </div>

        <h2 class="section-title">📊 Ranked Vulnerabilities</h2>

        <input type="text" class="search-box" id="searchBox" placeholder="🔍 Search CVE ID, package, or description..." oninput="filterTable()">

        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterSeverity('ALL', this)">All</button>
            <button class="filter-btn" onclick="filterSeverity('CRITICAL', this)">Critical</button>
            <button class="filter-btn" onclick="filterSeverity('HIGH', this)">High</button>
            <button class="filter-btn" onclick="filterSeverity('MEDIUM', this)">Medium</button>
            <button class="filter-btn" onclick="filterSeverity('LOW', this)">Low</button>
        </div>

        <table id="vulnTable">
            <thead>
                <tr>
                    <th onclick="sortTable(0)">#</th>
                    <th onclick="sortTable(1)">CVE ID</th>
                    <th onclick="sortTable(2)">Composite</th>
                    <th onclick="sortTable(3)">Severity</th>
                    <th onclick="sortTable(4)">CVSS</th>
                    <th onclick="sortTable(5)">EPSS</th>
                    <th onclick="sortTable(6)">Package</th>
                    <th onclick="sortTable(7)">Installed</th>
                    <th>Fixed</th>
                </tr>
            </thead>
            <tbody>
"""

        for i, v in enumerate(result.vulnerabilities):
            sev_class = v.composite_severity.value.lower()
            bar_color = {
                "critical": "var(--accent-red)",
                "high": "var(--accent-orange)",
                "medium": "var(--accent-yellow)",
                "low": "var(--accent-green)",
            }.get(sev_class, "var(--text-secondary)")
            bar_width = v.composite_score * 100

            html += f"""                <tr data-severity="{v.composite_severity.value}">
                    <td>{i + 1}</td>
                    <td><a href="https://nvd.nist.gov/vuln/detail/{v.cve_id}" target="_blank" style="color: var(--accent-blue); text-decoration: none;">{v.cve_id}</a></td>
                    <td>
                        {v.composite_score:.4f}
                        <div class="score-bar"><div class="score-bar-fill" style="width:{bar_width:.0f}%;background:{bar_color}"></div></div>
                    </td>
                    <td><span class="badge badge-{sev_class}">{v.composite_severity.value}</span></td>
                    <td>{v.cvss_v3_score:.1f}</td>
                    <td>{v.epss_score:.4f}</td>
                    <td>{v.affected_package}</td>
                    <td>{v.installed_version}</td>
                    <td>{v.fixed_version or '<span style="color:var(--accent-red)">No fix</span>'}</td>
                </tr>
"""

        html += """            </tbody>
        </table>

        <div class="footer">
            <p>Generated by EPSS-Augmented CVE Prioritization Framework v""" + result.framework_version + """</p>
            <p>Scoring: CompositeScore = w₁×normalize(CVSS) + w₂×EPSS + w₃×Reachability</p>
        </div>
    </div>

    <script>
        let currentSeverity = 'ALL';

        function filterTable() {
            const query = document.getElementById('searchBox').value.toLowerCase();
            const rows = document.querySelectorAll('#vulnTable tbody tr');
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                const sevMatch = currentSeverity === 'ALL' || row.dataset.severity === currentSeverity;
                row.style.display = (text.includes(query) && sevMatch) ? '' : 'none';
            });
        }

        function filterSeverity(severity, btn) {
            currentSeverity = severity;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            filterTable();
        }

        function sortTable(col) {
            const table = document.getElementById('vulnTable');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const isAsc = table.dataset.sortCol == col && table.dataset.sortDir === 'asc';

            rows.sort((a, b) => {
                let aVal = a.cells[col].textContent.trim();
                let bVal = b.cells[col].textContent.trim();
                const aNum = parseFloat(aVal);
                const bNum = parseFloat(bVal);
                if (!isNaN(aNum) && !isNaN(bNum)) {
                    return isAsc ? aNum - bNum : bNum - aNum;
                }
                return isAsc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
            });

            rows.forEach(row => tbody.appendChild(row));
            table.dataset.sortCol = col;
            table.dataset.sortDir = isAsc ? 'desc' : 'asc';
        }
    </script>
</body>
</html>"""

        with open(output_path, "w") as f:
            f.write(html)

        logger.info(f"[green]🌐 HTML report saved:[/green] {output_path}")
        return output_path
