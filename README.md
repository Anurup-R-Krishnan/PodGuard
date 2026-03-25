# EPSS-Augmented CVE Prioritization Framework

> **Multi-factor vulnerability triage for Docker container security** — combining CVSS severity, EPSS exploit probability, and runtime reachability analysis.

## 🛡️ Overview

The EPSS Framework scans Docker container images for vulnerabilities and produces **prioritized, composite risk scores** that go beyond simple CVSS severity. By integrating EPSS (Exploit Prediction Scoring System) data, the framework helps DevSecOps teams *fix what matters first* and dramatically reduce alert fatigue.

### Scoring Formula

```
CompositeScore = w₁ × normalize(CVSS) + w₂ × EPSS + w₃ × Reachability
```

- **w₁ (CVSS):** Theoretical severity impact (0-10, normalized)
- **w₂ (EPSS):** ML-predicted probability of exploitation within 30 days (0-1)
- **w₃ (Reachability):** Whether the vulnerable component is actually used at runtime (0 or 1)

## 📦 Installation

```bash
# Clone the repository
git clone <repo-url>
cd EPSS

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install with all dependencies
pip install -e ".[all]"

# Or just core dependencies
pip install -e .
```

### Prerequisites

- **Python 3.11+**
- **Trivy** (vulnerability scanner): [Install Trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/)
- **Docker** (for container image scanning)

## 🚀 Quick Start

### Scan a container image
```bash
epss-triage scan nginx:latest
```

### Custom weights
```bash
epss-triage scan ubuntu:22.04 --weights 0.3,0.5,0.2
```

### JSON output for CI/CD
```bash
epss-triage scan python:3.11 --json --format json
```

### Show framework info
```bash
epss-triage info
```

## 📊 Output

The framework generates:
- **JSON Reports:** Machine-readable structured vulnerability data
- **HTML Reports:** Interactive dark-themed dashboard with sortable tables, severity badges, and score visualizations

## 🏗️ Project Structure

```
epss_framework/
├── scanner/          # Trivy integration
├── enrichment/       # EPSS API client
├── reachability/     # Static analysis engine (Phase 2)
├── scoring/          # Composite scoring logic
├── ml/               # XGBoost model training (Phase 2)
├── reports/          # JSON/HTML report generation
├── pipeline/         # Pipeline orchestration
├── evaluation/       # NDCG@10 metrics (Phase 2)
├── config/           # Configuration management
├── utils/            # Shared data models & utilities
├── tests/            # Unit & integration tests
└── cli.py            # CLI application
```

## ⚙️ Configuration

Configure via environment variables:
```bash
export EPSS_WEIGHT_CVSS=0.4
export EPSS_WEIGHT_EPSS=0.4
export EPSS_WEIGHT_REACHABILITY=0.2
export EPSS_LOG_LEVEL=DEBUG
export EPSS_TRIVY_PATH=/usr/local/bin/trivy
```

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=epss_framework --cov-report=html

# Run specific test module
pytest epss_framework/tests/unit/test_scoring.py -v
```

## 📚 Developer Tooling

- `trivy.yaml` provides baseline scanner configuration.
- `.pre-commit-config.yaml` configures Ruff + mypy hooks.
- `mkdocs.yml` and `docs/` provide project documentation scaffolding.
- `CONTRIBUTING.md` defines contribution and quality-check workflow.

## 📜 License

MIT License
