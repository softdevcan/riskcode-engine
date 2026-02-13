"""HTML report generator for RiskCodeAI.

Generates a self-contained, single-file HTML security report
with inline CSS. Uses Jinja2 templating.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from riskcode_shared.types.models import (
    DependencyGraph,
    ScanResult,
    VulnerabilityInfo,
)

logger = logging.getLogger(__name__)

# ─── Inline HTML template (no external files needed) ─────────────────────────

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RiskCodeAI Security Report — {{ project_name }}</title>
<style>
:root {
  --bg: #0f172a;
  --surface: #1e293b;
  --card: #334155;
  --border: #475569;
  --text: #e2e8f0;
  --text-muted: #94a3b8;
  --accent: #38bdf8;
  --critical: #ef4444;
  --high: #f97316;
  --medium: #eab308;
  --low: #22c55e;
  --font: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: var(--font);
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
  min-height: 100vh;
}
.container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
h1 { font-size: 1.8rem; font-weight: 700; margin-bottom: 0.5rem; }
h2 { font-size: 1.3rem; font-weight: 600; margin-bottom: 1rem; color: var(--accent); }
h3 { font-size: 1.1rem; font-weight: 600; margin-bottom: 0.5rem; }

/* Header */
.header {
  background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 2rem;
  margin-bottom: 2rem;
}
.header .subtitle { color: var(--text-muted); font-size: 0.9rem; }
.header .timestamp { color: var(--accent); font-size: 0.85rem; margin-top: 0.5rem; }

/* Stat Cards */
.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}
.stat-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1.25rem;
  text-align: center;
  transition: transform 0.2s;
}
.stat-card:hover { transform: translateY(-2px); }
.stat-card .value {
  font-size: 2rem;
  font-weight: 700;
  display: block;
  margin-bottom: 0.25rem;
}
.stat-card .label {
  color: var(--text-muted);
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

/* Severity badge */
.badge {
  display: inline-block;
  padding: 0.2em 0.6em;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.badge-critical { background: var(--critical); color: #fff; }
.badge-high { background: var(--high); color: #fff; }
.badge-medium { background: var(--medium); color: #1a1a1a; }
.badge-low { background: var(--low); color: #1a1a1a; }

/* Severity bar */
.severity-bar {
  display: flex;
  border-radius: 6px;
  overflow: hidden;
  height: 12px;
  margin-bottom: 2rem;
  background: var(--card);
}
.severity-bar div { transition: width 0.5s ease; }
.sev-critical { background: var(--critical); }
.sev-high { background: var(--high); }
.sev-medium { background: var(--medium); }
.sev-low { background: var(--low); }

/* Tables */
table {
  width: 100%;
  border-collapse: collapse;
  margin-bottom: 2rem;
  background: var(--surface);
  border-radius: 10px;
  overflow: hidden;
}
th {
  background: var(--card);
  padding: 0.75rem 1rem;
  text-align: left;
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
}
td {
  padding: 0.75rem 1rem;
  border-bottom: 1px solid rgba(71, 85, 105, 0.3);
  font-size: 0.9rem;
}
tr:last-child td { border-bottom: none; }
tr:hover { background: rgba(56, 189, 248, 0.05); }

/* Vuln cards */
.vuln-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1.25rem;
  margin-bottom: 1rem;
  border-left: 4px solid var(--border);
  transition: border-color 0.2s;
}
.vuln-card:hover { border-left-color: var(--accent); }
.vuln-card.critical { border-left-color: var(--critical); }
.vuln-card.high { border-left-color: var(--high); }
.vuln-card.medium { border-left-color: var(--medium); }
.vuln-card.low { border-left-color: var(--low); }
.vuln-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.75rem;
}
.vuln-title { font-weight: 600; }
.vuln-meta { color: var(--text-muted); font-size: 0.85rem; }
.vuln-scores {
  display: flex;
  gap: 1rem;
  margin: 0.75rem 0;
}
.score-pill {
  background: var(--card);
  padding: 0.3em 0.8em;
  border-radius: 20px;
  font-size: 0.8rem;
}
.vuln-summary, .vuln-recommendation {
  margin-top: 0.75rem;
  padding: 0.75rem;
  background: var(--card);
  border-radius: 6px;
  font-size: 0.85rem;
  line-height: 1.5;
}
.vuln-recommendation { border-left: 3px solid var(--accent); }

/* Section */
.section {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.5rem;
  margin-bottom: 2rem;
}

/* Footer */
.footer {
  text-align: center;
  color: var(--text-muted);
  padding: 2rem;
  font-size: 0.8rem;
}
.footer a { color: var(--accent); text-decoration: none; }
</style>
</head>
<body>
<div class="container">

<!-- Header -->
<div class="header">
  <h1>🛡️ RiskCodeAI Security Report</h1>
  <div class="subtitle">{{ project_name }}</div>
  <div class="timestamp">Scanned at: {{ scanned_at }} | Scan ID: {{ scan_id }}</div>
</div>

<!-- Stats -->
<div class="stats">
  <div class="stat-card">
    <span class="value">{{ total_deps }}</span>
    <span class="label">Dependencies</span>
  </div>
  <div class="stat-card">
    <span class="value" style="color: {% if total_vulns > 0 %}var(--high){% else %}var(--low){% endif %}">{{ total_vulns }}</span>
    <span class="label">Vulnerabilities</span>
  </div>
  <div class="stat-card">
    <span class="value" style="color: var(--critical)">{{ critical_count }}</span>
    <span class="label">Critical</span>
  </div>
  <div class="stat-card">
    <span class="value" style="color: var(--high)">{{ high_count }}</span>
    <span class="label">High</span>
  </div>
  <div class="stat-card">
    <span class="value" style="color: var(--medium)">{{ medium_count }}</span>
    <span class="label">Medium</span>
  </div>
  <div class="stat-card">
    <span class="value" style="color: var(--low)">{{ low_count }}</span>
    <span class="label">Low</span>
  </div>
</div>

<!-- Severity Distribution Bar -->
{% if total_vulns > 0 %}
<div class="severity-bar">
  {% if critical_count > 0 %}<div class="sev-critical" style="width: {{ (critical_count / total_vulns * 100)|round(1) }}%"></div>{% endif %}
  {% if high_count > 0 %}<div class="sev-high" style="width: {{ (high_count / total_vulns * 100)|round(1) }}%"></div>{% endif %}
  {% if medium_count > 0 %}<div class="sev-medium" style="width: {{ (medium_count / total_vulns * 100)|round(1) }}%"></div>{% endif %}
  {% if low_count > 0 %}<div class="sev-low" style="width: {{ (low_count / total_vulns * 100)|round(1) }}%"></div>{% endif %}
</div>
{% endif %}

<!-- Vulnerabilities -->
{% if vulnerabilities %}
<h2>🔴 Vulnerabilities ({{ total_vulns }})</h2>
{% for v in vulnerabilities %}
<div class="vuln-card {{ v.severity }}">
  <div class="vuln-header">
    <div>
      <span class="vuln-title">{{ v.osv_id }}</span>
      {% if v.cve_id %}<span class="vuln-meta"> · {{ v.cve_id }}</span>{% endif %}
    </div>
    <span class="badge badge-{{ v.severity }}">{{ v.severity }}</span>
  </div>
  <div class="vuln-meta">📦 {{ v.package }} {% if v.fixed_version %}· Fix: <strong>{{ v.fixed_version }}</strong>{% endif %}</div>
  <div class="vuln-scores">
    <span class="score-pill">CVSS {{ v.cvss_score }}</span>
    {% if v.risk_score > 0 %}<span class="score-pill">Risk {{ v.risk_score }}</span>{% endif %}
  </div>
  {% if v.summary %}<div class="vuln-summary">{{ v.summary }}</div>{% endif %}
  {% if v.ai_summary %}
  <div class="vuln-recommendation">💡 <strong>AI Insight:</strong> {{ v.ai_summary }}</div>
  {% endif %}
  {% if v.update_recommendation %}
  <div class="vuln-recommendation">📋 <strong>Recommendation:</strong> {{ v.update_recommendation }}</div>
  {% endif %}
  {% if v.breaking_changes %}
  <div class="vuln-recommendation" style="border-left-color: var(--high)">
    ⚠️ <strong>Breaking Changes:</strong>
    <ul style="margin-top: 0.5rem; padding-left: 1.2rem;">
      {% for bc in v.breaking_changes %}<li>{{ bc }}</li>{% endfor %}
    </ul>
  </div>
  {% endif %}
</div>
{% endfor %}
{% else %}
<div class="section">
  <h2>✅ No Vulnerabilities Found</h2>
  <p>All {{ total_deps }} dependencies are clear of known vulnerabilities.</p>
</div>
{% endif %}

<!-- Dependencies -->
<div class="section">
  <h2>📦 Dependencies ({{ total_deps }})</h2>
  <table>
    <thead>
      <tr>
        <th>Package</th>
        <th>Version</th>
        <th>Type</th>
        <th>Scope</th>
        <th>Ecosystem</th>
      </tr>
    </thead>
    <tbody>
      {% for d in dependencies %}
      <tr>
        <td><strong>{{ d.name }}</strong></td>
        <td>{{ d.version }}</td>
        <td>{{ "Direct" if d.is_direct else "Transitive" }}</td>
        <td>{{ "Dev" if d.is_dev else "Production" }}</td>
        <td>{{ d.ecosystem }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

</div>

<!-- Footer -->
<div class="footer">
  Generated by <a href="https://github.com/riskcodeai">RiskCodeAI</a> · {{ generated_at }}
</div>

</body>
</html>
"""


class HTMLReportGenerator:
    """Generates self-contained HTML security reports.

    Uses Jinja2 for template rendering. Reports include:
    - Summary dashboard with severity stats
    - Vulnerability cards with risk scores and AI insights
    - Full dependency table
    """

    def generate(
        self,
        result: ScanResult,
        risk_scores: dict[str, float] | None = None,
    ) -> str:
        """Generate an HTML report from scan results.

        Args:
            result: Complete scan result.
            risk_scores: Optional mapping of osv_id → risk score.

        Returns:
            Self-contained HTML string.
        """
        try:
            from jinja2 import Environment
        except ImportError:
            logger.error(
                "Jinja2 is required for HTML reports. "
                "Install it with: pip install jinja2"
            )
            raise ImportError(
                "jinja2 is required for HTML report generation. "
                "Run: pip install jinja2"
            )

        env = Environment(autoescape=True)
        template = env.from_string(_HTML_TEMPLATE)

        # Prepare vulnerability data
        vuln_data = []
        for v in result.vulnerabilities:
            vuln_data.append({
                "osv_id": v.osv_id,
                "cve_id": v.cve_id,
                "severity": v.severity.value,
                "cvss_score": v.cvss_score,
                "risk_score": risk_scores.get(v.osv_id, v.risk_score) if risk_scores else v.risk_score,
                "package": v.affected_dependency or "Unknown",
                "summary": v.summary,
                "fixed_version": v.fixed_version,
                "ai_summary": v.ai_summary,
                "update_recommendation": v.update_recommendation,
                "breaking_changes": v.breaking_changes,
            })

        # Sort by severity then CVSS
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        vuln_data.sort(
            key=lambda x: (severity_order.get(x["severity"], 5), -x["cvss_score"])
        )

        # Prepare dependency data
        dep_data = []
        if result.dependency_graph:
            for d in result.dependency_graph.dependencies:
                dep_data.append({
                    "name": d.name,
                    "version": d.version_constraint.raw,
                    "is_direct": d.is_direct,
                    "is_dev": d.is_dev,
                    "ecosystem": d.ecosystem.value,
                })

        # Vulnerability counts
        vuln_summary = result.vulnerability_summary()

        context = {
            "project_name": result.project_name,
            "scan_id": str(result.id)[:8],
            "scanned_at": result.scanned_at.strftime("%Y-%m-%d %H:%M"),
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "total_deps": len(dep_data),
            "total_vulns": vuln_summary.get("total", 0),
            "critical_count": vuln_summary.get("critical", 0),
            "high_count": vuln_summary.get("high", 0),
            "medium_count": vuln_summary.get("medium", 0),
            "low_count": vuln_summary.get("low", 0),
            "vulnerabilities": vuln_data,
            "dependencies": dep_data,
        }

        return template.render(**context)

    def generate_to_file(
        self,
        result: ScanResult,
        output_path: str,
        risk_scores: dict[str, float] | None = None,
    ) -> str:
        """Generate HTML report and write to file.

        Args:
            result: Scan result data.
            output_path: File path for the HTML report.
            risk_scores: Optional risk score mapping.

        Returns:
            The output file path.
        """
        html = self.generate(result, risk_scores)

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding="utf-8")

        logger.info("HTML report written to: %s", output_path)
        return str(path.resolve())
