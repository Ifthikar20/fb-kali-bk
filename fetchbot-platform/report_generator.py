"""FetchBot.ai Report Generator - Professional Security Reports"""
import json
from typing import Dict, List
from datetime import datetime
from collections import Counter


class ReportGenerator:
    def __init__(self):
        self.severity_colors = {
            'critical': '#d32f2f',
            'high': '#f57c00',
            'medium': '#fbc02d',
            'low': '#388e3c',
            'info': '#1976d2'
        }

    def generate_html_report(self, pentest_data: Dict) -> str:
        """Generate professional HTML security report"""

        findings = pentest_data.get('findings', [])
        target = pentest_data.get('target', 'Unknown')
        analysis = pentest_data.get('analysis', '')
        timestamp = pentest_data.get('timestamp', datetime.utcnow().isoformat())

        # Count findings by severity
        severity_counts = Counter(f.get('severity', 'unknown') for f in findings)

        # Group findings
        findings_by_severity = {
            'critical': [f for f in findings if f.get('severity') == 'critical'],
            'high': [f for f in findings if f.get('severity') == 'high'],
            'medium': [f for f in findings if f.get('severity') == 'medium'],
            'low': [f for f in findings if f.get('severity') == 'low'],
            'info': [f for f in findings if f.get('severity') == 'info']
        }

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FetchBot.ai Security Report - {target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}

        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}

        .summary {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .summary h2 {{
            color: #667eea;
            margin-bottom: 20px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}

        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}

        .stat-card {{
            background: #f9f9f9;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid;
        }}

        .stat-card.critical {{ border-color: {self.severity_colors['critical']}; }}
        .stat-card.high {{ border-color: {self.severity_colors['high']}; }}
        .stat-card.medium {{ border-color: {self.severity_colors['medium']}; }}
        .stat-card.low {{ border-color: {self.severity_colors['low']}; }}
        .stat-card.info {{ border-color: {self.severity_colors['info']}; }}

        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
        }}

        .stat-card .label {{
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            margin-top: 5px;
        }}

        .analysis {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .analysis h2 {{
            color: #667eea;
            margin-bottom: 20px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}

        .analysis p {{
            margin-bottom: 15px;
            line-height: 1.8;
        }}

        .findings {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .findings h2 {{
            color: #667eea;
            margin-bottom: 20px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}

        .severity-section {{
            margin-bottom: 30px;
        }}

        .severity-section h3 {{
            margin-bottom: 15px;
            padding: 10px;
            border-radius: 5px;
            color: white;
        }}

        .severity-section.critical h3 {{ background: {self.severity_colors['critical']}; }}
        .severity-section.high h3 {{ background: {self.severity_colors['high']}; }}
        .severity-section.medium h3 {{ background: {self.severity_colors['medium']}; }}
        .severity-section.low h3 {{ background: {self.severity_colors['low']}; }}
        .severity-section.info h3 {{ background: {self.severity_colors['info']}; }}

        .finding {{
            background: #f9f9f9;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid;
        }}

        .finding.critical {{ border-color: {self.severity_colors['critical']}; }}
        .finding.high {{ border-color: {self.severity_colors['high']}; }}
        .finding.medium {{ border-color: {self.severity_colors['medium']}; }}
        .finding.low {{ border-color: {self.severity_colors['low']}; }}
        .finding.info {{ border-color: {self.severity_colors['info']}; }}

        .finding h4 {{
            color: #333;
            margin-bottom: 10px;
        }}

        .finding .meta {{
            display: flex;
            gap: 15px;
            margin-bottom: 10px;
            font-size: 0.9em;
            color: #666;
        }}

        .finding .meta span {{
            background: #e0e0e0;
            padding: 3px 10px;
            border-radius: 3px;
        }}

        .finding .description {{
            margin-top: 10px;
            color: #555;
        }}

        .finding .evidence {{
            background: #fff;
            padding: 10px;
            margin-top: 10px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9em;
            border: 1px solid #ddd;
        }}

        .footer {{
            background: #333;
            color: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            margin-top: 30px;
        }}

        .footer p {{
            margin-bottom: 5px;
        }}

        @media print {{
            .container {{
                max-width: 100%;
            }}
            .header, .summary, .findings, .analysis {{
                box-shadow: none;
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🤖 FetchBot.ai Security Report</h1>
            <div class="subtitle">AI-Powered Penetration Testing Platform</div>
            <div class="subtitle" style="margin-top: 10px;">Target: {target}</div>
            <div class="subtitle">Report Generated: {timestamp}</div>
        </div>

        <div class="summary">
            <h2>Executive Summary</h2>
            <p><strong>Total Findings:</strong> {len(findings)}</p>
            <div class="stats">
                <div class="stat-card critical">
                    <div class="number">{severity_counts.get('critical', 0)}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="number">{severity_counts.get('high', 0)}</div>
                    <div class="label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="number">{severity_counts.get('medium', 0)}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="number">{severity_counts.get('low', 0)}</div>
                    <div class="label">Low</div>
                </div>
                <div class="stat-card info">
                    <div class="number">{severity_counts.get('info', 0)}</div>
                    <div class="label">Info</div>
                </div>
            </div>
        </div>

        <div class="analysis">
            <h2>AI Security Analysis</h2>
            <div style="white-space: pre-wrap;">{analysis}</div>
        </div>

        <div class="findings">
            <h2>Detailed Findings</h2>
"""

        # Add findings by severity
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            severity_findings = findings_by_severity.get(severity, [])

            if severity_findings:
                html += f"""
            <div class="severity-section {severity}">
                <h3>{severity.upper()} Severity ({len(severity_findings)} findings)</h3>
"""

                for finding in severity_findings:
                    title = finding.get('title', 'Unknown Finding')
                    description = finding.get('description', '')
                    f_type = finding.get('type', 'unknown')
                    discovered_by = finding.get('discovered_by', 'unknown')
                    url = finding.get('url', '')
                    payload = finding.get('payload', '')
                    evidence = finding.get('evidence', '')

                    html += f"""
                <div class="finding {severity}">
                    <h4>{title}</h4>
                    <div class="meta">
                        <span>Type: {f_type}</span>
                        <span>Discovered by: {discovered_by}</span>
                    </div>
"""

                    if url:
                        html += f'<div class="meta"><span>URL: {url}</span></div>'

                    if description:
                        html += f'<div class="description">{description}</div>'

                    if payload:
                        html += f'<div class="evidence"><strong>Payload:</strong> {payload}</div>'

                    if evidence:
                        html += f'<div class="evidence"><strong>Evidence:</strong> {evidence}</div>'

                    html += """
                </div>
"""

                html += """
            </div>
"""

        html += f"""
        </div>

        <div class="footer">
            <p><strong>FetchBot.ai</strong> - AI-Powered Security Testing Platform</p>
            <p>Report generated at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p>For questions or support, contact: admin@fetchbot.ai</p>
        </div>
    </div>
</body>
</html>
"""

        return html

    def generate_json_report(self, pentest_data: Dict) -> str:
        """Generate JSON report"""
        return json.dumps(pentest_data, indent=2)

    def generate_markdown_report(self, pentest_data: Dict) -> str:
        """Generate Markdown report"""

        findings = pentest_data.get('findings', [])
        target = pentest_data.get('target', 'Unknown')
        analysis = pentest_data.get('analysis', '')
        timestamp = pentest_data.get('timestamp', datetime.utcnow().isoformat())

        severity_counts = Counter(f.get('severity', 'unknown') for f in findings)

        findings_by_severity = {
            'critical': [f for f in findings if f.get('severity') == 'critical'],
            'high': [f for f in findings if f.get('severity') == 'high'],
            'medium': [f for f in findings if f.get('severity') == 'medium'],
            'low': [f for f in findings if f.get('severity') == 'low'],
            'info': [f for f in findings if f.get('severity') == 'info']
        }

        md = f"""# FetchBot.ai Security Report

**Target:** {target}
**Report Generated:** {timestamp}

---

## Executive Summary

**Total Findings:** {len(findings)}

| Severity | Count |
|----------|-------|
| Critical | {severity_counts.get('critical', 0)} |
| High     | {severity_counts.get('high', 0)} |
| Medium   | {severity_counts.get('medium', 0)} |
| Low      | {severity_counts.get('low', 0)} |
| Info     | {severity_counts.get('info', 0)} |

---

## AI Security Analysis

{analysis}

---

## Detailed Findings

"""

        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            severity_findings = findings_by_severity.get(severity, [])

            if severity_findings:
                md += f"\n### {severity.upper()} Severity ({len(severity_findings)} findings)\n\n"

                for i, finding in enumerate(severity_findings, 1):
                    title = finding.get('title', 'Unknown Finding')
                    description = finding.get('description', '')
                    f_type = finding.get('type', 'unknown')
                    discovered_by = finding.get('discovered_by', 'unknown')
                    url = finding.get('url', '')
                    payload = finding.get('payload', '')

                    md += f"#### {i}. {title}\n\n"
                    md += f"- **Type:** {f_type}\n"
                    md += f"- **Discovered by:** {discovered_by}\n"

                    if url:
                        md += f"- **URL:** {url}\n"

                    if description:
                        md += f"\n{description}\n"

                    if payload:
                        md += f"\n**Payload:** `{payload}`\n"

                    md += "\n---\n\n"

        md += f"""
---

**FetchBot.ai** - AI-Powered Security Testing Platform
Report generated at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
"""

        return md
