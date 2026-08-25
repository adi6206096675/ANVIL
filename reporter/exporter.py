# reporter/exporter.py
import json
import os
from datetime import datetime

class AnvilExporter:
    """
    Dual-Layer Exporter for the ANVIL AppSec Suite.
    Generates machine-readable JSON, OASIS SARIF v2.1.0 (for Gatekeeper CI/CD pipelines),
    and interactive dark-mode HTML dashboards (for Manual Threat Hunting).
    """
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def export_json(self, report_data: dict) -> str:
        """Exports complete machine-readable JSON telemetry."""
        filepath = os.path.join(self.output_dir, f"anvil_audit_{self.timestamp}.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)
        return filepath

    def export_html(self, report_data: dict) -> str:
        """Generates a comprehensive dark-mode HTML dashboard covering all 5 security engines."""
        filepath = os.path.join(self.output_dir, f"anvil_dashboard_{self.timestamp}.html")
        
        mode = report_data.get("mode", "MANUAL").upper()
        target = report_data.get("target", "N/A")
        timestamp = report_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        sast_items = report_data.get("sast", [])
        dast_items = report_data.get("dast", [])
        sca_items = report_data.get("sca", [])
        iac_items = report_data.get("iac", [])
        fuzzer_items = report_data.get("fuzzer", [])

        failed_dast = [d for d in dast_items if not d.get("passed", True)]
        total_vulns = len(sast_items) + len(sca_items) + len(iac_items) + len(fuzzer_items) + len(failed_dast)

        # Build Table Rows
        sast_rows = "".join(
            f"<tr><td><span class='badge {f.get('severity','INFO')}'>{f.get('severity','INFO')}</span></td>"
            f"<td>{f.get('type','Unknown')}</td>"
            f"<td>{f.get('file','N/A')}:{f.get('line','N/A')}</td>"
            f"<td>{f.get('detail','')}</td></tr>"
            for f in sast_items
        )

        dast_rows = "".join(
            f"<tr><td><span class='badge {'PASS' if f.get('passed', True) else 'FAIL'}'>{'PASS' if f.get('passed', True) else 'FAIL'}</span></td>"
            f"<td>{f.get('case_name', f.get('rule_id', 'Rule'))}</td>"
            f"<td>{f.get('status_code', 'N/A')}</td>"
            f"<td>{f.get('notes', f.get('payload', ''))}</td></tr>"
            for f in dast_items
        )

        sca_rows = "".join(
            f"<tr><td><span class='badge {f.get('severity','HIGH')}'>{f.get('severity','HIGH')}</span></td>"
            f"<td>{f.get('package','N/A')} ({f.get('version','N/A')})</td>"
            f"<td>{f.get('cve_id','N/A')}</td>"
            f"<td>{f.get('detail','')}</td></tr>"
            for f in sca_items
        )

        iac_rows = "".join(
            f"<tr><td><span class='badge {f.get('severity','HIGH')}'>{f.get('severity','HIGH')}</span></td>"
            f"<td>{f.get('rule_id','N/A')}</td>"
            f"<td>{f.get('file','N/A')}:{f.get('line',1)}</td>"
            f"<td>{f.get('detail','')}</td></tr>"
            for f in iac_items
        )

        fuzzer_rows = "".join(
            f"<tr><td><span class='badge CRITICAL'>CRITICAL</span></td>"
            f"<td>Exit Code {f.get('exit_code','N/A')}</td>"
            f"<td><code>{repr(f.get('payload',''))}</code></td>"
            f"<td>Execution Time: {f.get('exec_time', f.get('exec_time_ms', 0)):.2f}ms</td></tr>"
            for f in fuzzer_items
        )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ANVIL AppSec Dashboard - {mode}</title>
    <style>
        :root {{
            --bg: #0d1117; --panel: #161b22; --border: #30363d;
            --text: #c9d1d9; --accent: #58a6ff; --danger: #f85149;
            --warning: #ffa657; --success: #3fb950;
        }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: var(--bg); color: var(--text); margin: 0; padding: 24px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }}
        h1 {{ color: var(--accent); margin: 0; font-size: 1.8rem; }}
        .meta {{ color: #8b949e; font-size: 0.9rem; margin-top: 4px; }}
        .mode-tag {{ padding: 6px 12px; border-radius: 6px; font-weight: bold; font-size: 0.85rem; letter-spacing: 1px; background: #21262d; border: 1px solid var(--border); }}
        .mode-tag.GATEKEEPER {{ border-color: var(--danger); color: var(--danger); }}
        .mode-tag.MANUAL {{ border-color: var(--accent); color: var(--accent); }}
        
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }}
        .metric-card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }}
        .metric-num {{ font-size: 2rem; font-weight: bold; color: var(--accent); }}
        .metric-num.has-vulns {{ color: var(--danger); }}
        .metric-label {{ color: #8b949e; font-size: 0.8rem; text-transform: uppercase; margin-top: 4px; }}

        h2 {{ color: var(--accent); font-size: 1.2rem; border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-top: 32px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; background: var(--panel); border-radius: 6px; overflow: hidden; }}
        th, td {{ border: 1px solid var(--border); padding: 10px 14px; text-align: left; font-size: 0.9rem; }}
        th {{ background: #21262d; color: #8b949e; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.5px; }}
        code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; font-family: monospace; color: #f0f6fc; }}
        
        .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; display: inline-block; }}
        .badge.CRITICAL, .badge.FAIL {{ background: rgba(248, 81, 73, 0.15); color: var(--danger); border: 1px solid var(--danger); }}
        .badge.HIGH {{ background: rgba(255, 166, 87, 0.15); color: var(--warning); border: 1px solid var(--warning); }}
        .badge.PASS {{ background: rgba(63, 185, 80, 0.15); color: var(--success); border: 1px solid var(--success); }}
        .badge.INFO, .badge.LOW, .badge.MEDIUM {{ background: rgba(88, 166, 255, 0.15); color: var(--accent); border: 1px solid var(--accent); }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🛡️ ANVIL Security Dashboard</h1>
            <div class="meta">Target: <code>{target}</code> | Scan Time: {timestamp}</div>
        </div>
        <div class="mode-tag {mode}">MODE: {mode}</div>
    </div>

    <div class="metrics-grid">
        <div class="metric-card">
            <div class="metric-num {'has-vulns' if total_vulns > 0 else ''}">{total_vulns}</div>
            <div class="metric-label">Total Vulnerabilities</div>
        </div>
        <div class="metric-card"><div class="metric-num">{len(sast_items)}</div><div class="metric-label">SAST Flaws</div></div>
        <div class="metric-card"><div class="metric-num">{len(sca_items)}</div><div class="metric-label">SCA Risks</div></div>
        <div class="metric-card"><div class="metric-num">{len(iac_items)}</div><div class="metric-label">IaC Risks</div></div>
        <div class="metric-card"><div class="metric-num">{len(fuzzer_items)}</div><div class="metric-label">Process Crashes</div></div>
    </div>

    <h2>1. Static Code Analysis (SAST)</h2>
    <table>
        <tr><th>Severity</th><th>Vulnerability</th><th>Location</th><th>Details</th></tr>
        {sast_rows if sast_rows else "<tr><td colspan='4'>No static vulnerabilities detected.</td></tr>"}
    </table>

    <h2>2. Dynamic API Contract Testing (DAST)</h2>
    <table>
        <tr><th>Result</th><th>Test Case / Payload</th><th>HTTP Status</th><th>Notes</th></tr>
        {dast_rows if dast_rows else "<tr><td colspan='4'>No dynamic tests executed.</td></tr>"}
    </table>

    <h2>3. Supply Chain & Dependencies (SCA)</h2>
    <table>
        <tr><th>Severity</th><th>Package</th><th>CVE ID</th><th>Details</th></tr>
        {sca_rows if sca_rows else "<tr><td colspan='4'>No vulnerable dependencies detected.</td></tr>"}
    </table>

    <h2>4. Infrastructure-as-Code (IaC)</h2>
    <table>
        <tr><th>Severity</th><th>Rule ID</th><th>Location</th><th>Details</th></tr>
        {iac_rows if iac_rows else "<tr><td colspan='4'>No infrastructure misconfigurations detected.</td></tr>"}
    </table>

    <h2>5. Multi-Core Process Breaches</h2>
    <table>
        <tr><th>Severity</th><th>Fault Type</th><th>Crash Payload</th><th>Execution Telemetry</th></tr>
        {fuzzer_rows if fuzzer_rows else "<tr><td colspan='4'>No process breaches triggered. Target held.</td></tr>"}
    </table>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        return filepath

    def export_sarif(self, report_data: dict) -> str:
        """
        Exports all findings in strict OASIS SARIF v2.1.0 format.
        Powers automated Gatekeeper pipeline enforcement and enterprise SAST/DAST ingestion.
        """
        filepath = os.path.join(self.output_dir, "anvil_report.sarif")
        results = []

        # 1. Map SAST Findings
        for issue in report_data.get("sast", []):
            results.append({
                "ruleId": issue.get("type", "SAST-VULN").replace(" ", "-").upper(),
                "level": "error" if issue.get("severity") in ["CRITICAL", "HIGH"] else "warning",
                "message": {"text": issue.get("detail", "Static security vulnerability detected.")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": issue.get("file", "unknown")},
                        "region": {"startLine": issue.get("line", 1)}
                    }
                }]
            })

        # 2. Map IaC Misconfigurations
        for issue in report_data.get("iac", []):
            results.append({
                "ruleId": issue.get("rule_id", "IAC-MISCONFIG").upper(),
                "level": "error" if issue.get("severity") in ["CRITICAL", "HIGH"] else "warning",
                "message": {"text": issue.get("detail", "Infrastructure configuration risk detected.")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": issue.get("file", "Dockerfile")},
                        "region": {"startLine": issue.get("line", 1)}
                    }
                }]
            })

        # 3. Map SCA Supply Chain Vulnerabilities
        for issue in report_data.get("sca", []):
            results.append({
                "ruleId": issue.get("cve_id", "SCA-VULN").upper(),
                "level": "error" if issue.get("severity") in ["CRITICAL", "HIGH"] else "warning",
                "message": {"text": f"Dependency '{issue.get('package')}' ({issue.get('version')}): {issue.get('detail')}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": issue.get("manifest", "requirements.txt")},
                        "region": {"startLine": 1}
                    }
                }]
            })

        # 4. Map Fuzzer Process Breaches
        for issue in report_data.get("fuzzer", []):
            results.append({
                "ruleId": "ANVIL-PROCESS-CRASH",
                "level": "error",
                "message": {"text": f"Target process crashed with exit code {issue.get('exit_code')} when exposed to payload: {repr(issue.get('payload'))}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": report_data.get("target", "target_binary")},
                        "region": {"startLine": 1}
                    }
                }]
            })

        # Construct Official OASIS SARIF v2.1.0 Envelope
        sarif_log = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "ANVIL AppSec Suite",
                        "semanticVersion": "2.0.0",
                        "informationUri": "https://localhost/anvil",
                        "rules": []
                    }
                },
                "results": results
            }]
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(sarif_log, f, indent=4)

        return filepath