"""Optional visualization for the NIDS (Project 3).

Generates an HTML dashboard and matplotlib graphs from alert CSV data.
Matplotlib and jinja2 are optional dependencies.
"""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path
from typing import Optional


def load_alerts(path: str) -> list[dict]:
    """Load alerts from a CSV file."""
    alerts: list[dict] = []
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                alerts.append(row)
    except FileNotFoundError:
        print(f"[!] Alert file not found: {path}")
    return alerts


def generate_dashboard(
    alerts_path: str,
    output_path: str = "nids_dashboard.html",
) -> None:
    """Generate a simple HTML dashboard from alert data."""
    alerts = load_alerts(alerts_path)

    total = len(alerts)
    by_severity = Counter(a.get("severity", "Unknown") for a in alerts)
    by_rule = Counter(a.get("rule_id", "Unknown") for a in alerts)
    by_protocol = Counter(a.get("protocol", "Unknown") for a in alerts)

    severity_rows = "\n".join(
        f"<tr><td>{sev}</td><td>{count}</td></tr>"
        for sev, count in by_severity.most_common()
    )
    rule_rows = "\n".join(
        f"<tr><td>{rid}</td><td>{count}</td></tr>"
        for rid, count in by_rule.most_common(10)
    )
    protocol_rows = "\n".join(
    f"<tr><td>{proto}</td><td>{count}</td></tr>"
    for proto, count in by_protocol.most_common()
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NIDS Detection Dashboard</title>
<style>
  body {{ font-family: Segoe UI, sans-serif; margin: 2rem; background: #f4f6f8; }}
  h1 {{ color: #1f2937; }}
  .card {{ background: #fff; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
  .stat {{ font-size: 2rem; font-weight: bold; color: #dc2626; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ border: 1px solid #e5e7eb; padding: 0.5rem; text-align: left; }}
  th {{ background: #f3f4f6; }}
</style>
</head>
<body>
  <h1>🚨 NIDS Detection Dashboard</h1>
  <div class="card">
    <h2>Overview</h2>
    <p><span class="stat">{total}</span> total alerts</p>
  </div>
  <div class="card">
    <h2>Alerts by Severity</h2>
    <table>
      <tr><th>Severity</th><th>Count</th></tr>
      {severity_rows}
    </table>
  </div>
  <div class="card">
    <h2>Top Triggered Rules</h2>
    <table>
      <tr><th>Rule ID</th><th>Count</th></tr>
      {rule_rows}
    </table>
  </div>
  <div class="card">
    <h2>Alerts by Protocol</h2>
    <table>
      <tr><th>Protocol</th><th>Count</th></tr>
      {protocol_rows}
    </table>
  </div>
  <div class="card">
    <h2>Recent Alerts</h2>
    <table>
      <tr><th>Time</th><th>Rule</th><th>Severity</th><th>Source</th><th>Destination</th><th>Alert</th></tr>
      {"".join(f"<tr><td>{a.get('timestamp','')}</td><td>{a.get('rule_id','')}</td><td>{a.get('severity','')}</td><td>{a.get('src_ip','')}:{a.get('src_port','')}</td><td>{a.get('dst_ip','')}:{a.get('dst_port','')}</td><td>{a.get('alert','')}</td></tr>" for a in alerts[-10:])}
    </table>
  </div>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    print(f"[*] Dashboard written to {output_path}")


def generate_graphs(
    alerts_path: str,
    output_dir: str = "graphs",
) -> None:
    """Generate matplotlib graphs from alert data (optional dependency)."""
    try:
        import matplotlib  # type: ignore

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt  # type: ignore
    except ImportError:
        print(
            "[!] matplotlib not installed. Install with: pip install matplotlib"
        )
        return

    alerts = load_alerts(alerts_path)
    if not alerts:
        print("[!] No alerts to graph.")
        return

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    by_severity = Counter(a.get("severity", "Unknown") for a in alerts)
    by_protocol = Counter(a.get("protocol", "Unknown") for a in alerts)

    # Severity bar chart
    plt.figure(figsize=(6, 4))
    plt.bar(by_severity.keys(), by_severity.values(), color=["#dc2626", "#f59e0b", "#3b82f6"])
    plt.title("Alerts by Severity")
    plt.xlabel("Severity")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(Path(output_dir) / "severity.png")
    plt.close()

    # Protocol pie chart
    plt.figure(figsize=(6, 4))
    plt.pie(by_protocol.values(), labels=by_protocol.keys(), autopct="%1.1f%%")
    plt.title("Alerts by Protocol")
    plt.tight_layout()
    plt.savefig(Path(output_dir) / "protocol.png")
    plt.close()

    print(f"[*] Graphs written to {output_dir}/")
