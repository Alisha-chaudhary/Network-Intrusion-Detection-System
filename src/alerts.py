"""Alert generation and logging for the NIDS (Project 3).

Writes alerts to CSV and maintains detection statistics.
"""

from __future__ import annotations

import csv
import os
from collections import Counter
from typing import Iterable, Optional

try:  # package execution
    from src.rules import NidsAlert
except ImportError:  # direct execution
    from rules import NidsAlert


class AlertLogger:
    """Logs NIDS alerts to CSV and maintains detection statistics."""

    FIELDNAMES = [
        "timestamp",
        "rule_id",
        "severity",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "alert",
        "action_taken",
    ]

    def __init__(self, path: str = "nids_alerts.csv") -> None:
        self.path = path
        self.severity_counts: Counter[str] = Counter()
        self.rule_counts: Counter[str] = Counter()
        self.alert_count: int = 0
        self._file = None
        self._writer = None
        self._opened = False

    def open(self) -> None:
        """Open the CSV file and write the header row if needed."""
        if self._opened:
            return
        new_file = (
            not os.path.exists(self.path)
            or os.path.getsize(self.path) == 0
        )
        self._file = open(self.path, mode="a", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._file, fieldnames=self.FIELDNAMES)
        if new_file:
            self._writer.writeheader()
        self._opened = True

    def log(self, alert: NidsAlert) -> None:
        """Write one alert to the CSV and update statistics."""
        self.open()
        assert self._writer is not None
        row = {
            "timestamp": alert.timestamp,
            "rule_id": alert.rule_id,
            "severity": alert.severity,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "src_port": alert.src_port,
            "dst_port": alert.dst_port,
            "protocol": alert.protocol,
            "alert": alert.alert,
            "action_taken": alert.action_taken,
        }
        self._writer.writerow(row)
        self.severity_counts[alert.severity] += 1
        self.rule_counts[alert.rule_id] += 1
        self.alert_count += 1
        print(
            f"[!] ALERT [{alert.severity}] {alert.rule_id}: {alert.alert} "
            f"({alert.src_ip} -> {alert.dst_ip})"
        )

    def log_batch(self, alerts: Iterable[NidsAlert]) -> None:
        """Log multiple alerts efficiently."""
        for alrt in alerts:
            self.log(alrt)

    def summary(self) -> str:
        """Return a human-readable detection summary."""
        lines = [
            "=== NIDS Detection Summary ===",
            f"Total alerts:  {self.alert_count}",
            "Severity breakdown:",
        ]
        if self.severity_counts:
            for sev, count in self.severity_counts.most_common():
                lines.append(f"  - {sev}: {count}")
        else:
            lines.append("  (none)")
        lines.append("Top triggered rules:")
        if self.rule_counts:
            for rule_id, count in self.rule_counts.most_common(5):
                lines.append(f"  - {rule_id}: {count}")
        else:
            lines.append("  (none)")
        lines.append(f"Alert log: {self.path}")
        return "\n".join(lines)

    def close(self) -> None:
        """Close the CSV file if open."""
        if self._file is not None and not self._file.closed:
            self._file.close()
        self._opened = False

    def __enter__(self) -> "AlertLogger":
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
