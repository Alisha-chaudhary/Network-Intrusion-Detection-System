"""Response mechanisms for the NIDS (Project 3).

Provides simulated/defensive response actions for detected intrusions:
- Log the alert
- Console notification
- Simulated block/quarantine (no real firewall changes by default)
- Optional callback for integrating with a real firewall/SIEM
"""

from __future__ import annotations

from typing import Callable, Optional

try:  # package execution
    from src.rules import NidsAlert
except ImportError:  # direct execution
    from rules import NidsAlert


class ResponseEngine:
    """Executes response actions when an alert is triggered.

    By default, actions are logged and simulated only. No real firewall,
    network, or system changes are made unless an external callback is wired.
    """

    def __init__(
        self,
        block_ips: bool = False,
        external_callback: Optional[Callable[[NidsAlert], None]] = None,
    ) -> None:
        self.block_ips = block_ips
        self.external_callback = external_callback
        self.blocked_ips: set[str] = set()

    def respond(self, alert: NidsAlert) -> None:
        """Execute the configured response for an alert."""
        # 1. Always log
        alert.action_taken = "logged"

        # 2. Simulated block for high-severity alerts (if enabled)
        if self.block_ips and alert.severity == "High" and alert.src_ip:
            if alert.src_ip not in self.blocked_ips:
                self.blocked_ips.add(alert.src_ip)
                alert.action_taken = "logged + simulated_block"
                print(
                    f"[RESPONSE] Simulated block of {alert.src_ip} "
                    f"(High severity: {alert.alert})"
                )

        # 3. External callback (e.g., SIEM, firewall API, email)
        if self.external_callback is not None:
            try:
                self.external_callback(alert)
            except Exception as exc:  # keep responding on callback errors
                print(f"[!] External response callback error: {exc}")

    def get_blocked_ips(self) -> list[str]:
        """Return the list of currently simulated-blocked IPs."""
        return sorted(self.blocked_ips)
