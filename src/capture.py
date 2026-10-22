"""Packet capture engine for the NIDS (Project 3).

Live packet capture using Scapy on Windows (Npcap) with:
- Interface listing and selection
- Configurable packet count / timeout
- BPF capture filters
- Graceful shutdown (Ctrl+C)
- Per-packet error handling
"""

from __future__ import annotations

import signal
from datetime import datetime
from typing import Callable, Optional

from scapy.all import conf, sniff, show_interfaces


class CaptureEngine:
    """Live packet capture engine built on Scapy."""

    def __init__(self) -> None:
        self.interface: Optional[str] = None
        self.packet_count: int = 0
        self._running = False
        self._stop_requested = False

    def list_interfaces(self) -> None:
        """Print available capture interfaces."""
        print("[*] Available network interfaces:")
        try:
            show_interfaces()
        except Exception as exc:  # pragma: no cover - environment dependent
            print(f"[!] Could not list interfaces: {exc}")
        print()

    def select_interface(self, interface: Optional[str] = None) -> str:
        """Select and return the capture interface."""
        if interface:
            self.interface = interface
        else:
            self.interface = conf.iface
        print(f"[*] Using interface: {self.interface}")
        return self.interface

    def capture(
        self,
        callback: Callable,
        count: int = 0,
        timeout: Optional[int] = None,
        bpf_filter: Optional[str] = None,
        store: bool = False,
    ) -> int:
        """Start live packet capture.

        Args:
            callback: Function called for every captured packet.
            count: Max packets to capture (0 = unlimited).
            timeout: Stop after N seconds (None = no timeout).
            bpf_filter: Optional BPF capture filter string.
            store: Whether Scapy retains packets in memory (False = stream).

        Returns:
            Number of packets processed.
        """
        self._running = True
        self._stop_requested = False
        self.packet_count = 0

        def wrapped(pkt) -> None:
            try:
                callback(pkt)
                self.packet_count += 1
            except Exception as exc:  # keep capturing on per-packet errors
                print(f"[!] Packet processing error: {exc}")

        def stop_filter(_pkt) -> bool:
            return self._stop_requested

        def handler(signum, frame):  # noqa: ARG001
            self._stop_requested = True
            print("\n[!] Stop requested. Finishing gracefully...")

        signal.signal(signal.SIGINT, handler)

        print(
            f"[*] NIDS capture starting "
            f"(count={count or 'unlimited'}, "
            f"timeout={timeout or 'none'}, "
            f"filter='{bpf_filter or 'none'}')"
        )
        print("[*] Press Ctrl+C to stop.\n")

        try:
            sniff(
                iface=self.interface,
                prn=wrapped,
                stop_filter=stop_filter,
                count=count,
                timeout=timeout,
                filter=bpf_filter,
                store=store,
            )
        except KeyboardInterrupt:
            print("\n[!] Capture interrupted by user.")
        except PermissionError:
            print(
                "[!] Permission denied: run as Administrator "
                "(Npcap requires elevated privileges on Windows)."
            )
            raise
        except OSError as exc:
            print(f"[!] Capture error on interface '{self.interface}': {exc}")
            raise
        finally:
            self._running = False
            print(
                f"\n[*] NIDS capture complete. Packets processed: {self.packet_count}"
            )

        return self.packet_count

    def stop(self) -> None:
        """Request a graceful stop of the running capture."""
        self._stop_requested = True
