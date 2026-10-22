"""NIDS - Network Intrusion Detection System (Project 3).

CLI entry point for live intrusion detection using Scapy (Npcap on Windows).

Usage:
    python src/main.py
    python src/main.py -r rules/snort_rules.rules -o alerts.csv
    python src/main.py --block --dashboard samples/sample_dashboard.html
"""

from __future__ import annotations

import argparse
import sys

try:  # package execution
    from src.capture import CaptureEngine
    from src.rules import load_rules, evaluate_packet
    from src.alerts import AlertLogger
    from src.response import ResponseEngine
    from src.visualize import generate_dashboard, generate_graphs
except ImportError:  # direct execution: python src/main.py
    from capture import CaptureEngine
    from rules import load_rules, evaluate_packet
    from alerts import AlertLogger
    from response import ResponseEngine
    from visualize import generate_dashboard, generate_graphs


def run() -> int:
    parser = argparse.ArgumentParser(
        description="NIDS: network intrusion detection system"
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Capture interface (default: Scapy default)",
    )
    parser.add_argument(
        "-r",
        "--rules",
        default="rules/snort_rules.rules",
        help="Snort-format rule file (default: rules/snort_rules.rules)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="nids_alerts.csv",
        help="Alert CSV output path (default: nids_alerts.csv)",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Max packets to capture (0 = unlimited)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=None,
        help="Stop capturing after N seconds",
    )
    parser.add_argument(
        "--block",
        action="store_true",
        help="Enable simulated blocking of high-severity source IPs",
    )
    parser.add_argument(
        "--dashboard",
        metavar="HTML_PATH",
        help="Generate HTML dashboard after capture (requires alert CSV)",
    )
    parser.add_argument(
        "--graphs",
        metavar="DIR",
        help="Generate matplotlib graphs into DIR after capture",
    )
    args = parser.parse_args()

    rules = load_rules(args.rules)
    print(f"[*] Loaded {len(rules)} detection rules from {args.rules}")

    engine = CaptureEngine()
    engine.list_interfaces()
    engine.select_interface(args.interface)

    logger = AlertLogger(path=args.output)
    responder = ResponseEngine(block_ips=args.block)

    def on_packet(pkt) -> None:
        alert = evaluate_packet(pkt, rules)
        if alert is not None:
            responder.respond(alert)
            logger.log(alert)

    try:
        with logger:
            engine.capture(
                callback=on_packet,
                count=args.count,
                timeout=args.timeout,
            )
    except KeyboardInterrupt:
        print("\n[!] NIDS stopped by user.")
    except PermissionError:
        print(
            "[!] Run as Administrator (Npcap requires elevated privileges "
            "on Windows)."
        )
        return 1
    except OSError as exc:
        print(f"[!] Capture failed: {exc}")
        return 1
    finally:
        print("\n" + logger.summary())
        if responder.get_blocked_ips():
            print(f"[*] Simulated-blocked IPs: {', '.join(responder.get_blocked_ips())}")

    # Optional post-capture visualization
    if args.dashboard:
        generate_dashboard(args.output, args.dashboard)
    if args.graphs:
        generate_graphs(args.output, args.graphs)

    return 0


if __name__ == "__main__":
    sys.exit(run())
