"""Detection rule engine for the NIDS (Project 3).

Parses Snort-format rule files and evaluates packets against them.
Rule format (Snort-compatible):

    alert tcp any any -> any 22 (msg:"SSH brute force"; sid:1000001; rev:1;)

Design principles:
- Never assume every packet contains every layer.
- Gracefully handle malformed rules.
- Return plain dataclass records for alerts and tests.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Packet


@dataclass
class NidsRule:
    """A parsed detection rule."""

    action: str = "alert"
    protocol: str = "any"
    src_ip: str = "any"
    src_port: str = "any"
    direction: str = "->"
    dst_ip: str = "any"
    dst_port: str = "any"
    msg: str = ""
    sid: int = 0
    rev: int = 1
    threshold: Optional[int] = None  # count within window
    threshold_window: Optional[int] = None  # seconds
    raw: str = ""


@dataclass
class NidsAlert:
    """A generated alert record."""

    timestamp: str = ""
    rule_id: str = ""
    severity: str = "Medium"
    src_ip: str = ""
    dst_ip: str = ""
    src_port: str = ""
    dst_port: str = ""
    protocol: str = ""
    alert: str = ""
    action_taken: str = "logged"


def _format_timestamp(pkt: Packet) -> str:
    try:
        t = pkt.time
        from datetime import datetime

        if isinstance(t, datetime):
            return t.strftime("%H:%M:%S.%f")[:-3]
        return datetime.fromtimestamp(float(t)).strftime("%H:%M:%S.%f")[:-3]
    except (AttributeError, TypeError, ValueError):
        return ""


def parse_snort_rule(line: str) -> Optional[NidsRule]:
    """Parse a single Snort-format rule line into an NidsRule.

    Returns None for comments, empty lines, or unparseable rules.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Minimal Snort parser: action proto src srcport -> dst dstport (options)
    pattern = (
        r"^(?P<action>alert|drop|pass|reject)\s+"
        r"(?P<proto>\w+)\s+"
        r"(?P<src_ip>[^/\s]+)\s+"
        r"(?P<src_port>[^/\s]+)\s+"
        r"(?P<dir>[<>-]+)\s+"
        r"(?P<dst_ip>[^/\s]+)\s+"
        r"(?P<dst_port>[^/\s]+)\s+"
        r"\((?P<options>.*)\)\s*$"
    )
    match = re.match(pattern, line)
    if not match:
        return None

    groups = match.groupdict()
    rule = NidsRule(
        action=groups["action"],
        protocol=groups["proto"],
        src_ip=groups["src_ip"],
        src_port=groups["src_port"],
        direction=groups["dir"],
        dst_ip=groups["dst_ip"],
        dst_port=groups["dst_port"],
        raw=line,
    )

    # Parse options: key:"value"; key:value;
    option_pattern = re.compile(r'(\w+):(?:"([^"]*)"|([^;]*));')
    for opt in option_pattern.finditer(groups["options"]):
        key = opt.group(1)
        value = opt.group(2) if opt.group(2) is not None else opt.group(3)
        if key == "msg":
            rule.msg = value
        elif key == "sid":
            try:
                rule.sid = int(value)
            except ValueError:
                pass
        elif key == "rev":
            try:
                rule.rev = int(value)
            except ValueError:
                pass
        elif key == "threshold":
            # threshold: count N, seconds W
            parts = [p.strip() for p in value.split(",")]
            for part in parts:
                if part.startswith("count:"):
                    try:
                        rule.threshold = int(part.split(":")[1])
                    except (IndexError, ValueError):
                        pass
                elif part.startswith("seconds:"):
                    try:
                        rule.threshold_window = int(part.split(":")[1])
                    except (IndexError, ValueError):
                        pass

    return rule


def load_rules(path: str) -> list[NidsRule]:
    """Load rules from a Snort-format .rules file."""
    rules: list[NidsRule] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                rule = parse_snort_rule(line)
                if rule is not None:
                    rules.append(rule)
    except FileNotFoundError:
        print(f"[!] Rule file not found: {path}")
    return rules


def _matches_field(pkt_value: str, rule_value: str) -> bool:
    """Check if a packet field matches a rule field ('any' matches everything)."""
    if rule_value == "any":
        return True
    return str(pkt_value) == rule_value


def evaluate_packet(pkt: Packet, rules: list[NidsRule]) -> Optional[NidsAlert]:
    """Evaluate a packet against the rule set and return an alert if matched.

    Returns the first matching rule's alert, or None.
    """
    # Extract packet metadata (whichever layers are present)
    ip_layer = pkt.getlayer(IP) if pkt.haslayer(IP) else None
    tcp_layer = pkt.getlayer(TCP) if pkt.haslayer(TCP) else None
    udp_layer = pkt.getlayer(UDP) if pkt.haslayer(UDP) else None
    icmp_layer = pkt.getlayer(ICMP) if pkt.haslayer(ICMP) else None

    if tcp_layer:
        protocol = "TCP"
        src_port = str(tcp_layer.sport)
        dst_port = str(tcp_layer.dport)
    elif udp_layer:
        protocol = "UDP"
        src_port = str(udp_layer.sport)
        dst_port = str(udp_layer.dport)
    elif icmp_layer:
        protocol = "ICMP"
        src_port = ""
        dst_port = ""
    else:
        protocol = "Other"
        src_port = ""
        dst_port = ""

    src_ip = ip_layer.src if ip_layer else ""
    dst_ip = ip_layer.dst if ip_layer else ""

    for rule in rules:
        # Protocol match
        if rule.protocol != "any" and rule.protocol.lower() != protocol.lower():
            continue
        # Source/destination IP match
        if not _matches_field(src_ip, rule.src_ip):
            continue
        if not _matches_field(dst_ip, rule.dst_ip):
            continue
        # Port match
        if not _matches_field(src_port, rule.src_port):
            continue
        if not _matches_field(dst_port, rule.dst_port):
            continue

        # Build alert
        alert_msg = rule.msg or f"Rule {rule.sid} matched"
        severity = "High" if rule.action in {"drop", "reject"} else "Medium"

        return NidsAlert(
            timestamp=_format_timestamp(pkt),
            rule_id=str(rule.sid),
            severity=severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            alert=alert_msg,
            action_taken="logged",
        )

    return None
