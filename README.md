# Project: Network Intrusion Detection System 🚨

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-packet%20capture-green)](https://scapy.net/)
[![Npcap](https://img.shields.io/badge/Npcap-Windows%20capture-purple)](https://npcap.com/)
[![Suricata](https://img.shields.io/badge/Suricata-rules%20compatible-orange)](https://suricata.io/)
[![Snort](https://img.shields.io/badge/Snort-rule%20format-red)](https://www.snort.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

A network-based intrusion detection system (NIDS) built in Python with **Scapy** (Npcap on Windows). It captures live traffic, evaluates packets against configurable detection rules, generates alerts, implements response mechanisms, and optionally visualizes detected attacks.

Includes **Snort-compatible rule files** and a **Suricata sample configuration** so you can migrate to a full IDS/IPS deployment later.

> **Scope:** Educational NIDS for authorized networks only. Detects and alerts; response actions are logged/simulated by default.

---

## 🎯 What This Project Does

| NIDS Requirement | Deliverable |
|------------------|-------------|
| **Set up NIDS** | Python capture engine using Scapy + Npcap (Windows) |
| **Configure rules & alerts** | Snort-format `.rules` file + Suricata sample YAML config |
| **Monitor traffic** | Live packet inspection against rule set |
| **Response mechanisms** | Alert logging, console output, simulated block/quarantine |
| **Visualize attacks** | Optional HTML dashboard + matplotlib graphs (`tools/`) |

---

## 🧩 Project Structure

```
3-Network-Intrusion-Detection-System/
├── src/
│   ├── main.py              # CLI entry point
│   ├── capture.py           # Live packet capture (Scapy/Npcap)
│   ├── rules.py             # Rule engine (Snort/Suricata-compatible)
│   ├── alerts.py            # Alert generation + logging
│   ├── response.py          # Response mechanisms (block, log, notify)
│   └── visualize.py         # Optional dashboard + graphs
├── rules/
│   ├── snort_rules.rules    # Snort-format detection rules
│   └── suricata.yaml        # Suricata sample configuration
├── tests/
│   ├── test_rules.py        # Unit tests for rule engine
│   └── test_alerts.py       # Unit tests for alerting
├── samples/
│   ├── sample_alerts.csv    # Sanitized sample alert output
│   └── sample_dashboard.html# Sample visualization dashboard
├── tools/
│   └── generate_dashboard.py# HTML dashboard generator
├── requirements.txt
└── README.md
```

---

## ⚠️ Detection Rules Covered

| Rule ID | Threat | Severity | Protocol |
|---------|--------|----------|----------|
| NIDS-001 | Port scan (SYN flood to many ports) | High | TCP |
| NIDS-002 | Possible brute-force (many failed auth attempts) | High | TCP |
| NIDS-003 | DNS amplification / large DNS response | Medium | UDP |
| NIDS-004 | ICMP flood / ping of death | Medium | ICMP |
| NIDS-005 | Outbound connection to known-bad port | Medium | TCP |
| NIDS-006 | Large payload / possible data exfiltration | Medium | TCP/UDP |

---

## 🚀 Quick Start

### 1. Install dependencies

```powershell
cd 3-Network-Intrusion-Detection-System
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Install Npcap (Windows)

Scapy on Windows requires [Npcap](https://npcap.com/) in **WinPcap API-compatible mode**. Run your terminal / VS Code as **Administrator**.

### 3. Run the NIDS

```powershell
# List interfaces, then monitor default interface
python src/main.py

# Monitor with custom rule file and alert output
python src/main.py -r rules/snort_rules.rules -o alerts.csv

# Generate HTML dashboard from alerts
python tools/generate_dashboard.py -i alerts.csv -o samples/sample_dashboard.html
```

Press **Ctrl+C** to stop and view the detection summary.

---

## 📄 Sample Alert Output (`samples/sample_alerts.csv`)

```csv
timestamp,rule_id,severity,src_ip,dst_ip,src_port,dst_port,protocol,alert,action_taken
14:30:01.102,NIDS-001,High,192.168.1.45,10.0.0.5,51234,22,TCP,Possible port scan: 15 unique destination ports,logged
14:30:01.105,NIDS-004,Medium,10.0.0.1,10.0.0.2,,,ICMP,ICMP flood: 100 packets in 10 seconds,logged
14:30:01.108,NIDS-005,Medium,192.168.1.45,203.0.113.5,51236,4444,TCP,Outbound connection to suspicious port 4444,logged
```

---

## 🛠️ Built With

- **Python** - core language
- **Scapy** - packet capture and dissection
- **Npcap** - Windows packet capture driver
- **csv** - alert export
- **argparse** - CLI
- **matplotlib** (optional) - attack visualization graphs
- **jinja2** (optional) - HTML dashboard templating

---

## 📦 Full NIDS Deployment (Optional)

For production-grade IDS/IPS, deploy **Suricata** or **Snort** on a dedicated sensor:

| Tool | Windows Install | Rule Format |
|------|----------------|-------------|
| **Suricata** | Download from suricata.io, install with Npcap | YAML + `.rules` |
| **Snort** | Download from snort.org, requires WinPcap/Npcap | `.rules` |

This project's `rules/snort_rules.rules` and `rules/suricata.yaml` provide rule templates you can import directly into Suricata or Snort.

---

## ⚖️ Authorized Testing Only

This NIDS is for **authorized network monitoring and defensive security research only**.

- Only monitor networks you own or have explicit written permission to observe.
- Do not deploy on third-party, corporate, or public networks without authorization.
- Response actions are logged/simulated by default; do not enable active blocking without authorization.
- The author is not responsible for misuse of this project.

See `Ethics.md` and `Security.md` in the repository root for full policies.

---

## 📄 License

[MIT License](../../LICENSE)

---

**Built by Alisha-chaudhary** · Cybersecurity Analyst
