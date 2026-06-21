# Real-Time Firewall Packet Filter Simulator

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A production‑grade, zero‑dependency Python 3 simulator that emulates a stateful firewall packet filter. It parses real‑time network traffic (from a file or continuous synthetic stream), evaluates each packet against a pre‑configured Access Control List (ACL), and provides color‑coded terminal logging with a final ASCII summary report. Designed for educational use in network security portfolios and fully compatible with online sandboxes.

---

## 🔧 Technical Overview

The simulator implements a **first‑match** ACL evaluation engine. Each packet is represented by:

- Source IP (dotted decimal)
- Destination port (1–65535)
- Protocol (`TCP` or `UDP`)

The engine iterates through a user‑defined rule set, checking CIDR‑based source IP ranges, port lists, and protocol types. If a rule matches, its associated action (`allow` or `block`) is executed. If no rule matches, the packet is **implicitly blocked** (default‑deny). All decisions are logged in real time with ANSI color highlighting.

Key architectural decisions:

- **Pure standard library**: Uses only `time`, `random`, `sys`, `re`, and `datetime` – no external packages or low‑level socket hooks.
- **Streaming architecture**: Processes packets one at a time, either from a CSV‑like text file or via a continuous synthetic traffic generator.
- **Deterministic CIDR matching**: Efficiently converts IPs to integers and applies bitmask logic for CIDR membership.

---

## 📋 Access Control List (ACL) Logic Mechanics

The ACL is defined as a list of dictionaries, evaluated in order. Each rule can contain:

| Field         | Type                | Description                                                     |
|---------------|---------------------|-----------------------------------------------------------------|
| `action`      | `str`               | `'allow'` or `'block'`                                          |
| `src_cidrs`   | `list[str]`         | One or more CIDR blocks (e.g., `['192.168.1.0/24']`)            |
| `dst_ports`   | `list[int]` or `None` | List of destination ports; `None` means any port               |
| `protocol`    | `list[str]` or `None` | List of protocols (`TCP`, `UDP`); `None` means any protocol    |
| `description` | `str`               | Human‑readable label for logging and reporting                  |

**Evaluation flow**:

1. For a given packet, each rule is tested in sequence.
2. The packet must satisfy **all** conditions in a rule to be a match:
   - Source IP falls within **any** CIDR in `src_cidrs`.
   - Destination port is present in `dst_ports` (if specified).
   - Protocol is present in `protocol` (if specified).
3. On first match, the rule’s `action` is returned and evaluation stops.
4. If no rule matches, the packet is blocked as **Default Deny**.

This model supports granular policies such as:  
`Allow HTTP/HTTPS from anywhere`, `Block MySQL from anywhere`, and `Block SSH from specific untrusted IP blocks`.

---

## 📦 Prerequisites

- **Python 3.6** or later (no external libraries required)
- A terminal with ANSI color support (most modern terminals support it)
- (Optional) A text file containing packet data for batch processing

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/firewall-packet-filter.git
cd firewall-packet-filter
