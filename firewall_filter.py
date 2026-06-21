#!/usr/bin/env python3
"""
Real-Time Firewall Packet Filter Simulator
IIT Kanpur B.Cyber Degree Application - Proof-of-Work

This script simulates a network firewall packet filter with a pre-configured ACL.
It can read packet data from a text file or generate continuous simulated traffic.
For each packet, it evaluates source IP, destination port, and protocol against
ACL rules and logs the decision in real-time with colored output.
Finally, it prints a professional summary report in ASCII table format.

All code uses only Python built-in modules (time, random, sys, re, datetime).
"""

import sys
import time
import random
import re
from datetime import datetime

# -----------------------------------------------------------------------------
# 1. ANSI Color Codes for Terminal Output
# -----------------------------------------------------------------------------
COLOR_GREEN = '\033[92m'
COLOR_RED = '\033[91m'
COLOR_YELLOW = '\033[93m'
COLOR_RESET = '\033[0m'
COLOR_BOLD = '\033[1m'

# -----------------------------------------------------------------------------
# 2. Pre-configured Access Control List (ACL) Rules
#    Each rule is a dict with:
#      - action: 'allow' or 'block'
#      - src_cidrs: list of CIDR strings (e.g., '0.0.0.0/0' for any)
#      - dst_ports: list of ports or None for any
#      - protocol: list of protocols (e.g., ['TCP', 'UDP']) or None for any
#      - description: human-readable label
#    Rules are evaluated in order; first match wins. Implicit default deny.
# -----------------------------------------------------------------------------
ACL_RULES = [
    {
        'action': 'allow',
        'src_cidrs': ['0.0.0.0/0'],          # any source
        'dst_ports': [80, 443],
        'protocol': ['TCP'],
        'description': 'Allow HTTP/HTTPS web traffic'
    },
    {
        'action': 'allow',
        'src_cidrs': ['0.0.0.0/0'],
        'dst_ports': [53],
        'protocol': ['UDP'],
        'description': 'Allow DNS queries'
    },
    {
        'action': 'block',
        'src_cidrs': ['0.0.0.0/0'],
        'dst_ports': [3306],
        'protocol': ['TCP'],
        'description': 'Block MySQL database access'
    },
    {
        'action': 'block',
        'src_cidrs': ['192.168.1.0/24', '10.0.0.0/8', '203.0.113.0/24'],
        'dst_ports': [22],
        'protocol': ['TCP'],
        'description': 'Block SSH from known bad IP blocks'
    },
    # Default rule: block everything (implicit)
]

# -----------------------------------------------------------------------------
# 3. Helper Functions
# -----------------------------------------------------------------------------

def ip_to_int(ip: str) -> int:
    """Convert dotted IPv4 address to an integer for CIDR matching."""
    parts = ip.split('.')
    if len(parts) != 4:
        raise ValueError(f"Invalid IP address: {ip}")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

def ip_in_cidr(ip: str, cidr: str) -> bool:
    """
    Check if an IP address is within a CIDR block.
    Supports both single IPs (e.g., '192.168.1.100') and CIDR notation.
    """
    if '/' in cidr:
        network_str, prefix_str = cidr.split('/')
        prefix = int(prefix_str)
        network_int = ip_to_int(network_str)
        ip_int = ip_to_int(ip)
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        return (ip_int & mask) == (network_int & mask)
    else:
        # Single IP
        return ip == cidr

def parse_packet_line(line: str) -> dict:
    """
    Parse a line from the input file.
    Expected format: "src_ip,dst_port,protocol" (e.g., "192.168.1.5,443,TCP")
    Spaces are trimmed.
    Returns a dict with keys: src_ip, dst_port, protocol.
    Raises ValueError if parsing fails.
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None  # skip empty or comment lines
    parts = [p.strip() for p in line.split(',')]
    if len(parts) != 3:
        raise ValueError(f"Invalid packet format (expected 3 comma-separated fields): {line}")
    src_ip, dst_port_str, protocol = parts
    dst_port = int(dst_port_str)
    if not (1 <= dst_port <= 65535):
        raise ValueError(f"Destination port out of range: {dst_port}")
    protocol = protocol.upper()
    if protocol not in ('TCP', 'UDP'):
        raise ValueError(f"Unsupported protocol: {protocol}")
    # Basic IP format validation (simple regex)
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', src_ip):
        raise ValueError(f"Invalid IP address format: {src_ip}")
    return {'src_ip': src_ip, 'dst_port': dst_port, 'protocol': protocol}

def generate_random_packet() -> dict:
    """
    Generate a random simulated packet for continuous traffic.
    Returns dict with src_ip, dst_port, protocol.
    """
    # Generate a random private or public IP (mostly private for realism)
    # Choose a random private range: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
    rand = random.random()
    if rand < 0.4:
        # 10.0.0.0/8
        src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    elif rand < 0.8:
        # 192.168.0.0/16
        src_ip = f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
    else:
        # 172.16.0.0/12
        src_ip = f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"
    # Random destination port: 1-65535, with bias towards common ports
    port_choices = [80, 443, 22, 3306, 53, 8080, 25, 110, 143, 21, 20, 23, 123, 161, 389, 636, 3389, 5900]
    if random.random() < 0.7:
        dst_port = random.choice(port_choices)
    else:
        dst_port = random.randint(1024, 65535)
    protocol = random.choice(['TCP', 'UDP'])
    return {'src_ip': src_ip, 'dst_port': dst_port, 'protocol': protocol}

def evaluate_packet(packet: dict) -> tuple:
    """
    Evaluate a packet against the ACL_RULES.
    Returns: (action, rule_description, matched_rule_index)
    action: 'allow' or 'block'
    If no rule matches, default block with description 'Default Deny'.
    """
    src_ip = packet['src_ip']
    dst_port = packet['dst_port']
    protocol = packet['protocol']

    for idx, rule in enumerate(ACL_RULES):
        # Check source IPs: packet must match any of the rule's CIDRs
        src_match = False
        for cidr in rule['src_cidrs']:
            if ip_in_cidr(src_ip, cidr):
                src_match = True
                break
        if not src_match:
            continue

        # Check destination ports: if rule has ports defined, packet port must be in list
        if rule['dst_ports'] is not None and dst_port not in rule['dst_ports']:
            continue

        # Check protocol: if rule has protocols defined, packet protocol must match
        if rule['protocol'] is not None and protocol not in rule['protocol']:
            continue

        # All conditions satisfied -> return action and description
        return (rule['action'], rule['description'], idx)

    # No matching rule -> default deny
    return ('block', 'Default Deny (no rule matched)', -1)

def print_packet_decision(packet: dict, action: str, description: str, timestamp: str):
    """Print a single packet decision with color coding."""
    src = packet['src_ip']
    dst = packet['dst_port']
    proto = packet['protocol']
    if action == 'allow':
        color = COLOR_GREEN
        tag = f"{COLOR_BOLD}[ALLOWED]{COLOR_RESET}"
    else:
        color = COLOR_RED
        tag = f"{COLOR_BOLD}[BLOCKED]{COLOR_RESET}"
    # Format with aligned columns
    print(f"{timestamp} | {tag} | {color}SRC: {src:<15} DST_PORT: {dst:<5} PROTO: {proto:<3} -> {description}{COLOR_RESET}")

def print_summary(stats: dict, total_packets: int):
    """
    Print a final summary report in ASCII table format.
    stats: dict with keys like 'allow_count', 'block_count', and per-rule counts.
    """
    print("\n" + "=" * 80)
    print(f"{COLOR_BOLD}FIREWALL PACKET FILTER SUMMARY REPORT{COLOR_RESET}")
    print("=" * 80)

    # Overall stats
    allow = stats.get('allow_count', 0)
    block = stats.get('block_count', 0)
    print(f"Total Packets Processed: {total_packets}")
    print(f"  {COLOR_GREEN}Allowed: {allow}{COLOR_RESET}")
    print(f"  {COLOR_RED}Blocked: {block}{COLOR_RESET}")
    if total_packets > 0:
        allow_pct = (allow / total_packets) * 100
        block_pct = (block / total_packets) * 100
        print(f"  Allow Rate: {allow_pct:.1f}% | Block Rate: {block_pct:.1f}%")

    # Per-rule breakdown (using rule descriptions)
    print("\n" + "-" * 80)
    print(f"{'Rule ID':<8} {'Action':<8} {'Matches':<10} {'Description'}")
    print("-" * 80)
    # We'll gather per-rule stats from stats['rule_counts'] which maps rule index to count
    rule_counts = stats.get('rule_counts', {})
    default_count = stats.get('default_block_count', 0)
    # Print rules in order
    for idx, rule in enumerate(ACL_RULES):
        count = rule_counts.get(idx, 0)
        action = rule['action']
        desc = rule['description']
        print(f"{idx:<8} {action:<8} {count:<10} {desc}")
    # Default deny rule (not in ACL)
    print(f"{'DEFAULT':<8} {'block':<8} {default_count:<10} Default Deny (no rule matched)")

    print("=" * 80)

# -----------------------------------------------------------------------------
# 4. Main Simulation Logic
# -----------------------------------------------------------------------------

def main():
    print(f"{COLOR_BOLD}Real-Time Firewall Packet Filter Simulator{COLOR_RESET}")
    print("Using ACL rules defined in the script.\n")

    # Ask user for a packet input file, or generate continuous traffic
    file_name = input("Enter packet data file name (or press Enter for continuous simulation): ").strip()
    packets_from_file = []
    if file_name:
        try:
            with open(file_name, 'r') as f:
                lines = f.readlines()
            for line in lines:
                try:
                    pkt = parse_packet_line(line)
                    if pkt is not None:
                        packets_from_file.append(pkt)
                except ValueError as e:
                    print(f"Warning: Skipping invalid line: {line.strip()} - {e}")
            print(f"Loaded {len(packets_from_file)} packets from file.")
        except FileNotFoundError:
            print(f"File '{file_name}' not found. Falling back to continuous simulation.")
            packets_from_file = None
    else:
        packets_from_file = None

    # Statistics
    stats = {
        'allow_count': 0,
        'block_count': 0,
        'rule_counts': {},   # rule index -> count of matches
        'default_block_count': 0
    }
    total_packets = 0

    # Function to process a single packet and update stats
    def process_packet(packet):
        nonlocal total_packets
        total_packets += 1
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        action, desc, rule_idx = evaluate_packet(packet)
        if action == 'allow':
            stats['allow_count'] += 1
        else:
            stats['block_count'] += 1
        if rule_idx >= 0:
            stats['rule_counts'][rule_idx] = stats['rule_counts'].get(rule_idx, 0) + 1
        else:
            stats['default_block_count'] += 1
        print_packet_decision(packet, action, desc, timestamp)

    # If we have packets from file, process them all, then show summary
    if packets_from_file is not None:
        for packet in packets_from_file:
            process_packet(packet)
            # Small delay to simulate real-time (optional)
            # time.sleep(0.1)
        # After processing, print summary
        print_summary(stats, total_packets)
        return

    # Continuous simulation: generate packets until user interrupts (Ctrl+C)
    print("\nStarting continuous packet simulation. Press Ctrl+C to stop and view summary.")
    try:
        while True:
            packet = generate_random_packet()
            process_packet(packet)
            # Random interval between 0.1 and 1.0 seconds to simulate traffic burst
            time.sleep(random.uniform(0.1, 0.8))
    except KeyboardInterrupt:
        print("\n\nSimulation interrupted by user.")
        print_summary(stats, total_packets)
        sys.exit(0)

if __name__ == "__main__":
    main()