#!/usr/bin/env python3
"""
NeuralGuard — Combat Attack Simulator v2
════════════════════════════════════════
Four-phase attack simulation designed to exercise every panel
on the Grafana IPS Command Center dashboard:

  Module 1 — PortScan      (class 2): SYN sweep across 100 ports
  Module 2 — DDoS Botnet   (class 1): 500-packet burst from 50 spoofed IPs
  Module 3 — SSH BruteForce(class 3): Rapid SYN storm on port 22
  Module 4 — Blitzkrieg    (mixed)  : High-volume mixed wave from 20 IPs

Usage:
    sudo .venv/bin/python tests/simulate_attacks.py --target <IP>
"""

import time
import random
import sys
import argparse

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import IP, TCP, send, conf

# Suppress scapy verbose output
conf.verb = 0

# ── CLI ──────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="NeuralGuard Combat Attack Simulator v2")
parser.add_argument("--target",   type=str, default="192.168.41.158", help="Target IP address")
parser.add_argument("--delay",    type=float, default=0.005,          help="Inter-packet delay (seconds)")
parser.add_argument("--no-spoof", action="store_true",                help="Disable IP spoofing (use real src IP)")
args = parser.parse_args()

TARGET_IP = args.target
PKT_DELAY  = args.delay

# ── ANSI Colours ─────────────────────────────────────────────────────────────
R  = "\033[91m"    # red
Y  = "\033[93m"    # yellow
C  = "\033[96m"    # cyan
G  = "\033[92m"    # green
M  = "\033[95m"    # magenta
B  = "\033[1m"     # bold
DIM= "\033[2m"     # dim
RST= "\033[0m"     # reset

# ── Helpers ───────────────────────────────────────────────────────────────────
BOTNET_POOL  = [f"10.{random.randint(0,254)}.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(80)]
ROUTER_POOL  = [f"172.{random.randint(16,31)}.{random.randint(0,254)}.{random.randint(1,254)}" for _ in range(30)]
ALL_FAKE_IPS = BOTNET_POOL + ROUTER_POOL

stats = {
    "portscan":   0,
    "ddos":       0,
    "bruteforce": 0,
    "blitzkrieg": 0,
}

def rnd_ip():
    return random.choice(ALL_FAKE_IPS)

def rnd_sport():
    return random.randint(1024, 65535)

def bar(done, total, width=30):
    filled = int(width * done / total)
    return f"[{'█' * filled}{'░' * (width - filled)}] {done}/{total}"

def send_pkt(src_ip, dst_port, flags="S", payload=b"", extra_syn=0, extra_rst=0):
    """Craft and send a single packet."""
    pkt = IP(src=src_ip, dst=TARGET_IP) / TCP(
        sport=rnd_sport(),
        dport=dst_port,
        flags=flags,
        window=random.choice([1024, 2048, 4096, 8192])
    )
    if payload:
        pkt = pkt / payload
    send(pkt, verbose=0)

# ── Module 1: PortScan ───────────────────────────────────────────────────────
def module_1_portscan():
    """Sweep 100 random destination ports with SYN packets from a single attacker IP."""
    attacker = rnd_ip()
    print(f"\n{B}{R}[MODULE 1] PortScan{RST}  ←  attacker: {C}{attacker}{RST}  →  target: {C}{TARGET_IP}{RST}")
    print(f"{DIM}  Strategy: SYN sweep across 100 random ports (mimics nmap -sS){RST}\n")

    for i in range(1, 101):
        dst_port = random.randint(1, 1024)
        send_pkt(attacker, dst_port, flags="S")
        stats["portscan"] += 1

        if i % 20 == 0:
            print(f"  {bar(i, 100)}  {G}✓{RST}", flush=True)
        time.sleep(PKT_DELAY)

    print(f"\n  {G}[✓] PortScan complete — {stats['portscan']} SYN probes sent{RST}\n")

# ── Module 2: DDoS Botnet Burst ───────────────────────────────────────────────
def module_2_ddos():
    """500 SYN packets to port 80 from 50 distinct spoofed botnet IPs."""
    print(f"\n{B}{R}[MODULE 2] DDoS Botnet Burst{RST}  →  target: {C}{TARGET_IP}:80{RST}")
    print(f"{DIM}  Strategy: 500 SYN packets from 50 unique botnet members (HTTP flood wave){RST}\n")

    botnet_subset = random.sample(ALL_FAKE_IPS, min(50, len(ALL_FAKE_IPS)))
    pkt_per_bot   = max(1, 500 // len(botnet_subset))

    total = 0
    for bot_ip in botnet_subset:
        for _ in range(pkt_per_bot):
            payload = b"X" * random.randint(16, 64)
            send_pkt(bot_ip, 80, flags="S", payload=payload)
            total += 1
            stats["ddos"] += 1
        time.sleep(PKT_DELAY * 2)

        if total % 100 == 0:
            print(f"  {bar(total, 500)}  {G}✓{RST}", flush=True)

    print(f"\n  {G}[✓] DDoS burst complete — {stats['ddos']} packets from {len(botnet_subset)} bots{RST}\n")

# ── Module 3: SSH Brute Force ─────────────────────────────────────────────────
def module_3_bruteforce():
    """Rapid SYN storm on port 22 from 10 attacker IPs — classic credential stuffing pattern."""
    print(f"\n{B}{M}[MODULE 3] SSH Brute Force{RST}  →  target: {C}{TARGET_IP}:22{RST}")
    print(f"{DIM}  Strategy: 200 rapid SYN bursts on SSH port from 10 distinct sources{RST}\n")

    attackers = random.sample(ALL_FAKE_IPS, 10)
    total = 0

    for i, atk_ip in enumerate(attackers):
        bursts = 20  # 20 rapid SYNs per attacker
        for j in range(bursts):
            # Brute force: small window, rapid resets after SYN
            pkt = IP(src=atk_ip, dst=TARGET_IP) / TCP(
                sport=rnd_sport(),
                dport=22,
                flags="S",
                window=512
            )
            send(pkt, verbose=0)
            total += 1
            stats["bruteforce"] += 1
            time.sleep(PKT_DELAY)

        print(f"  Attacker {i+1:02d}/{len(attackers)}: {C}{atk_ip}{RST}  {bar(total, 200)}  {G}✓{RST}", flush=True)

    print(f"\n  {G}[✓] Brute Force complete — {stats['bruteforce']} SYN bursts across {len(attackers)} attackers{RST}\n")

# ── Module 4: Blitzkrieg (mixed high-volume) ─────────────────────────────────
def module_4_blitzkrieg():
    """High-volume mixed attack wave — all attack types simultaneously from 20 IPs."""
    print(f"\n{B}{R}[MODULE 4] BLITZKRIEG — Mixed High-Volume Wave{RST}  →  target: {C}{TARGET_IP}{RST}")
    print(f"{DIM}  Strategy: 400 mixed packets (DDoS/Scan/BruteForce) from 20 concurrent attackers{RST}\n")

    attackers = random.sample(ALL_FAKE_IPS, 20)
    ATTACK_PLANS = [
        # (dst_port, flags, payload_size, label)
        (80,   "S", 48, "DDoS"),
        (443,  "S", 48, "DDoS"),
        (22,   "S", 0,  "BruteForce"),
        (21,   "S", 0,  "BruteForce"),
        (None, "S", 0,  "PortScan"),   # random port
    ]

    total = 0
    for i in range(400):
        atk_ip   = random.choice(attackers)
        plan     = random.choice(ATTACK_PLANS)
        dst_port = plan[0] if plan[0] else random.randint(1, 1024)
        payload  = (b"G" * plan[2]) if plan[2] else b""

        send_pkt(atk_ip, dst_port, flags=plan[1], payload=payload)
        total += 1
        stats["blitzkrieg"] += 1

        if total % 80 == 0:
            print(f"  {bar(total, 400)}  {G}✓{RST}", flush=True)

        time.sleep(PKT_DELAY)

    print(f"\n  {G}[✓] Blitzkrieg complete — {stats['blitzkrieg']} mixed packets across {len(attackers)} attackers{RST}\n")

# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"""
{B}{R}
  ███╗   ██╗███████╗██╗   ██╗██████╗  █████╗ ██╗
  ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔══██╗██║
  ██╔██╗ ██║█████╗  ██║   ██║██████╔╝███████║██║
  ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██╔══██║██║
  ██║ ╚████║███████╗╚██████╔╝██║  ██║██║  ██║███████╗
  ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
  {RST}{C}G U A R D   —   C O M B A T   S I M U L A T O R   v 2{RST}

  {Y}Target  :{RST} {TARGET_IP}
  {Y}Modules :{RST} PortScan · DDoS Botnet · SSH BruteForce · Blitzkrieg
  {Y}Bots    :{RST} {len(ALL_FAKE_IPS)} spoofed IPs across 2 subnets
  {Y}Delay   :{RST} {PKT_DELAY}s/packet
""")

    try:
        t_start = time.time()

        # ── Phase 1: PortScan ────────────────────────────────────────────────
        module_1_portscan()
        print(f"{Y}  ⏳ Waiting 3s for sniffer to flush flows…{RST}")
        time.sleep(3)

        # ── Phase 2: DDoS Botnet ─────────────────────────────────────────────
        module_2_ddos()
        print(f"{Y}  ⏳ Waiting 3s for sniffer to flush flows…{RST}")
        time.sleep(3)

        # ── Phase 3: SSH BruteForce ──────────────────────────────────────────
        module_3_bruteforce()
        print(f"{Y}  ⏳ Waiting 3s for sniffer to flush flows…{RST}")
        time.sleep(3)

        # ── Phase 4: Blitzkrieg ──────────────────────────────────────────────
        module_4_blitzkrieg()

        # ── Final wait for AI pipeline to process remaining flows ─────────────
        print(f"\n{C}  ⏳ Waiting 8s for sniffer to process remaining flows…{RST}")
        time.sleep(8)

        elapsed = time.time() - t_start
        total_pkts = sum(stats.values())

        print(f"""
{B}{'═' * 60}{RST}
  {G}[✓] COMBAT SIMULATION COMPLETE{RST}

  {'Module':<18} {'Packets':>8}
  {'─'*28}
  {'PortScan':<18} {stats['portscan']:>8}
  {'DDoS Botnet':<18} {stats['ddos']:>8}
  {'SSH BruteForce':<18} {stats['bruteforce']:>8}
  {'Blitzkrieg':<18} {stats['blitzkrieg']:>8}
  {'─'*28}
  {'TOTAL':<18} {total_pkts:>8}

  {Y}Elapsed : {elapsed:.1f}s{RST}
  {C}→ Check Grafana at http://localhost:3000{RST}
{B}{'═' * 60}{RST}
""")

    except PermissionError:
        print(f"\n{R}[!] Error: Scapy requires root/sudo to send raw packets.{RST}")
        sys.exit(1)
    except KeyboardInterrupt:
        total_pkts = sum(stats.values())
        print(f"\n{Y}[!] Simulation interrupted — {total_pkts} packets sent before stop.{RST}")
        sys.exit(0)
