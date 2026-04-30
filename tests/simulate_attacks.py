#!/usr/bin/env python3
"""
NeuralGuard — Attack Simulation for Dashboard Demo
════════════════════════════════════════════════════
Injects realistic attack alerts directly into PostgreSQL with real-time
staggered timing so the Grafana dashboard fills up gradually.

Each module pauses between alert injections so you can watch the dashboard
update live. AUTO_BLOCKED IPs are also added to ip_management (blacklist).

Usage:  python tests/simulate_attacks.py [--reset] [--fast]
        --reset  Clears existing alerts before injecting
        --fast   Skip delays (instant injection like before)
"""

import argparse
import random
import time
import sys
from datetime import datetime

import psycopg2

DB_DSN = "postgresql://admin:adminpassword@127.0.0.1:5432/neuralguard"

# ── ANSI colours ──────────────────────────────────────────────────────────────
R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"; G = "\033[92m"
M = "\033[95m"; B = "\033[1m"; DIM = "\033[2m"; RST = "\033[0m"

# ── IP Pools ──────────────────────────────────────────────────────────────────
BOTNET_IPS = [f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(40)]
SCANNER_IPS = [f"172.{random.randint(16,31)}.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(15)]
BRUTEFORCE_IPS = [f"192.168.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(10)]
BENIGN_IPS = [
    "192.168.41.10", "192.168.41.20", "192.168.41.30",
    "192.168.41.40", "192.168.41.50", "10.0.0.1", "10.0.0.2",
]

TARGET_IP = "192.168.41.150"

stats = {"ddos": 0, "portscan": 0, "bruteforce": 0, "benign": 0}
blacklisted = set()


def bar(done, total, width=30):
    f = int(width * done / total)
    return f"[{'█' * f}{'░' * (width - f)}] {done}/{total}"


def connect_db():
    for attempt in range(5):
        try:
            return psycopg2.connect(DB_DSN)
        except Exception as e:
            print(f"  {Y}DB attempt {attempt + 1}: {e}{RST}")
            time.sleep(2)
    print(f"  {R}[✗] Failed to connect to PostgreSQL{RST}")
    sys.exit(1)


def insert_one(conn, alert):
    """Insert a single alert into the database."""
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO alerts (timestamp, src_ip, dst_ip, src_port, dst_port,
                            protocol, predicted_class, chaos_score, status, confidence)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ''', alert)
    conn.commit()
    cur.close()


def blacklist_ip(conn, ip):
    """Add an IP to the ip_management blacklist table."""
    if ip in blacklisted:
        return
    try:
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO ip_management (ip_address, status)
            VALUES (%s, 'BLACKLISTED')
            ON CONFLICT (ip_address) DO NOTHING
        ''', (ip,))
        conn.commit()
        cur.close()
        blacklisted.add(ip)
    except Exception:
        pass


# ── Module 1: DoS/DDoS ───────────────────────────────────────────────────────
def module_ddos(conn, delay):
    print(f"\n  {B}{R}[MODULE 1]{RST} DoS/DDoS Botnet  →  {C}{TARGET_IP}:80/443{RST}")
    print(f"  {DIM}40 botnet IPs launching SYN flood{RST}\n")

    bots = random.sample(BOTNET_IPS, 40)
    for i, bot_ip in enumerate(bots):
        ts = datetime.now()
        dst_port = random.choice([80, 443, 8080])
        src_port = random.randint(40000, 60000)
        confidence = round(random.uniform(0.91, 0.99), 3)
        chaos = round(random.uniform(0.80, 0.95), 3)

        alert = (ts, bot_ip, TARGET_IP, src_port, dst_port,
                 'TCP', 1, chaos, 'AUTO_BLOCKED', confidence)
        insert_one(conn, alert)
        blacklist_ip(conn, bot_ip)
        stats["ddos"] += 1

        if (i + 1) % 5 == 0:
            print(f"    {bar(i+1, 40)}  {R}⚡ {bot_ip} → :{dst_port}{RST}  "
                  f"{G}AUTO_BLOCKED{RST}", flush=True)

        time.sleep(delay)

    print(f"\n  {G}[✓]{RST} {stats['ddos']} DDoS alerts — {len([b for b in bots])} IPs blacklisted\n")


# ── Module 2: PortScan ────────────────────────────────────────────────────────
def module_portscan(conn, delay):
    print(f"  {B}{C}[MODULE 2]{RST} PortScan  →  {C}{TARGET_IP}{RST}")
    print(f"  {DIM}10 scanners probing multiple ports{RST}\n")

    scanners = random.sample(SCANNER_IPS, 10)
    count = 0
    for scanner_ip in scanners:
        num_probes = random.randint(2, 5)
        for _ in range(num_probes):
            ts = datetime.now()
            dst_port = random.choice([22, 80, 443, 21, 23, 25, 53, 110, 135, 139,
                                      445, 993, 995, 1433, 3306, 3389, 5432, 8080])
            src_port = random.randint(40000, 60000)
            confidence = round(random.uniform(0.78, 0.96), 3)
            chaos = round(random.uniform(0.60, 0.85), 3)
            status = 'AUTO_BLOCKED' if confidence >= 0.90 else 'NEEDS_REVIEW'

            alert = (ts, scanner_ip, TARGET_IP, src_port, dst_port,
                     'TCP', 2, chaos, status, confidence)
            insert_one(conn, alert)
            if status == 'AUTO_BLOCKED':
                blacklist_ip(conn, scanner_ip)
            count += 1

            time.sleep(delay * 0.5)  # Scans are faster

        stats["portscan"] = count
        print(f"    {C}🔍 {scanner_ip}{RST} scanned {num_probes} ports", flush=True)
        time.sleep(delay)

    print(f"\n  {G}[✓]{RST} {stats['portscan']} PortScan alerts from {len(scanners)} scanners\n")


# ── Module 3: BruteForce ─────────────────────────────────────────────────────
def module_bruteforce(conn, delay):
    print(f"  {B}{M}[MODULE 3]{RST} SSH Brute Force  →  {C}{TARGET_IP}:22{RST}")
    print(f"  {DIM}8 attackers hammering SSH/FTP/RDP{RST}\n")

    attackers = random.sample(BRUTEFORCE_IPS, 8)
    count = 0
    for atk_ip in attackers:
        num_attempts = random.randint(2, 4)
        for _ in range(num_attempts):
            ts = datetime.now()
            dst_port = random.choice([22, 22, 22, 21, 23, 3389])
            src_port = random.randint(40000, 60000)
            confidence = round(random.uniform(0.80, 0.97), 3)
            chaos = round(random.uniform(0.70, 0.90), 3)
            status = 'AUTO_BLOCKED' if confidence >= 0.90 else 'NEEDS_REVIEW'

            alert = (ts, atk_ip, TARGET_IP, src_port, dst_port,
                     'TCP', 3, chaos, status, confidence)
            insert_one(conn, alert)
            if status == 'AUTO_BLOCKED':
                blacklist_ip(conn, atk_ip)
            count += 1

            time.sleep(delay * 0.7)

        stats["bruteforce"] = count
        print(f"    {M}🔓 {atk_ip}{RST} → {num_attempts} login attempts", flush=True)
        time.sleep(delay)

    print(f"\n  {G}[✓]{RST} {stats['bruteforce']} BruteForce alerts from {len(attackers)} attackers\n")


# ── Module 4: Benign ──────────────────────────────────────────────────────────
def module_benign(conn, delay):
    print(f"  {B}{G}[MODULE 4]{RST} Benign Traffic (normal baseline)")
    print(f"  {DIM}40 normal connections — web, DNS, email{RST}\n")

    for i in range(40):
        ts = datetime.now()
        src_ip = random.choice(BENIGN_IPS)
        dst_port = random.choice([80, 443, 53, 993, 587, 8080])
        src_port = random.randint(40000, 65000)
        protocol = random.choice(['TCP', 'TCP', 'TCP', 'UDP'])
        confidence = round(random.uniform(0.95, 1.0), 3)
        chaos = round(random.uniform(0.0, 0.15), 3)

        alert = (ts, src_ip, TARGET_IP, src_port, dst_port,
                 protocol, 0, chaos, 'BENIGN', confidence)
        insert_one(conn, alert)
        stats["benign"] += 1

        if (i + 1) % 10 == 0:
            print(f"    {bar(i+1, 40)}  {G}✓ normal traffic{RST}", flush=True)

        time.sleep(delay * 0.3)  # Benign flows in faster

    print(f"\n  {G}[✓]{RST} {stats['benign']} benign flow records\n")


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NeuralGuard Attack Simulator")
    parser.add_argument("--reset", action="store_true",
                        help="Clear existing alerts before injecting")
    parser.add_argument("--fast", action="store_true",
                        help="Skip delays (instant injection)")
    args = parser.parse_args()

    # 0.8s between alerts when live, 0 when --fast
    delay = 0.0 if args.fast else 0.8

    print(f"""
{B}{R}
  ███╗   ██╗███████╗██╗   ██╗██████╗  █████╗ ██╗
  ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔══██╗██║
  ██╔██╗ ██║█████╗  ██║   ██║██████╔╝███████║██║
  ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██╔══██║██║
  ██║ ╚████║███████╗╚██████╔╝██║  ██║██║  ██║███████╗
  ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
  {RST}{C}G U A R D  —  A T T A C K   S I M U L A T O R{RST}

  {Y}Target   :{RST} {TARGET_IP}
  {Y}Method   :{RST} Direct DB injection (Tailscale-compatible)
  {Y}Mode     :{RST} {'⚡ Fast (instant)' if args.fast else '🔴 Live (real-time — watch Grafana!)'}
  {Y}Attacks  :{RST} DoS/DDoS · PortScan · BruteForce · Benign
""")

    conn = connect_db()
    print(f"  {G}[✓] Connected to PostgreSQL{RST}\n")

    if args.reset:
        cur = conn.cursor()
        cur.execute("TRUNCATE TABLE alerts RESTART IDENTITY;")
        cur.execute("TRUNCATE TABLE ip_management RESTART IDENTITY;")
        conn.commit()
        cur.close()
        print(f"  {Y}[✓] Database cleared{RST}\n")

    try:
        t_start = time.time()

        module_ddos(conn, delay)
        module_portscan(conn, delay)
        module_bruteforce(conn, delay)
        module_benign(conn, delay)

        conn.close()
        elapsed = time.time() - t_start
        total = sum(stats.values())

        print(f"""
{B}{'═' * 60}{RST}
  {G}[✓] SIMULATION COMPLETE{RST}

  {'Attack Type':<20} {'Count':>6}  {'Status'}
  {'─' * 50}
  {R}{'DoS / DDoS':<20}{RST} {stats['ddos']:>6}  AUTO_BLOCKED
  {C}{'PortScan':<20}{RST} {stats['portscan']:>6}  AUTO_BLOCKED / NEEDS_REVIEW
  {M}{'SSH BruteForce':<20}{RST} {stats['bruteforce']:>6}  AUTO_BLOCKED / NEEDS_REVIEW
  {G}{'Benign':<20}{RST} {stats['benign']:>6}  BENIGN
  {'─' * 50}
  {'TOTAL':<20} {total:>6}
  {'Blacklisted IPs':<20} {len(blacklisted):>6}

  {Y}Elapsed : {elapsed:.1f}s{RST}
  {C}→ Open Grafana at http://localhost:3000{RST}
  {DIM}Dashboard auto-refreshes every 5 seconds{RST}
{B}{'═' * 60}{RST}
""")

    except KeyboardInterrupt:
        conn.close()
        total = sum(stats.values())
        print(f"\n{Y}[!] Interrupted — {total} alerts injected, {len(blacklisted)} IPs blacklisted.{RST}")
        sys.exit(0)
