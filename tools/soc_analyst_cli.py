#!/usr/bin/env python3
"""
NeuralGuard SOC Analyst CLI
────────────────────────────
Interactive Human-in-the-Loop review queue for alerts flagged as NEEDS_REVIEW.

Usage:
    sudo ./.venv/bin/python tools/soc_analyst_cli.py

Requires sudo for ufw commands when blocking IPs.
"""

import subprocess
import sys
import psycopg2

DB_DSN = "postgresql://admin:adminpassword@127.0.0.1:5432/neuralguard"

ATTACK_TYPES = {
    0: "Benign",
    1: "DoS / DDoS",
    2: "PortScan",
    3: "Patator (Brute Force)",
    4: "Other",
}

# ─── Terminal colors ──────────────────────────────────────────────────
BOLD    = "\033[1m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
DIM     = "\033[2m"
RESET   = "\033[0m"


def get_connection():
    """Connect to PostgreSQL or exit with a helpful message."""
    try:
        conn = psycopg2.connect(DB_DSN)
        return conn
    except Exception as e:
        print(f"{RED}[✗] Failed to connect to database: {e}{RESET}")
        sys.exit(1)


def fetch_review_queue(conn):
    """
    Fetch unique IPs from the NEEDS_REVIEW queue.
    For each IP, returns the highest-confidence alert details.
    """
    cur = conn.cursor()
    cur.execute("""
        SELECT DISTINCT ON (src_ip)
            src_ip,
            predicted_class,
            confidence,
            COUNT(*) OVER (PARTITION BY src_ip) AS alert_count,
            MIN(timestamp) OVER (PARTITION BY src_ip) AS first_seen,
            MAX(timestamp) OVER (PARTITION BY src_ip) AS last_seen,
            dst_port
        FROM alerts
        WHERE status = 'NEEDS_REVIEW'
        ORDER BY src_ip, confidence DESC
    """)
    rows = cur.fetchall()
    cur.close()
    return rows


def update_status(conn, src_ip, new_status):
    """Update all NEEDS_REVIEW alerts for a given source IP to the new status."""
    cur = conn.cursor()
    cur.execute(
        "UPDATE alerts SET status = %s WHERE src_ip = %s AND status = 'NEEDS_REVIEW'",
        (new_status, src_ip)
    )
    affected = cur.rowcount
    conn.commit()
    cur.close()
    return affected


def block_ip(src_ip):
    """Execute ufw deny for the given IP."""
    try:
        result = subprocess.run(
            ['sudo', 'ufw', 'deny', 'from', src_ip],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            print(f"  {GREEN}[🛡️  UFW] Blocked {src_ip}{RESET}")
            return True
        else:
            print(f"  {RED}[✗ UFW] Failed: {result.stderr.strip()}{RESET}")
            return False
    except subprocess.TimeoutExpired:
        print(f"  {RED}[✗ UFW] Command timed out{RESET}")
        return False
    except Exception as e:
        print(f"  {RED}[✗ UFW] Error: {e}{RESET}")
        return False


def print_banner():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗
║           NeuralGuard SOC Analyst CLI v1.0              ║
║          Human-in-the-Loop Review Queue                 ║
╚══════════════════════════════════════════════════════════╝{RESET}
""")


def print_alert_card(index, total, src_ip, attack_class, confidence, alert_count, first_seen, last_seen, dst_port):
    """Print a formatted alert card for the analyst."""
    attack_name = ATTACK_TYPES.get(attack_class, f"Unknown ({attack_class})")

    # Color the confidence based on how close to auto-block threshold
    if confidence >= 0.85:
        conf_color = RED
    elif confidence >= 0.80:
        conf_color = YELLOW
    else:
        conf_color = GREEN

    print(f"{BOLD}┌─────────────────────────────────────────────────────────┐{RESET}")
    print(f"{BOLD}│  Alert {index}/{total}{RESET}")
    print(f"{BOLD}├─────────────────────────────────────────────────────────┤{RESET}")
    print(f"│  {BOLD}Source IP:{RESET}        {YELLOW}{src_ip}{RESET}")
    print(f"│  {BOLD}Attack Type:{RESET}      {RED}{attack_name}{RESET}")
    print(f"│  {BOLD}AI Confidence:{RESET}    {conf_color}{confidence:.1%}{RESET}")
    print(f"│  {BOLD}Target Port:{RESET}      {dst_port}")
    print(f"│  {BOLD}Alert Count:{RESET}      {alert_count} alert(s)")
    print(f"│  {BOLD}First Seen:{RESET}       {first_seen}")
    print(f"│  {BOLD}Last Seen:{RESET}        {last_seen}")
    print(f"{BOLD}└─────────────────────────────────────────────────────────┘{RESET}")


def prompt_action():
    """Prompt the analyst and return their choice."""
    while True:
        print(f"  {BOLD}[B]{RESET}lock   — Block this IP (ufw deny + mark AUTO_BLOCKED)")
        print(f"  {BOLD}[C]{RESET}lear   — Mark as false positive (set BENIGN)")
        print(f"  {BOLD}[S]{RESET}kip    — Leave in queue for later")
        print(f"  {BOLD}[Q]{RESET}uit    — Exit the tool")
        print()
        choice = input(f"  {CYAN}▸ Action: {RESET}").strip().upper()

        if choice in ('B', 'BLOCK'):
            return 'BLOCK'
        elif choice in ('C', 'CLEAR'):
            return 'CLEAR'
        elif choice in ('S', 'SKIP'):
            return 'SKIP'
        elif choice in ('Q', 'QUIT'):
            return 'QUIT'
        else:
            print(f"  {RED}Invalid choice. Please enter B, C, S, or Q.{RESET}\n")


def main():
    print_banner()

    conn = get_connection()
    print(f"{GREEN}[✓] Connected to PostgreSQL{RESET}")

    queue = fetch_review_queue(conn)

    if not queue:
        print(f"\n{GREEN}[✓] Review queue is empty — no alerts need attention.{RESET}\n")
        conn.close()
        return

    print(f"\n{YELLOW}[!] {len(queue)} unique IP(s) pending review{RESET}\n")

    stats = {'blocked': 0, 'cleared': 0, 'skipped': 0}

    for i, row in enumerate(queue, 1):
        src_ip, attack_class, confidence, alert_count, first_seen, last_seen, dst_port = row

        print_alert_card(i, len(queue), src_ip, attack_class, confidence, alert_count, first_seen, last_seen, dst_port)
        print()

        action = prompt_action()

        if action == 'QUIT':
            print(f"\n{DIM}Exiting... remaining alerts stay in queue.{RESET}")
            break
        elif action == 'BLOCK':
            affected = update_status(conn, src_ip, 'AUTO_BLOCKED')
            block_ip(src_ip)
            stats['blocked'] += 1
            print(f"  {GREEN}[✓] {affected} alert(s) for {src_ip} → AUTO_BLOCKED{RESET}\n")
        elif action == 'CLEAR':
            affected = update_status(conn, src_ip, 'BENIGN')
            stats['cleared'] += 1
            print(f"  {GREEN}[✓] {affected} alert(s) for {src_ip} → BENIGN (false positive){RESET}\n")
        elif action == 'SKIP':
            stats['skipped'] += 1
            print(f"  {DIM}[→] Skipped {src_ip} — stays in review queue{RESET}\n")

    # Summary
    print(f"\n{BOLD}{'═' * 58}{RESET}")
    print(f"{BOLD}  Session Summary{RESET}")
    print(f"{'═' * 58}")
    print(f"  {RED}Blocked:{RESET}  {stats['blocked']}")
    print(f"  {GREEN}Cleared:{RESET}  {stats['cleared']}")
    print(f"  {YELLOW}Skipped:{RESET}  {stats['skipped']}")
    print(f"{'═' * 58}\n")

    conn.close()


if __name__ == '__main__':
    main()
