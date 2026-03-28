#!/usr/bin/env python3
"""
NeuralGuard Database Reset Tool
────────────────────────────────
Wipes all data from the alerts and ip_management tables
and resets ID counters to zero for a fresh combat test.

Usage:
    ./.venv/bin/python tools/reset_db.py           # interactive
    ./.venv/bin/python tools/reset_db.py --force   # non-interactive (CI/automation)
"""

import argparse
import psycopg2
import sys

DB_DSN = "postgresql://admin:adminpassword@127.0.0.1:5432/neuralguard"

BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"


def main():
    ap = argparse.ArgumentParser(description="NeuralGuard Database Reset Tool")
    ap.add_argument("--force", "-y", action="store_true",
                    help="Skip confirmation prompt (for automated/CI use)")
    args = ap.parse_args()

    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗")
    print(f"║        NeuralGuard Database Reset Tool                  ║")
    print(f"╚══════════════════════════════════════════════════════════╝{RESET}\n")

    # Safety prompt — skipped when --force is supplied
    if not args.force:
        confirm = input(f"{YELLOW}[!] This will DELETE ALL data from alerts and ip_management.{RESET}\n"
                        f"    Type {BOLD}YES{RESET} to confirm: ").strip()
        if confirm != "YES":
            print(f"\n{RED}[✗] Aborted. No data was deleted.{RESET}\n")
            sys.exit(0)

    try:
        conn = psycopg2.connect(DB_DSN)
        cur = conn.cursor()

        # Get row counts before truncate
        cur.execute("SELECT COUNT(*) FROM alerts")
        alert_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM ip_management")
        ip_count = cur.fetchone()[0]

        # Truncate both tables and reset identity counters
        cur.execute("TRUNCATE TABLE alerts, ip_management RESTART IDENTITY;")
        conn.commit()

        print(f"\n{GREEN}[✓] Database reset complete:{RESET}")
        print(f"    • alerts:        {RED}{alert_count}{RESET} rows deleted, ID counter reset to 0")
        print(f"    • ip_management: {RED}{ip_count}{RESET} rows deleted, ID counter reset to 0")
        print(f"\n{GREEN}[✓] Ready for fresh combat test.{RESET}\n")

        conn.close()
    except Exception as e:
        print(f"\n{RED}[✗] Database error: {e}{RESET}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
