#!/usr/bin/env python3
"""
NeuralGuard IP Manager API
──────────────────────────
Lightweight Flask API for managing blocked IPs from Grafana.

Endpoints:
    GET /api/unblock/<ip>  — Unblock an IP (ufw delete deny + remove from DB)
    GET /api/status        — List all managed IPs

Usage:
    sudo ./.venv/bin/python tools/ip_manager_api.py

Requires sudo for ufw commands.
"""

import subprocess
import psycopg2
from flask import Flask, jsonify

app = Flask(__name__)

DB_DSN = "postgresql://admin:adminpassword@127.0.0.1:5432/neuralguard"


def get_db():
    """Get a database connection."""
    return psycopg2.connect(DB_DSN)


@app.route('/api/unblock/<ip>', methods=['GET'])
def unblock_ip(ip):
    """Unblock an IP: remove ufw rule and delete from ip_management."""
    errors = []

    # 1. Remove ufw rule
    try:
        result = subprocess.run(
            ['sudo', 'ufw', 'delete', 'deny', 'from', ip],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            errors.append(f"ufw: {result.stderr.strip()}")
    except subprocess.TimeoutExpired:
        errors.append("ufw: command timed out")
    except Exception as e:
        errors.append(f"ufw: {e}")

    # 2. Remove from ip_management table
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM ip_management WHERE ip_address = %s", (ip,))
        deleted = cur.rowcount
        conn.commit()
        conn.close()
    except Exception as e:
        errors.append(f"db: {e}")
        deleted = 0

    if errors:
        return jsonify({
            "status": "partial" if deleted > 0 else "error",
            "ip": ip,
            "db_rows_deleted": deleted,
            "errors": errors
        }), 500

    return jsonify({
        "status": "ok",
        "ip": ip,
        "message": f"IP {ip} unblocked and removed from management table",
        "db_rows_deleted": deleted
    })


@app.route('/api/status', methods=['GET'])
def list_managed_ips():
    """List all IPs in the ip_management table."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT ip_address, status, added_at FROM ip_management ORDER BY added_at DESC")
        rows = cur.fetchall()
        conn.close()
        return jsonify({
            "status": "ok",
            "count": len(rows),
            "ips": [
                {"ip_address": r[0], "status": r[1], "added_at": str(r[2])}
                for r in rows
            ]
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == '__main__':
    print("╔══════════════════════════════════════════════════════════╗")
    print("║        NeuralGuard IP Manager API v1.0                  ║")
    print("║        Unblock endpoint for Grafana dashboard           ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()
    print("[+] Endpoints:")
    print("    GET /api/unblock/<ip>  — Unblock IP (ufw + DB)")
    print("    GET /api/status        — List managed IPs")
    print()
    app.run(host='0.0.0.0', port=5001, debug=False)
