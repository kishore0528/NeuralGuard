#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  NeuralGuard IPS — Stop All Services
#  Usage: sudo ./stop.sh
# ═══════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║        NeuralGuard IPS — Shutdown                       ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── Kill Sniffer ──────────────────────────────────────────────
if [ -f "$LOG_DIR/sniffer.pid" ]; then
    PID=$(cat "$LOG_DIR/sniffer.pid")
    if kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null
        echo "  ✓ Sniffer IPS stopped (PID $PID)"
    else
        echo "  - Sniffer was not running"
    fi
    rm -f "$LOG_DIR/sniffer.pid"
else
    echo "  - No sniffer PID file found"
fi

# ── Kill IP Manager API ──────────────────────────────────────
if [ -f "$LOG_DIR/api.pid" ]; then
    PID=$(cat "$LOG_DIR/api.pid")
    if kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null
        echo "  ✓ IP Manager API stopped (PID $PID)"
    else
        echo "  - IP Manager API was not running"
    fi
    rm -f "$LOG_DIR/api.pid"
else
    echo "  - No API PID file found"
fi

# ── Stop Docker ──────────────────────────────────────────────
echo "  Stopping Docker services..."
docker compose -f "$SCRIPT_DIR/docker-compose.yml" down
echo "  ✓ PostgreSQL + Grafana stopped"

echo ""
echo "  All services stopped."
echo ""
