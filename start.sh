#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  NeuralGuard IPS — Start All Services
#  Usage: sudo ./start.sh
# ═══════════════════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv/bin/python"
LOG_DIR="$SCRIPT_DIR/logs"

mkdir -p "$LOG_DIR"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║        NeuralGuard IPS — Full Stack Launcher            ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── 1. Docker services (PostgreSQL + Grafana) ────────────────
echo "[1/3] Starting Docker services (PostgreSQL + Grafana)..."
docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d
echo "  ✓ PostgreSQL on :5432"
echo "  ✓ Grafana on    :3000"
echo ""

# Wait for PostgreSQL to be ready
echo "  Waiting for PostgreSQL to accept connections..."
for i in $(seq 1 15); do
    if docker exec neural_postgres pg_isready -U admin -d neuralguard > /dev/null 2>&1; then
        echo "  ✓ PostgreSQL is ready."
        break
    fi
    if [ "$i" -eq 15 ]; then
        echo "  ✗ PostgreSQL did not become ready in time."
        exit 1
    fi
    sleep 1
done
echo ""

# ── 2. IP Manager API (Flask on :5001) ───────────────────────
echo "[2/3] Starting IP Manager API on :5001..."
$VENV "$SCRIPT_DIR/tools/ip_manager_api.py" > "$LOG_DIR/ip_manager_api.log" 2>&1 &
API_PID=$!
echo "  ✓ IP Manager API started (PID: $API_PID)"
echo ""

# ── 3. Sniffer IPS (packet capture + AI) ─────────────────────
echo "[3/3] Starting Sniffer IPS on [eno1, tailscale0]..."
$VENV "$SCRIPT_DIR/sensor/sniffer.py" > >(tee "$LOG_DIR/sniffer.log") 2>&1 &
SNIFFER_PID=$!
echo "  ✓ Sniffer IPS started (PID: $SNIFFER_PID)"
echo ""

# ── Summary ──────────────────────────────────────────────────
echo "══════════════════════════════════════════════════════════"
echo "  All services running:"
echo "    • PostgreSQL    — localhost:5432"
echo "    • Grafana       — http://localhost:3000  (admin/admin)"
echo "    • IP Manager    — http://localhost:5001  (PID $API_PID)"
echo "    • Sniffer IPS   — live capture           (PID $SNIFFER_PID)"
echo ""
echo "  Logs: $LOG_DIR/"
echo "  Stop: sudo ./stop.sh"
echo "══════════════════════════════════════════════════════════"
echo ""

# Save PIDs for stop script
echo "$API_PID" > "$LOG_DIR/api.pid"
echo "$SNIFFER_PID" > "$LOG_DIR/sniffer.pid"

# Keep the script alive — forward sniffer output to terminal
wait $SNIFFER_PID
