#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
#  NeuralGuard IPS — Fully Automated Combat Test
#  ───────────────────────────────────────────────
#  Usage:  sudo ./combat_test.sh [TARGET_IP]
#
#  What this script does (zero manual intervention):
#    1. Verifies all prerequisites (Docker, Python venv, model files)
#    2. Starts Docker services (PostgreSQL + Grafana) if not running
#    3. Starts IP Manager API if not running
#    4. Resets the database to a clean slate (--force, no prompt)
#    5. Starts the AI sniffer and waits for it to warm up
#    6. Opens the Grafana dashboard in a browser
#    7. Fires a 4-module attack simulation (1200+ packets)
#    8. Waits for the AI pipeline to classify all remaining flows
#    9. Prints a colour-coded live database summary
#   10. Tails sniffer log for final verdict
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv/bin/python"
LOG_DIR="$SCRIPT_DIR/logs"
SNIFFER_LOG="$LOG_DIR/sniffer.log"
API_LOG="$LOG_DIR/ip_manager_api.log"
DB_DSN="postgresql://admin:adminpassword@127.0.0.1:5432/neuralguard"

# ── Target IP ─────────────────────────────────────────────────────────────────
TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    # Auto-detect local non-loopback IP
    TARGET=$(ip -4 addr show scope global | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
    if [[ -z "$TARGET" ]]; then
        TARGET="192.168.41.158"
    fi
fi

# ── ANSI colours ──────────────────────────────────────────────────────────────
RED='\033[0;91m'
YEL='\033[0;93m'
CYN='\033[0;96m'
GRN='\033[0;92m'
MAG='\033[0;95m'
BLD='\033[1m'
DIM='\033[2m'
RST='\033[0m'

mkdir -p "$LOG_DIR"

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BLD}${RED}"
cat << 'BANNER'
  ╔══════════════════════════════════════════════════════════╗
  ║   NeuralGuard IPS — Fully Automated Combat Test v2     ║
  ║   ──────────────────────────────────────────────────   ║
  ║   4-Phase Attack · AI Detection · Zero Intervention    ║
  ╚══════════════════════════════════════════════════════════╝
BANNER
echo -e "${RST}"
echo -e "  ${YEL}Target IP :${RST} ${CYN}${TARGET}${RST}"
echo -e "  ${YEL}Log Dir   :${RST} ${DIM}${LOG_DIR}${RST}"
echo -e "  ${YEL}Grafana   :${RST} ${CYN}http://localhost:3000${RST}"
echo ""

# ── Helper: step header ───────────────────────────────────────────────────────
step() {
    local num="$1"; shift
    echo -e "\n${BLD}${CYN}[STEP ${num}]${RST} $*"
}

ok()   { echo -e "  ${GRN}✓${RST}  $*"; }
warn() { echo -e "  ${YEL}⚠${RST}  $*"; }
fail() { echo -e "  ${RED}✗${RST}  $*"; }

# ── Helper: wait with spinner ─────────────────────────────────────────────────
wait_spin() {
    local secs=$1; shift
    local msg="$*"
    local spin=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    for ((i=0; i<secs*5; i++)); do
        printf "\r  ${CYN}%s${RST}  %s  " "${spin[$((i % 10))]}" "$msg"
        sleep 0.2
    done
    echo -e "\r  ${GRN}✓${RST}  ${msg} — done          "
}

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 1 — Prerequisites check
# ═══════════════════════════════════════════════════════════════════════════════
step 1 "Verifying prerequisites…"

[[ -f "$VENV" ]]    && ok "Python venv found" \
                     || { fail "venv missing at $VENV"; exit 1; }

[[ -f "$SCRIPT_DIR/brain/neuralguard_v2.h5" ]] \
                    && ok "Model file found" \
                     || { fail "Model not found: brain/neuralguard_v2.h5"; exit 1; }

[[ -f "$SCRIPT_DIR/brain/scaler.pkl" ]] \
                    && ok "Scaler file found" \
                     || { fail "Scaler not found: brain/scaler.pkl"; exit 1; }

command -v docker &>/dev/null \
                    && ok "Docker available" \
                     || { fail "Docker not found"; exit 1; }

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 2 — Docker services (PostgreSQL + Grafana)
# ═══════════════════════════════════════════════════════════════════════════════
step 2 "Starting Docker services (PostgreSQL + Grafana)…"

docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d 2>&1 \
    | while IFS= read -r line; do echo -e "  ${DIM}${line}${RST}"; done

ok "PostgreSQL on :5432"
ok "Grafana on    :3000"

# Wait for PostgreSQL readiness
echo -e "\n  Waiting for PostgreSQL to accept connections…"
for i in $(seq 1 20); do
    if docker exec neural_postgres pg_isready -U admin -d neuralguard >/dev/null 2>&1; then
        ok "PostgreSQL is ready (attempt ${i})"
        break
    fi
    if [[ "$i" -eq 20 ]]; then
        fail "PostgreSQL did not become ready in time"
        exit 1
    fi
    sleep 1
done

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 3 — IP Manager API
# ═══════════════════════════════════════════════════════════════════════════════
step 3 "Starting IP Manager API on :5001…"

API_RUNNING=false
if [[ -f "$LOG_DIR/api.pid" ]]; then
    APID=$(cat "$LOG_DIR/api.pid")
    if kill -0 "$APID" 2>/dev/null; then
        ok "IP Manager API already running (PID $APID)"
        API_RUNNING=true
    fi
fi

if ! $API_RUNNING; then
    $VENV "$SCRIPT_DIR/tools/ip_manager_api.py" > "$API_LOG" 2>&1 &
    APID=$!
    echo "$APID" > "$LOG_DIR/api.pid"
    sleep 1
    ok "IP Manager API started (PID $APID)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 4 — Reset database (non-interactive --force)
# ═══════════════════════════════════════════════════════════════════════════════
step 4 "Resetting database for clean combat test…"

$VENV "$SCRIPT_DIR/tools/reset_db.py" --force
ok "Database wiped — alerts & ip_management tables cleared"

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 5 — Start AI Sniffer
# ═══════════════════════════════════════════════════════════════════════════════
step 5 "Starting AI Sniffer IPS…"

# Kill any stale sniffer
if [[ -f "$LOG_DIR/sniffer.pid" ]]; then
    SPID=$(cat "$LOG_DIR/sniffer.pid")
    if kill -0 "$SPID" 2>/dev/null; then
        warn "Terminating existing sniffer (PID $SPID)…"
        kill "$SPID" 2>/dev/null || true
        sleep 2
    fi
fi

# Clear old log
> "$SNIFFER_LOG"

# Launch sniffer — tee output to log AND terminal (background)
$VENV "$SCRIPT_DIR/sensor/sniffer.py" > >(tee "$SNIFFER_LOG") 2>&1 &
SNIFFER_PID=$!
echo "$SNIFFER_PID" > "$LOG_DIR/sniffer.pid"
ok "Sniffer IPS started (PID $SNIFFER_PID)"

# Wait for sniffer to load model + connect to DB
echo ""
echo -e "  ${DIM}Waiting for model to load and DB to initialise…${RST}"
WARMUP=0
for i in $(seq 1 30); do
    if grep -q "NeuralGuard IPS v2" "$SNIFFER_LOG" 2>/dev/null; then
        ok "Sniffer is LIVE and ready (${i}s warmup)"
        WARMUP=1
        break
    fi
    sleep 1
done

if [[ "$WARMUP" -eq 0 ]]; then
    warn "Sniffer warmup timed out; proceeding anyway (check $SNIFFER_LOG)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 6 — Open Grafana Dashboard
# ═══════════════════════════════════════════════════════════════════════════════
step 6 "Opening Grafana IPS Command Center in browser…"

GRAFANA_URL="http://localhost:3000/d/postgres_ips_dash_005/neuralguard-ips-command-center?orgId=1&refresh=5s&from=now-5m&to=now"

if command -v xdg-open &>/dev/null; then
    xdg-open "$GRAFANA_URL" &>/dev/null &
    ok "Grafana opened → ${CYN}${GRAFANA_URL}${RST}"
elif command -v google-chrome &>/dev/null; then
    google-chrome --new-tab "$GRAFANA_URL" &>/dev/null &
    ok "Grafana opened in Chrome → ${CYN}${GRAFANA_URL}${RST}"
else
    warn "Cannot auto-open browser. Navigate to: ${CYN}${GRAFANA_URL}${RST}"
fi

echo ""
echo -e "  ${YEL}⚡ Dashboard auto-refreshes every 5s — watch it fill up live!${RST}"

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 7 — Fire Attack Simulation
# ═══════════════════════════════════════════════════════════════════════════════
step 7 "Launching 4-module combat attack simulation…"
echo ""
echo -e "  ${MAG}Modules:${RST} PortScan · DDoS Botnet · SSH BruteForce · Blitzkrieg"
echo -e "  ${MAG}Volume :${RST} ~1,200+ packets across 110+ spoofed attacker IPs"
echo ""

$VENV "$SCRIPT_DIR/tests/simulate_attacks.py" --target "$TARGET"

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 8 — Wait for AI pipeline to flush all flows
# ═══════════════════════════════════════════════════════════════════════════════
step 8 "Waiting for AI pipeline to classify remaining flows…"
wait_spin 10 "Sniffer processing residual flows"

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 9 — Live DB Summary
# ═══════════════════════════════════════════════════════════════════════════════
step 9 "Querying database for combat results…"
echo ""

# Run a summary query via psql inside the Docker container
SUMMARY=$(docker exec neural_postgres psql -U admin -d neuralguard -t -A -F'|' -c "
SELECT
  status,
  COUNT(*) AS total,
  ROUND(AVG(confidence)::numeric, 3) AS avg_conf,
  ROUND(MAX(confidence)::numeric, 3) AS max_conf
FROM alerts
GROUP BY status
ORDER BY total DESC;
" 2>/dev/null || echo "QUERY_FAILED")

if [[ "$SUMMARY" == "QUERY_FAILED" || -z "$SUMMARY" ]]; then
    warn "Could not query DB — check Docker connectivity"
else
    echo -e "  ${BLD}┌──────────────────┬────────┬──────────┬──────────┐${RST}"
    echo -e "  ${BLD}│ Status           │  Count │ Avg Conf │ Max Conf │${RST}"
    echo -e "  ${BLD}├──────────────────┼────────┼──────────┼──────────┤${RST}"
    while IFS='|' read -r status total avg_conf max_conf; do
        [[ -z "$status" ]] && continue
        case "$status" in
            AUTO_BLOCKED) CLR="${RED}" ;;
            NEEDS_REVIEW) CLR="${YEL}" ;;
            BENIGN)       CLR="${GRN}" ;;
            *)            CLR="${RST}" ;;
        esac
        printf "  ${BLD}│${RST} ${CLR}%-16s${RST} ${BLD}│${RST} %6s ${BLD}│${RST} %8s ${BLD}│${RST} %8s ${BLD}│${RST}\n" \
               "$status" "$total" "$avg_conf" "$max_conf"
    done <<< "$SUMMARY"
    echo -e "  ${BLD}└──────────────────┴────────┴──────────┴──────────┘${RST}"
fi

echo ""

# Top offending IPs
echo -e "  ${BLD}${YEL}🔥 Top 5 Offending IPs:${RST}"
docker exec neural_postgres psql -U admin -d neuralguard -t -A -F'|' -c "
SELECT src_ip, COUNT(*) AS hits, MAX(status) AS worst_status
FROM alerts
WHERE status != 'BENIGN'
GROUP BY src_ip
ORDER BY hits DESC
LIMIT 5;
" 2>/dev/null | while IFS='|' read -r ip hits wstatus; do
    [[ -z "$ip" ]] && continue
    echo -e "    ${CYN}${ip}${RST}  →  ${RED}${hits}${RST} alerts  [${YEL}${wstatus}${RST}]"
done

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 10 — Final Sniffer Log Tail
# ═══════════════════════════════════════════════════════════════════════════════
step 10 "Recent sniffer detections (last 20 lines):"
echo ""
echo -e "${DIM}"
tail -20 "$SNIFFER_LOG" 2>/dev/null || echo "  (no log entries yet)"
echo -e "${RST}"

# ── Final Banner ──────────────────────────────────────────────────────────────
echo ""
echo -e "${BLD}${GRN}"
cat << 'DONE'
  ╔══════════════════════════════════════════════════════════╗
  ║         ✅  COMBAT TEST COMPLETE                        ║
  ║                                                          ║
  ║  • Grafana dashboard auto-refreshes every 5 seconds     ║
  ║  • Sniffer continues running in background              ║
  ║  • Run  sudo ./stop.sh  to shut everything down         ║
  ╚══════════════════════════════════════════════════════════╝
DONE
echo -e "${RST}"
echo -e "  ${CYN}Grafana → http://localhost:3000   (admin / admin)${RST}"
echo -e "  ${DIM}Sniffer log → ${SNIFFER_LOG}${RST}"
echo ""
