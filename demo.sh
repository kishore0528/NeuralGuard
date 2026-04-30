#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
#  NeuralGuard — Full Demo Launcher
#  ─────────────────────────────────
#  Runs combat_test.sh (attack simulation) then starts all services via start.sh
#
#  Usage:  sudo ./demo.sh [--reset]
#          --reset  Clears the database before simulation
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pass through any flags (e.g. --reset)
FLAGS="${*:-}"



# ── Phase 1: Combat Test ─────────────────────────────────────────────────────
echo "Running combat test..."
echo ""
"$SCRIPT_DIR/combat_test.sh" $FLAGS



# ── Phase 2: Start Services ──────────────────────────────────────────────────
echo "Launching all services..."
echo ""
"$SCRIPT_DIR/start.sh"
