#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  NeuralGuard IPS — Attack Simulation Launcher
#  Usage: sudo ./attack.sh [TARGET_IP]
#
#  Defaults to 192.168.41.158 if no target is provided.
#  Also optionally resets the database before attacking.
# ═══════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv/bin/python"
TARGET="${1:-192.168.41.158}"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║        NeuralGuard — Attack Simulation                  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  Target: $TARGET"
echo ""

# ── Optional DB reset ────────────────────────────────────────
read -rp "  Reset database before attack? [y/N]: " RESET
if [[ "$RESET" =~ ^[Yy]$ ]]; then
    echo ""
    echo "YES" | $VENV "$SCRIPT_DIR/tools/reset_db.py"
    echo ""
fi

# ── Launch attack simulation ─────────────────────────────────
echo "  Launching attack simulation..."
echo ""
$VENV "$SCRIPT_DIR/tests/simulate_attacks.py" --target "$TARGET"
