#!/bin/bash
# Start all three SOC dashboard services.
# Usage: bash start.sh
#        bash start.sh --no-install  (skip npm install)

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}▸${RESET} $*"; }
success() { echo -e "${GREEN}✓${RESET} $*"; }
warn()    { echo -e "${YELLOW}⚠${RESET} $*"; }
die()     { echo -e "${RED}✗ $*${RESET}" >&2; exit 1; }

echo -e "\n${BOLD}SOC Operations Center${RESET} — LangGraph + CopilotKit\n"

# ── Python / venv ──────────────────────────────────────────────────────────────
if [ -f ".venv/bin/python" ]; then
    PYTHON=".venv/bin/python"
    UVICORN=".venv/bin/uvicorn"
elif command -v python3 &>/dev/null; then
    PYTHON="python3"
    UVICORN="$(python3 -m site --user-base)/bin/uvicorn"
    command -v uvicorn &>/dev/null && UVICORN="uvicorn"
else
    die "Python not found. Install Python 3.11+ and run: pip install -r requirements.txt"
fi

command -v "$UVICORN" &>/dev/null 2>&1 || UVICORN="$PYTHON -m uvicorn"
success "Python: $PYTHON"

# ── .env check ────────────────────────────────────────────────────────────────
if [ ! -f ".env" ]; then
    warn ".env not found. Copying .env.example → .env"
    cp .env.example .env
    echo -e "${YELLOW}  Edit .env and set OPENAI_API_KEY (or ANTHROPIC_API_KEY)${RESET}"
fi

# ── Node / npm ─────────────────────────────────────────────────────────────────
if ! command -v npm &>/dev/null; then
    die "npm not found. Install Node.js 18+ to run the dashboard."
fi

SKIP_INSTALL=false
for arg in "$@"; do [ "$arg" = "--no-install" ] && SKIP_INSTALL=true; done

if [ "$SKIP_INSTALL" = false ] && [ -d "soc_dashboard" ]; then
    info "Installing dashboard npm packages…"
    (cd soc_dashboard && npm install --silent)
    success "npm install complete"
fi

# ── Start services ─────────────────────────────────────────────────────────────
info "Starting SIEM simulator on port 8081…"
$UVICORN siem_simulator.main:app --port 8081 --reload --log-level warning &
SIEM_PID=$!

sleep 1  # slight stagger so logs don't collide

info "Starting SOC pipeline on port 8082…"
$UVICORN soc_agents.main:app --port 8082 --reload --log-level warning &
SOC_PID=$!

sleep 1

info "Starting React dashboard…"
(cd soc_dashboard && npm run dev --silent) &
DASH_PID=$!

# ── Summary ────────────────────────────────────────────────────────────────────
sleep 2
echo ""
echo -e "  ${GREEN}SIEM simulator ${RESET}  http://localhost:8081/docs"
echo -e "  ${GREEN}SOC pipeline   ${RESET}  http://localhost:8082/docs"
echo -e "  ${GREEN}Dashboard      ${RESET}  http://localhost:5173"
echo ""
echo -e "  ${CYAN}Ctrl+K${RESET} inside the dashboard opens the AI analyst chat."
echo -e "  ${CYAN}Ctrl+C${RESET} here stops all services.\n"

# ── Graceful shutdown ──────────────────────────────────────────────────────────
cleanup() {
    echo -e "\n${YELLOW}Stopping services…${RESET}"
    kill "$SIEM_PID" "$SOC_PID" "$DASH_PID" 2>/dev/null || true
    wait "$SIEM_PID" "$SOC_PID" "$DASH_PID" 2>/dev/null || true
    success "All services stopped."
    exit 0
}

trap cleanup INT TERM
wait
