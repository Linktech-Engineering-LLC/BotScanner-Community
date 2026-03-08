#!/usr/bin/env bash

# ============================================================
# BotScanner Python 3.12 Virtual Environment Bootstrap Script
# Creates a clean venv, installs dependencies, and logs actions.
# Logs written to Logs/bootstrap.log
# ============================================================

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$PROJECT_ROOT/Logs"
LOG_FILE="$LOG_DIR/bootstrap.log"

mkdir -p "$LOG_DIR"

timestamp() {
    date +"%Y-%m-%d %H:%M:%S"
}

log() {
    echo "$(timestamp)  $1" | tee -a "$LOG_FILE"
}

log "===== Starting BotScanner Python 3.12 bootstrap ====="

# ------------------------------------------------------------
# Verify Python 3.12 exists
# ------------------------------------------------------------
if ! command -v python3.12 >/dev/null 2>&1; then
    log "ERROR: python3.12 not found. Install Python 3.12 before running this script."
    exit 1
fi

log "Found Python 3.12 at: $(command -v python3.12)"

# ------------------------------------------------------------
# Remove any existing venv
# ------------------------------------------------------------
if [ -d "$PROJECT_ROOT/.venv" ]; then
    log "Removing existing virtual environment: $PROJECT_ROOT/.venv"
    rm -rf "$PROJECT_ROOT/.venv"
fi

# ------------------------------------------------------------
# Create new venv
# ------------------------------------------------------------
log "Creating new Python 3.12 virtual environment..."
python3.12 -m venv "$PROJECT_ROOT/.venv"

if [ ! -f "$PROJECT_ROOT/.venv/bin/python" ]; then
    log "ERROR: venv creation failed. No interpreter found in .venv."
    exit 1
fi

log "Virtual environment created successfully."

# ------------------------------------------------------------
# Activate venv
# ------------------------------------------------------------
log "Activating virtual environment..."
source "$PROJECT_ROOT/.venv/bin/activate"

# ------------------------------------------------------------
# Upgrade pip
# ------------------------------------------------------------
log "Upgrading pip..."
pip install --upgrade pip >> "$LOG_FILE" 2>&1
log "pip upgraded."

# ------------------------------------------------------------
# Install dependencies
# ------------------------------------------------------------
REQ_FILE="$PROJECT_ROOT/requirements.txt"

if [ ! -f "$REQ_FILE" ]; then
    log "ERROR: requirements.txt not found at $REQ_FILE"
    exit 1
fi

log "Installing dependencies from requirements.txt..."
pip install -r "$REQ_FILE" >> "$LOG_FILE" 2>&1

if [ $? -ne 0 ]; then
    log "ERROR: Dependency installation failed. Check bootstrap.log for details."
    exit 1
fi

log "Dependencies installed successfully."

# ------------------------------------------------------------
# Verify interpreter version inside venv
# ------------------------------------------------------------
VENV_PY_VERSION=$(python --version 2>&1)
log "Venv Python version: $VENV_PY_VERSION"

if [[ "$VENV_PY_VERSION" != Python\ 3.12* ]]; then
    log "ERROR: venv is not using Python 3.12. Something is wrong."
    exit 1
fi

# ------------------------------------------------------------
# Completion
# ------------------------------------------------------------
log "Bootstrap complete."
log "===== End of bootstrap ====="

echo
echo "Bootstrap finished. Log written to: $LOG_FILE"
