#!/usr/bin/env bash

# ============================================================
# BotScanner Cleanup Script
# Removes VCS directories, caches, old venvs, and metadata.
# Logs all actions to Logs/cleanup.log
# ============================================================

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$PROJECT_ROOT/Logs"
LOG_FILE="$LOG_DIR/cleanup.log"

mkdir -p "$LOG_DIR"

timestamp() {
    date +"%Y-%m-%d %H:%M:%S"
}

log() {
    echo "$(timestamp)  $1" | tee -a "$LOG_FILE"
}

log "===== Starting BotScanner cleanup ====="

# ------------------------------------------------------------
# Remove .svn and .git directories
# ------------------------------------------------------------
log "Scanning for .svn and .git directories..."

find "$PROJECT_ROOT" -type d \( -name ".svn" -o -name ".git" \) | while read -r dir; do
    log "Removing VCS directory: $dir"
    rm -rf "$dir"
done

# ------------------------------------------------------------
# Remove __pycache__ directories
# ------------------------------------------------------------
log "Removing __pycache__ directories..."

find "$PROJECT_ROOT" -type d -name "__pycache__" | while read -r dir; do
    log "Removing cache directory: $dir"
    rm -rf "$dir"
done

# ------------------------------------------------------------
# Remove .egg-info metadata
# ------------------------------------------------------------
log "Removing .egg-info directories..."

find "$PROJECT_ROOT" -type d -name "*.egg-info" | while read -r dir; do
    log "Removing egg-info: $dir"
    rm -rf "$dir"
done

# ------------------------------------------------------------
# Remove old virtual environments
# ------------------------------------------------------------
log "Checking for old virtual environments..."

if [ -d "$PROJECT_ROOT/.venv" ]; then
    log "Removing old venv: $PROJECT_ROOT/.venv"
    rm -rf "$PROJECT_ROOT/.venv"
fi

if [ -d "$PROJECT_ROOT/venv" ]; then
    log "Removing old venv: $PROJECT_ROOT/venv"
    rm -rf "$PROJECT_ROOT/venv"
fi

# ------------------------------------------------------------
# Completion
# ------------------------------------------------------------
log "Cleanup complete."
log "===== End of cleanup ====="

echo
echo "Cleanup finished. Log written to: $LOG_FILE"
