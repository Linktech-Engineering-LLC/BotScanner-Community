#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_BASE="${SCRIPT_NAME%.*}"   # strip extension
LOG_DIR="Logs"
LOGFILE="$LOG_DIR/${SCRIPT_BASE}.log"

TS="$(date +"%Y-%m-%d_%H-%M-%S")"
ARCHIVE_DIR="archive/cleanup_$TS"
ROOT_DIRS=("config" "utils" "net" "firewall" "tests")

mkdir -p "$ARCHIVE_DIR"
mkdir -p "$LOG_DIR"

log() {
    echo "[$(date +"%Y-%m-%d %H:%M:%S")] $1" | tee -a "$LOGFILE"
}

log "Starting cleanup run at $TS"
log "Archive directory: $ARCHIVE_DIR"
log "Log file: $LOGFILE"

log "Validating that no root-level modules are imported..."
if grep -R "^\s*from \(config\|utils\|net\|firewall\)" -n BotScanner/ | tee -a "$LOGFILE"; then
    log "ERROR: Found imports referencing root-level modules. Aborting."
    exit 1
fi

log "No unsafe imports detected."

log "Moving duplicate root-level directories into archive..."
for d in "${ROOT_DIRS[@]}"; do
    if [[ -d "$d" ]]; then
        log "ACTION: Moving $d -> $ARCHIVE_DIR/$d"
        mv "$d" "$ARCHIVE_DIR/"
    else
        log "SKIP: $d does not exist at root."
    fi
done

log "Cleanup complete."
log "All actions appended to: $LOGFILE"
