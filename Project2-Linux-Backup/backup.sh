#!/bin/bash
# ============================================================
# Linux Backup Automation Script - Cybersecurity Project 2
# Author  : kalibaba
# Machine : kalibaba@Kalibaba
# Date    : June 2026
# ============================================================

# ── CONFIGURATION ───────────────────────────────────────────
BACKUP_SOURCE_DIRS=("/etc" "/home" "/var/log")
BACKUP_DEST="/home/kalibaba/backup_project/backups"
LOG_FILE="/home/kalibaba/backup_project/backup.log"
MAX_BACKUPS=7
BACKUP_PREFIX="backup"

# ── COLOURS ─────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

# ── LOGGING ─────────────────────────────────────────────────
log() {
    local level="$1"; shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

info()    { log "INFO " "${GREEN}$*${NC}"; }
warn()    { log "WARN " "${YELLOW}$*${NC}"; }
error()   { log "ERROR" "${RED}$*${NC}"; }
section() { log "----" "${BLUE}${BOLD}=== $* ===${NC}"; }

# ── BANNER ──────────────────────────────────────────────────
print_banner() {
    echo -e "${BLUE}${BOLD}"
    echo "============================================================"
    echo "       LINUX BACKUP AUTOMATION TOOL"
    echo "       kalibaba@Kalibaba — Cybersecurity Project 2"
    echo "============================================================"
    echo -e "${NC}"
}

# ── INIT ────────────────────────────────────────────────────
init() {
    section "Initialisation"
    mkdir -p "$BACKUP_DEST"
    touch "$LOG_FILE"
    info "Backup destination : $BACKUP_DEST"
    info "Log file           : $LOG_FILE"
    info "Max backups kept   : $MAX_BACKUPS"
    info "Hostname           : $(hostname)"
    info "User               : $(whoami)"
    info "Date               : $(date)"
}

# ── DISK SPACE CHECK ────────────────────────────────────────
check_disk_space() {
    section "Disk Space Check"
    local available_kb
    available_kb=$(df -k "$BACKUP_DEST" | awk 'NR==2 {print $4}')
    local available_gb=$(( available_kb / 1024 / 1024 ))
    info "Available disk space: ${available_gb} GB"
    df -h "$BACKUP_DEST" | tee -a "$LOG_FILE"
    if [[ $available_kb -lt 524288 ]]; then
        warn "Low disk space! Less than 512MB available."
    else
        info "Disk space is sufficient."
    fi
}

# ── PERFORM BACKUP ──────────────────────────────────────────
perform_backup() {
    section "Performing Backup"
    local date_stamp
    date_stamp=$(date '+%Y%m%d_%H%M%S')
    local backup_name="${BACKUP_PREFIX}_${date_stamp}"
    local backup_path="${BACKUP_DEST}/${backup_name}"
    local success=0
    local failed=0

    mkdir -p "$backup_path"
    info "Backup folder created: $backup_path"

    for src in "${BACKUP_SOURCE_DIRS[@]}"; do
        if [[ ! -d "$src" ]]; then
            warn "Source directory not found, skipping: $src"
            (( failed++ )) || true
            continue
        fi
        local dest_dir="${backup_path}${src}"
        mkdir -p "$dest_dir"
        info "Backing up: $src -> $dest_dir"
        if rsync -aAX --delete \
            --exclude='/proc/*' \
            --exclude='/sys/*' \
            --exclude='/dev/*' \
            --exclude='/run/*' \
            --exclude='/tmp/*' \
            "$src/" "$dest_dir/" 2>>"$LOG_FILE"; then
            info "  SUCCESS: $src backed up"
            (( success++ )) || true
        else
            error "  FAILED: $src could not be backed up"
            (( failed++ )) || true
        fi
    done

    # ── COMPRESS ────────────────────────────────────────────
    section "Compressing Backup"
    local archive="${backup_path}.tar.gz"
    info "Creating compressed archive: $archive"
    if tar -czf "$archive" -C "$BACKUP_DEST" "$backup_name" 2>>"$LOG_FILE"; then
        local size
        size=$(du -sh "$archive" | cut -f1)
        info "Archive created: $archive (Size: $size)"
        rm -rf "$backup_path"
        info "Temporary folder removed."
    else
        error "Compression failed!"
    fi

    # ── CHECKSUM ────────────────────────────────────────────
    section "Generating SHA-256 Checksum"
    local checksum_file="${BACKUP_DEST}/checksum_${date_stamp}.sha256"
    sha256sum "$archive" > "$checksum_file"
    info "Checksum file: $checksum_file"
    cat "$checksum_file" | tee -a "$LOG_FILE"

    # ── SUMMARY ─────────────────────────────────────────────
    section "Backup Summary"
    info "Directories succeeded : $success"
    info "Directories failed    : $failed"
    info "Archive               : $archive"
    info "Timestamp             : $date_stamp"
}

# ── ROTATE OLD BACKUPS ──────────────────────────────────────
rotate_backups() {
    section "Rotating Old Backups"
    local count
    count=$(find "$BACKUP_DEST" -maxdepth 1 -name "${BACKUP_PREFIX}_*.tar.gz" | wc -l)
    info "Current backup count: $count (max allowed: $MAX_BACKUPS)"
    if [[ $count -gt $MAX_BACKUPS ]]; then
        local to_delete=$(( count - MAX_BACKUPS ))
        info "Removing $to_delete old backup(s)..."
        find "$BACKUP_DEST" -maxdepth 1 -name "${BACKUP_PREFIX}_*.tar.gz" \
            | sort | head -n "$to_delete" \
            | while read -r old; do
                rm -f "$old"
                info "  Deleted: $old"
            done
    else
        info "No rotation needed."
    fi
}

# ── VERIFY INTEGRITY ────────────────────────────────────────
verify_backup() {
    section "Verifying Backup Integrity"
    local latest
    latest=$(find "$BACKUP_DEST" -maxdepth 1 -name "${BACKUP_PREFIX}_*.tar.gz" | sort | tail -1)
    if [[ -z "$latest" ]]; then
        warn "No backup found to verify."
        return
    fi
    info "Verifying: $latest"
    if tar -tzf "$latest" > /dev/null 2>&1; then
        info "  INTEGRITY CHECK PASSED: $latest"
    else
        error "  INTEGRITY CHECK FAILED: $latest"
    fi
    info "Backup file size: $(du -sh "$latest" | cut -f1)"
    info "Files in archive: $(tar -tzf "$latest" | wc -l)"
}

# ── LIST BACKUPS ────────────────────────────────────────────
list_backups() {
    section "Available Backups"
    echo -e "${BOLD}Archives in $BACKUP_DEST:${NC}"
    ls -lh "$BACKUP_DEST"/*.tar.gz 2>/dev/null || warn "No backup archives found."
    echo ""
    echo -e "${BOLD}Checksum files:${NC}"
    ls -lh "$BACKUP_DEST"/*.sha256 2>/dev/null || warn "No checksum files found."
}

# ── MAIN ────────────────────────────────────────────────────
main() {
    local start_time
    start_time=$(date +%s)

    print_banner
    init
    check_disk_space
    perform_backup
    rotate_backups
    verify_backup
    list_backups

    local end_time elapsed
    end_time=$(date +%s)
    elapsed=$(( end_time - start_time ))

    section "BACKUP COMPLETED SUCCESSFULLY"
    info "Total time  : ${elapsed} seconds"
    info "Log saved   : $LOG_FILE"
}

main "$@"
