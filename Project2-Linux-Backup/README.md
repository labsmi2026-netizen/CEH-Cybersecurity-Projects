# Project 2 — Linux Backup Automation

A Bash script that automates secure backups of critical system directories, verifies integrity with SHA-256 checksums, and runs on a schedule via cron.

## What it does

- Backs up critical system directories (`/etc`, `/var/log`)
- Generates SHA-256 checksums for integrity verification
- Compresses backups into timestamped archives
- Runs automatically on a schedule via cron
- Logs each run for auditability

## Key lesson

The report documents a real incident: an early version of the script backed up its own destination folder, causing a **recursive backup loop that filled the disk (143 GB)**. The fix — excluding the backup directory from the source with `--exclude` — is explained in detail, along with the restoration process. A good example of catching and resolving a real automation bug.

## Usage

```bash
# Run the backup manually
./backup.sh

# Verify a backup's integrity
sha256sum -c checksum_<timestamp>.sha256
```

To schedule it, add a cron entry (example — daily at 2 AM):
0 2 * * * /home/kalibaba/backup_project/backup.sh
## Environment

Kali Linux, VMware Workstation, isolated lab.

## Files

- `backup.sh` — the backup automation script
- `Project2_Backup_Report.pdf` — full technical report

## Stack

Bash · cron · `tar`, `sha256sum`

---
*Performed in an authorized lab environment for educational purposes.*
