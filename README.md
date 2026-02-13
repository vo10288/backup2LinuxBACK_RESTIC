<div align="center">

# 🛡️ Backup System v3.0

**Enterprise backup solution powered by Restic + Backrest**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB.svg?logo=python&logoColor=white)](https://python.org)
[![Restic](https://img.shields.io/badge/Restic-0.17+-00ADD8.svg?logo=go&logoColor=white)](https://restic.net)
[![Linux](https://img.shields.io/badge/Platform-Linux-FCC624.svg?logo=linux&logoColor=black)](https://kernel.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

*Deduplication · Native Encryption · Ransomware Detection · Web UI · Multi-Cloud*

[Features](#-features) · [Quick Start](#-quick-start) · [Configuration](#-configuration) · [Backrest UI](#-backrest-webui) · [Italiano 🇮🇹](#italiano)

</div>

---

## 🎯 Overview

A complete backup system for mixed Linux/Windows environments (SMBs with 10-50 endpoints). Built on **Restic** for efficient, encrypted backups and **Backrest** for a modern web interface.

```
  Windows Machines (CIFS)              Linux Backup Server
  ┌─────────────────────┐            ┌─────────────────────────────────┐
  │ //fileserver/Data   │──mount────▶│  Anomaly Detection              │
  │ //pc01/C$           │   (ro)     │         │                       │
  │ //pc02/C$           │            │         ▼                       │
  │ //pc03/C$           │            │  ┌─────────────────────┐        │
  │ //pc04/C$           │            │  │    RESTIC BACKUP    │        │
  └─────────────────────┘            │  │  • Deduplication    │        │
                                     │  │  • AES-256 encrypt  │        │
                                     │  │  • Incremental      │        │
                                     │  └──────────┬──────────┘        │
                                     │             │                   │
                                     │             ▼                   │
                                     │  ┌─────────────────────┐        │
                                     │  │ RESTIC REPOSITORY   │        │
                                     │  │ Local / S3 / B2 /   │        │
                                     │  │ Azure / GCS / SFTP  │        │
                                     │  └─────────────────────┘        │
                                     │                                 │
                                     │  ┌─────────────────────┐        │
                                     │  │  BACKREST WebUI     │────────┼──▶ :9898
                                     │  │  Browse & Restore   │        │
                                     │  └─────────────────────┘        │
                                     └─────────────────────────────────┘
```

## ✨ Features

### 🚀 Restic Engine
- **Block-level deduplication** — 60-80% storage savings
- **Native AES-256 encryption** — no external tools needed
- **Immutable snapshots** — unlimited versioning
- **Multi-backend** — local, SFTP, S3, B2, Azure, GCS, REST server

### 🛡️ Security
- **Ransomware detection** — blocks backup if suspicious patterns found
- **Anomaly detection** — alerts on unusual file changes
- **Pre-check** — verifies source availability before backup
- **Integrity verification** — periodic `restic check`

### 📊 Monitoring
- **Backrest WebUI** — browse snapshots, restore files, view logs
- **JSON reports** — 90-day history
- **Notifications** — email, webhook (Slack/Discord/Teams), Shoutrrr

### 🔧 Operations
- **Automatic retention** — daily/weekly/monthly/yearly policies
- **Parallel backup** — multiple sources simultaneously
- **Graceful recovery** — retry with exponential backoff

## 🚀 Quick Start

### Prerequisites

- Linux server (Ubuntu 22.04+ / Debian 12+ recommended)
- Python 3.10+
- Root access
- Storage for repository (local disk, NAS, or cloud)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/backup-system.git
cd backup-system

# 2. Run setup (as root)
sudo bash setup.sh

# 3. Edit configuration
sudo nano /etc/backup_system/config.yaml

# 4. Edit Windows credentials
sudo nano /etc/backup_system/creds_fileserver

# 5. Test in dry-run mode
# Set dry_run: true in config.yaml, then:
sudo python3 /opt/backup_system/backup.py

# 6. Start Backrest WebUI
sudo systemctl start backrest
# Open http://your-server:9898

# 7. Run first real backup
# Set dry_run: false, then:
sudo python3 /opt/backup_system/backup.py
```

### ⚠️ Important: Backup Your Password!

The file `/etc/backup_system/restic.password` is the **only key** to your data. Without it, your backups are **permanently unrecoverable**. Store a copy in a secure offline location.

## ⚙️ Configuration

All settings in `/etc/backup_system/config.yaml`.

### Windows Sources (CIFS)

```yaml
sources:
  - name: "FileServer-Data"
    enabled: true
    type: cifs
    unc: "//192.168.1.10/Data"
    host: "192.168.1.10"
    mount_point: /mnt/source/fileserver_data
    credentials_file: /etc/backup_system/creds_fileserver
    mount_options: "vers=3.0,seal,ro"
    exclude_patterns:
      - "*.tmp"
      - "$Recycle.Bin"
      - "System Volume Information"
    tags:
      - "fileserver"
      - "critical"
```

### Repository

```yaml
restic:
  # Local
  repository: /mnt/backup/restic-repo
  
  # NAS via SFTP
  repository: sftp:backup@nas:/volume1/restic
  
  # Amazon S3
  repository: s3:s3.amazonaws.com/my-bucket
  
  # Backblaze B2
  repository: b2:my-bucket:/restic
  
  password_file: /etc/backup_system/restic.password
```

### Retention Policy

```yaml
retention:
  keep_last: 3        # Last N snapshots
  keep_daily: 7       # One per day (7 days)
  keep_weekly: 4      # One per week (4 weeks)
  keep_monthly: 12    # One per month (12 months)
  keep_yearly: 2      # One per year (2 years)
```

### Anomaly Detection

```yaml
security:
  anomaly_detection:
    enabled: true
    max_change_percent: 50      # Block if >50% files changed
    max_new_files_percent: 40   # Block if >40% new files
    suspicious_extensions:
      - ".encrypted"
      - ".locked"
      - ".crypto"
      - ".ransom"
```

## 🖥️ Backrest WebUI

Backrest provides a modern web interface on port **9898**:

- **Dashboard** — repository stats, recent snapshots
- **Browse** — explore any snapshot's contents
- **Restore** — one-click file/folder recovery
- **Diff** — compare snapshots
- **Operations** — manual forget, prune, check

```bash
# Start
sudo systemctl start backrest

# Status
sudo systemctl status backrest

# Logs
journalctl -u backrest -f
```

## 📁 Project Structure

```
backup-system/
├── src/
│   ├── backup.py          # Main orchestrator
│   ├── core.py            # Mount/umount, utilities
│   ├── restic_wrapper.py  # Restic CLI wrapper
│   ├── security.py        # Anomaly detection
│   └── notify.py          # Notifications
├── examples/
│   └── config.yaml        # Example configuration
├── docs/
│   ├── ARCHITETTURA.md    # Architecture (Italian)
│   └── BACKREST.md        # Backrest setup guide
├── setup.sh               # Installer
├── requirements.txt
├── LICENSE
└── README.md
```

## 🔧 Useful Commands

```bash
# List snapshots
restic -r /mnt/backup/restic-repo snapshots

# Browse latest snapshot
restic -r /mnt/backup/restic-repo ls latest

# Restore specific file
restic -r /mnt/backup/restic-repo restore latest \
    --target /tmp/restore \
    --include "Users/john/Documents"

# Repository stats
restic -r /mnt/backup/restic-repo stats

# Manual integrity check
restic -r /mnt/backup/restic-repo check --read-data

# Diff between snapshots
restic -r /mnt/backup/restic-repo diff abc123 def456
```

## 🆚 Why Restic over rsync?

| Feature | rsync + partitions | Restic |
|---------|-------------------|--------|
| **Deduplication** | ❌ Full copies | ✅ Block-level |
| **Storage needed** | ~7x source data | ~1.2-1.5x source data |
| **Encryption** | External (LUKS) | ✅ Native AES-256 |
| **Versioning** | Limited by partitions | ✅ Unlimited |
| **Cloud support** | ❌ | ✅ S3, B2, Azure, GCS |
| **Verification** | Manual | ✅ `restic check` |
| **Web UI** | ❌ | ✅ Backrest |

---

## Italiano

<details>
<summary>🇮🇹 Clicca per la documentazione in italiano</summary>

### Panoramica

Sistema di backup enterprise per ambienti misti Linux/Windows. Utilizza **Restic** per backup efficienti con deduplicazione e crittografia nativa, e **Backrest** per un'interfaccia web moderna.

### Vantaggi rispetto a rsync

- **Deduplicazione**: risparmio 60-80% spazio disco
- **Crittografia nativa**: AES-256 senza dipendenze esterne
- **Snapshot immutabili**: versioning illimitato
- **Multi-cloud**: S3, B2, Azure, GCS, SFTP
- **WebUI**: Backrest per gestione e restore

### Installazione rapida

```bash
git clone https://github.com/YOUR_USERNAME/backup-system.git
cd backup-system
sudo bash setup.sh
sudo nano /etc/backup_system/config.yaml
sudo systemctl start backrest
```

### Documentazione

- [Architettura](docs/ARCHITETTURA.md)
- [Configurazione Backrest](docs/BACKREST.md)

</details>

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE).

## Acknowledgments

- [Restic](https://restic.net) — Fast, secure, efficient backup program
- [Backrest](https://github.com/garethgeorge/backrest) — Web UI for restic
