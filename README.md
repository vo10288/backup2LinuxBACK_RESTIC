<div align="center">
<img width="2400" height="1260" alt="backup-system-map-linkedin" src="https://github.com/user-attachments/assets/d5b6f3b3-d90c-4fc0-b267-30132b273289" />


# 🛡️ Backup System v3.0

**Enterprise backup solution powered by Restic + Backrest**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB.svg?logo=python&logoColor=white)](https://python.org)
[![Restic](https://img.shields.io/badge/Restic-0.17+-00ADD8.svg?logo=go&logoColor=white)](https://restic.net)
[![Linux](https://img.shields.io/badge/Platform-Linux-FCC624.svg?logo=linux&logoColor=black)](https://kernel.org)
[![Security](https://img.shields.io/badge/Security-Hardened-success.svg?logo=shield&logoColor=white)](#-security)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

*Deduplication · Native Encryption · Ransomware Detection · Web UI · Multi-Cloud*

[Features](#-features) · [Quick Start](#-quick-start) · [Configuration](#-configuration) · [Security](#-security) · [Backrest UI](#-backrest-webui) · [Italiano 🇮🇹](#italiano)

![Uploading backup-system-map-linkedin.png…]()

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
- **Hardened code** — input validation, no shell injection, path traversal protection

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

## 🔒 Security

This project follows security best practices to protect your backup infrastructure.

### Security Features

| Protection | Description |
|------------|-------------|
| **Input Validation** | All external inputs validated with whitelist patterns |
| **Path Traversal Protection** | `../` and absolute paths blocked, all paths normalized |
| **Command Injection Prevention** | No `shell=True`, all commands as lists |
| **Log Injection Prevention** | Newlines and control characters sanitized |
| **Symlink Protection** | Directory scans don't follow symlinks |
| **Email Header Injection** | Headers sanitized to prevent SMTP attacks |
| **Credential Protection** | Files with 600 permissions, never logged |

### Validation Functions

The codebase includes dedicated security functions:

```python
# Path validation (prevents traversal)
validate_path(path, base_path=None, must_exist=False)
validate_subpath(subpath, base_path)

# Input sanitization
sanitize_log_message(msg)      # Log injection prevention
sanitize_tag(tag)              # Restic tag validation
sanitize_hostname(host)        # Hostname/IP validation
sanitize_source_name(name)     # Safe filenames
sanitize_email_header(text)    # SMTP header injection

# Protocol validation
validate_hostname(host)        # RFC-compliant hostname
validate_unc_path(unc)         # Windows UNC paths
validate_email(email)          # Email format
```

### Security Checklist

- [x] No `shell=True` in subprocess calls
- [x] All user inputs validated before use
- [x] Path traversal (`../`) blocked everywhere
- [x] Symlinks not followed during scans
- [x] Log messages sanitized (no newlines)
- [x] Credentials never appear in logs
- [x] Timeouts on all external operations
- [x] Length limits on all string inputs

### Reporting Vulnerabilities

If you discover a security vulnerability, please email **security@example.com** instead of opening a public issue.

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

### Securing Backrest

For production, put Backrest behind a reverse proxy with authentication:

```nginx
# /etc/nginx/sites-available/backrest
server {
    listen 443 ssl;
    server_name backup.example.com;
    
    ssl_certificate /etc/letsencrypt/live/backup.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/backup.example.com/privkey.pem;
    
    auth_basic "Backup System";
    auth_basic_user_file /etc/nginx/.htpasswd;
    
    location / {
        proxy_pass http://127.0.0.1:9898;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 📁 Project Structure

```
backup-system/
├── src/
│   ├── backup.py          # Main orchestrator
│   ├── core.py            # Mount/umount, utilities, security functions
│   ├── restic_wrapper.py  # Restic CLI wrapper with input validation
│   ├── security.py        # Anomaly detection, baseline management
│   └── notify.py          # Notifications with sanitization
├── examples/
│   └── config.yaml        # Example configuration
├── docs/
│   ├── ARCHITETTURA.md    # Architecture (Italian)
│   └── BACKREST.md        # Backrest setup guide
├── setup.sh               # Installer
├── requirements.txt       # Python dependencies
├── CONTRIBUTING.md        # Contribution guidelines
├── LICENSE                # MIT License
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

# Unlock stale locks
restic -r /mnt/backup/restic-repo unlock
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

### Sicurezza

Il codice è stato hardened contro:
- **Command Injection**: nessun uso di `shell=True`
- **Path Traversal**: validazione di tutti i path
- **Log Injection**: sanitizzazione dei messaggi
- **SMTP Injection**: validazione header email

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

When contributing security-related code:
1. Use the existing validation functions from `core.py`
2. Never use `shell=True` in subprocess
3. Always validate external inputs
4. Add appropriate length limits
5. Test with malicious inputs (path traversal, injection)

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE).

## Acknowledgments

- [Restic](https://restic.net) — Fast, secure, efficient backup program
- [Backrest](https://github.com/garethgeorge/backrest) — Web UI for restic
