#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  SETUP — Backup System v3.0 (Restic + Backrest)
# ═══════════════════════════════════════════════════════════════
#  Installa e configura:
#    - Restic (backup engine)
#    - Backrest (WebUI)
#    - Script di backup Python
#    - Crontab per esecuzione notturna
#    - Systemd service per Backrest
#
#  Eseguire come root:  sudo bash setup.sh
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

INSTALL_DIR="/opt/backup_system"
CONFIG_DIR="/etc/backup_system"
LOG_DIR="/var/log/backup_system"
STATE_DIR="/var/lib/backup_system"
CACHE_DIR="/var/cache/restic"
BACKREST_DIR="/var/lib/backrest"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Versioni
RESTIC_VERSION="0.17.3"
BACKREST_VERSION="1.7.1"

# Colori
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Backup System v3.0 — Restic + Backrest${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: Run as root (sudo bash setup.sh)${NC}"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH_RESTIC="amd64"; ARCH_BACKREST="amd64" ;;
    aarch64) ARCH_RESTIC="arm64"; ARCH_BACKREST="arm64" ;;
    armv7l)  ARCH_RESTIC="arm"; ARCH_BACKREST="arm" ;;
    *)       echo -e "${RED}Unsupported architecture: $ARCH${NC}"; exit 1 ;;
esac

# ─── 1. Dipendenze di sistema ─────────────────────────────
echo -e "${GREEN}[1/9]${NC} Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq \
    cifs-utils \
    smbclient \
    python3 \
    python3-pip \
    python3-yaml \
    curl \
    jq \
    bzip2

# ─── 2. Installa Restic ───────────────────────────────────
echo -e "${GREEN}[2/9]${NC} Installing Restic ${RESTIC_VERSION}..."
if ! command -v restic &> /dev/null || [[ $(restic version | grep -oP '\d+\.\d+\.\d+') != "$RESTIC_VERSION" ]]; then
    RESTIC_URL="https://github.com/restic/restic/releases/download/v${RESTIC_VERSION}/restic_${RESTIC_VERSION}_linux_${ARCH_RESTIC}.bz2"
    curl -sL "$RESTIC_URL" | bunzip2 > /usr/local/bin/restic
    chmod +x /usr/local/bin/restic
    echo "  ✓ Restic ${RESTIC_VERSION} installed"
else
    echo "  → Restic already installed"
fi
restic version

# ─── 3. Installa Backrest ─────────────────────────────────
echo -e "${GREEN}[3/9]${NC} Installing Backrest ${BACKREST_VERSION}..."
if ! command -v backrest &> /dev/null; then
    BACKREST_URL="https://github.com/garethgeorge/backrest/releases/download/v${BACKREST_VERSION}/backrest_Linux_${ARCH_BACKREST}.tar.gz"
    curl -sL "$BACKREST_URL" | tar xz -C /usr/local/bin backrest
    chmod +x /usr/local/bin/backrest
    echo "  ✓ Backrest ${BACKREST_VERSION} installed"
else
    echo "  → Backrest already installed"
fi
backrest --version || echo "  (version check not supported)"

# ─── 4. Crea directory ────────────────────────────────────
echo -e "${GREEN}[4/9]${NC} Creating directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$STATE_DIR"
mkdir -p "$CACHE_DIR"
mkdir -p "$BACKREST_DIR"
mkdir -p /mnt/source
mkdir -p /mnt/backup

# ─── 5. Copia script Python ───────────────────────────────
echo -e "${GREEN}[5/9]${NC} Installing backup scripts..."
SRC_DIR="$SCRIPT_DIR/src"
for PY_FILE in backup.py core.py restic_wrapper.py security.py notify.py; do
    if [[ -f "$SRC_DIR/$PY_FILE" ]]; then
        cp "$SRC_DIR/$PY_FILE" "$INSTALL_DIR/"
        chmod 700 "$INSTALL_DIR/$PY_FILE"
        echo "  ✓ $PY_FILE"
    elif [[ -f "$SCRIPT_DIR/$PY_FILE" ]]; then
        cp "$SCRIPT_DIR/$PY_FILE" "$INSTALL_DIR/"
        chmod 700 "$INSTALL_DIR/$PY_FILE"
        echo "  ✓ $PY_FILE"
    else
        echo -e "  ${YELLOW}⚠ $PY_FILE not found${NC}"
    fi
done

# ─── 6. Configurazione ────────────────────────────────────
echo -e "${GREEN}[6/9]${NC} Setting up configuration..."

# Config principale
if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
    if [[ -f "$SCRIPT_DIR/config.yaml" ]]; then
        cp "$SCRIPT_DIR/config.yaml" "$CONFIG_DIR/"
    elif [[ -f "$SCRIPT_DIR/examples/config.yaml" ]]; then
        cp "$SCRIPT_DIR/examples/config.yaml" "$CONFIG_DIR/"
    fi
    echo -e "  ${YELLOW}→ config.yaml created — EDIT BEFORE FIRST RUN!${NC}"
else
    echo "  → config.yaml already exists"
fi

# Password Restic
RESTIC_PWD_FILE="$CONFIG_DIR/restic.password"
if [[ ! -f "$RESTIC_PWD_FILE" ]]; then
    # Genera password casuale sicura
    head -c 32 /dev/urandom | base64 | tr -d '\n' > "$RESTIC_PWD_FILE"
    chmod 600 "$RESTIC_PWD_FILE"
    echo -e "  ${YELLOW}→ Restic password generated: $RESTIC_PWD_FILE${NC}"
    echo -e "  ${RED}   BACKUP THIS FILE SECURELY! Without it, data is UNRECOVERABLE!${NC}"
else
    echo "  → Restic password file exists"
fi

# Credenziali CIFS
for CRED in creds_fileserver creds_domain_admin; do
    CRED_PATH="$CONFIG_DIR/$CRED"
    if [[ ! -f "$CRED_PATH" ]]; then
        cat > "$CRED_PATH" <<'CRED'
username=backup_user
password=CHANGE_ME
domain=WORKGROUP
CRED
        chmod 600 "$CRED_PATH"
        echo -e "  ${YELLOW}→ Created $CRED (edit before use)${NC}"
    fi
done

# ─── 7. Crontab ───────────────────────────────────────────
echo -e "${GREEN}[7/9]${NC} Setting up crontab..."
CRON_LINE="30 2 * * * /usr/bin/python3 $INSTALL_DIR/backup.py -c $CONFIG_DIR/config.yaml >> $LOG_DIR/cron.log 2>&1"
(crontab -l 2>/dev/null | grep -v "backup.py" || true; echo "$CRON_LINE") | crontab -
echo "  → Backup scheduled: every night at 02:30"

# ─── 8. Systemd service per Backrest ──────────────────────
echo -e "${GREEN}[8/9]${NC} Setting up Backrest service..."
cat > /etc/systemd/system/backrest.service <<EOF
[Unit]
Description=Backrest — Restic Backup WebUI
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/backrest
Environment="BACKREST_PORT=0.0.0.0:9898"
Environment="BACKREST_DATA=$BACKREST_DIR"
Environment="XDG_CACHE_HOME=$CACHE_DIR"
Restart=on-failure
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable backrest.service
echo "  → Backrest service created"
echo "  → Start with: systemctl start backrest"

# ─── 9. Logrotate ─────────────────────────────────────────
echo -e "${GREEN}[9/9]${NC} Setting up logrotate..."
cat > /etc/logrotate.d/backup_system <<'LR'
/var/log/backup_system/*.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
}
LR

# ─── Inizializza repository Restic ────────────────────────
echo ""
echo -e "${CYAN}Initializing Restic repository...${NC}"
REPO_PATH=$(grep -oP 'repository:\s*\K[^\s]+' "$CONFIG_DIR/config.yaml" 2>/dev/null || echo "/mnt/backup/restic-repo")

if [[ "$REPO_PATH" == /* ]]; then
    # Repository locale
    mkdir -p "$REPO_PATH"
    if [[ ! -f "$REPO_PATH/config" ]]; then
        RESTIC_PASSWORD_FILE="$RESTIC_PWD_FILE" restic -r "$REPO_PATH" init
        echo -e "  ${GREEN}✓ Repository initialized: $REPO_PATH${NC}"
    else
        echo "  → Repository already exists"
    fi
fi

# ─── Riepilogo ────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Installation complete!${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "  NEXT STEPS:"
echo ""
echo "  1. Edit configuration:"
echo "     nano $CONFIG_DIR/config.yaml"
echo ""
echo "  2. Edit Windows credentials:"
echo "     nano $CONFIG_DIR/creds_fileserver"
echo "     nano $CONFIG_DIR/creds_domain_admin"
echo ""
echo "  3. Test backup (dry-run):"
echo "     Set 'dry_run: true' in config.yaml, then:"
echo "     python3 $INSTALL_DIR/backup.py -c $CONFIG_DIR/config.yaml"
echo ""
echo "  4. Start Backrest WebUI:"
echo "     systemctl start backrest"
echo "     Open: http://$(hostname -I | awk '{print $1}'):9898"
echo ""
echo "  5. Run first real backup:"
echo "     Set 'dry_run: false' and run:"
echo "     python3 $INSTALL_DIR/backup.py -c $CONFIG_DIR/config.yaml"
echo ""
echo -e "  ${RED}IMPORTANT: Backup your Restic password file!${NC}"
echo "     $RESTIC_PWD_FILE"
echo "     Without it, your backups are UNRECOVERABLE!"
echo ""
echo "  Cron: every night at 02:30"
echo "  Logs: $LOG_DIR/"
echo "  Backrest: http://localhost:9898"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
