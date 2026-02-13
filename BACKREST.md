# Configurazione Backrest

Backrest è la WebUI per gestire i backup Restic. Questa guida spiega come configurarlo e usarlo.

## Avvio

```bash
# Avvia il servizio
sudo systemctl start backrest

# Abilita all'avvio
sudo systemctl enable backrest

# Verifica stato
sudo systemctl status backrest

# Log
journalctl -u backrest -f
```

## Accesso WebUI

Apri nel browser: `http://IP_SERVER:9898`

Al primo accesso, Backrest chiede di creare un account admin.

## Configurazione Repository

### Aggiungere il repository esistente

1. Vai su **Settings** → **Repositories**
2. Click **Add Repository**
3. Compila:
   - **Name**: `backup-principale`
   - **URI**: `/mnt/backup/restic-repo` (o il path del tuo repo)
   - **Password**: (la password in `/etc/backup_system/restic.password`)
4. Click **Save**

### Repository remoti

Per repository su cloud o NAS:

```
# S3
s3:s3.amazonaws.com/bucket-name

# Backblaze B2
b2:bucket-name:/path

# SFTP
sftp:user@host:/path/to/repo

# REST Server
rest:http://nas.local:8000/
```

## Configurazione Piani di Backup

Backrest può anche schedulare i backup (alternativa al nostro script cron).

### Aggiungere un piano

1. Vai su **Plans** → **Add Plan**
2. Configura:
   - **Name**: `backup-fileserver`
   - **Repository**: seleziona il repo creato
   - **Paths**: `/mnt/source/fileserver_dati`
   - **Excludes**: `*.tmp`, `$Recycle.Bin`, etc.
   - **Schedule**: `0 2 * * *` (ogni notte alle 2)
   - **Retention**: configura keep_daily, keep_weekly, etc.

### Nota importante

Se usi il nostro script `backup.py` con cron, **non** configurare gli schedule in Backrest per evitare duplicati. Usa Backrest solo per:
- Monitoraggio
- Browse snapshot
- Restore manuale

## Operazioni comuni

### Visualizzare snapshot

1. Vai su **Snapshots**
2. Filtra per repository, tag, o data
3. Click su uno snapshot per vedere i dettagli

### Esplorare contenuto

1. Seleziona uno snapshot
2. Click **Browse**
3. Naviga nell'albero dei file
4. Click su un file per vedere anteprima/metadati

### Ripristinare file

1. Naviga allo snapshot desiderato
2. Seleziona file/cartelle da ripristinare
3. Click **Restore**
4. Scegli la destinazione
5. Conferma

### Confrontare snapshot

1. Seleziona due snapshot
2. Click **Diff**
3. Visualizza file aggiunti/modificati/rimossi

## Manutenzione

### Prune manuale

1. Vai su **Operations**
2. Seleziona repository
3. Click **Prune**
4. Conferma

### Check integrità

1. Vai su **Operations**
2. Seleziona repository
3. Click **Check**
4. Opzionale: abilita "Read data" per verifica completa

## Variabili d'ambiente

Il servizio systemd usa queste variabili:

```bash
# Porta (default 9898)
BACKREST_PORT=0.0.0.0:9898

# Directory dati
BACKREST_DATA=/var/lib/backrest

# Cache
XDG_CACHE_HOME=/var/cache/restic
```

Per modificarle:

```bash
sudo systemctl edit backrest
```

Aggiungi:
```ini
[Service]
Environment="BACKREST_PORT=0.0.0.0:8080"
```

Poi riavvia:
```bash
sudo systemctl daemon-reload
sudo systemctl restart backrest
```

## Sicurezza

### Accesso remoto

Di default Backrest ascolta su `0.0.0.0:9898`. Per limitare:

```bash
# Solo localhost
Environment="BACKREST_PORT=127.0.0.1:9898"
```

### Reverse proxy con HTTPS

Esempio con nginx:

```nginx
server {
    listen 443 ssl;
    server_name backup.example.com;
    
    ssl_certificate /etc/ssl/certs/backup.crt;
    ssl_certificate_key /etc/ssl/private/backup.key;
    
    location / {
        proxy_pass http://127.0.0.1:9898;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Troubleshooting

### "Repository not found"

- Verifica che il path sia corretto
- Verifica che il repository sia inizializzato (`restic -r /path snapshots`)
- Verifica la password

### "Permission denied"

- Backrest gira come root (vedi servizio systemd)
- Verifica permessi sulla directory del repository

### WebUI non raggiungibile

```bash
# Verifica che il servizio sia attivo
sudo systemctl status backrest

# Verifica la porta
sudo ss -tlnp | grep 9898

# Verifica firewall
sudo ufw status
sudo ufw allow 9898/tcp
```
