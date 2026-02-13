# Architettura — Backup System v3.0 (Restic + Backrest)

## Panoramica

Il sistema utilizza **Restic** come motore di backup e **Backrest** come interfaccia web. Questa combinazione offre:

- **Deduplicazione** a livello di blocchi (risparmio 60-80% spazio)
- **Crittografia nativa** AES-256 (senza dipendenze esterne)
- **Snapshot immutabili** con versioning illimitato
- **WebUI professionale** per gestione e restore

## Componenti

```
┌─────────────────────────────────────────────────────────────────┐
│                         ORCHESTRATORE                           │
│                          backup.py                               │
│                              │                                   │
│    ┌─────────────┬──────────┼──────────┬─────────────┐          │
│    │             │          │          │             │          │
│    ▼             ▼          ▼          ▼             ▼          │
│ ┌──────┐   ┌─────────┐  ┌────────┐ ┌────────┐  ┌─────────┐     │
│ │core  │   │security │  │restic_ │ │notify  │  │Backrest │     │
│ │.py   │   │.py      │  │wrapper │ │.py     │  │(WebUI)  │     │
│ │      │   │         │  │.py     │ │        │  │         │     │
│ │Mount │   │Anomaly  │  │Backup  │ │Email   │  │Browse   │     │
│ │Umount│   │Detection│  │Restore │ │Webhook │  │Restore  │     │
│ │Check │   │Baseline │  │Forget  │ │Report  │  │Schedule │     │
│ └──────┘   └─────────┘  └────────┘ └────────┘  └─────────┘     │
│                              │                                   │
│                              ▼                                   │
│              ┌───────────────────────────────┐                  │
│              │      RESTIC REPOSITORY        │                  │
│              │   (crittografato, deduplicato)│                  │
│              │                               │                  │
│              │  Locale: /mnt/backup/repo     │                  │
│              │  Remote: S3, B2, SFTP, etc.   │                  │
│              └───────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────┘
```

## Flusso di Esecuzione

```
CRON 02:30
    │
    ▼
┌─ FASE 1: Inizializzazione
│   • Acquisisce lock file
│   • Carica configurazione
│   • Verifica/inizializza repository Restic
│   • Rimuove lock stale (restic unlock)
│
├─ FASE 2: Backup sorgenti (parallelo opzionale)
│   │
│   Per ogni sorgente:
│   │
│   ├── Pre-check: ping + smbclient
│   │   └── FAIL → skip sorgente
│   │
│   ├── Mount CIFS (ro, retry con backoff)
│   │   └── FAIL → skip sorgente
│   │
│   ├── Anomaly Detection:
│   │   ├── Scansiona file, dimensioni, estensioni
│   │   ├── Cerca estensioni ransomware
│   │   ├── Confronta con baseline precedente
│   │   └── BLOCCA se anomalia rilevata
│   │
│   ├── restic backup (con tag, esclusioni)
│   │   └── Deduplicazione automatica
│   │
│   └── Umount sorgente
│
├─ FASE 3: Retention Policy
│   • restic forget (applica keep_daily, keep_weekly, etc.)
│   • restic prune (rimuove dati non referenziati)
│
├─ FASE 4: Integrity Check (periodico, ogni 7 giorni)
│   • restic check --read-data-subset=5%
│
└─ FASE 5: Report e Notifiche
    • Salva report JSON
    • Aggiorna storico
    • Invia email/webhook
```

## Vantaggi vs rsync tradizionale

| Aspetto | rsync + partizioni | Restic |
|---------|-------------------|--------|
| **Storage** | N copie complete | 1 repo deduplicato |
| **Spazio** | ~700% dei dati | ~120-150% dei dati |
| **Versioni** | Limitate dal n° partizioni | Illimitate |
| **Crittografia** | Richiede LUKS | Nativa |
| **Restore** | Mount partizione + rsync | `restic restore` o WebUI |
| **Cloud** | ❌ | ✅ S3, B2, Azure, GCS |
| **Verifica** | Manuale | `restic check` |

## Sicurezza

### Crittografia

Restic utilizza:
- **AES-256-CTR** per cifrare i dati
- **Poly1305-AES** per autenticazione (MAC)
- La chiave deriva dalla password via **scrypt**

### Anomaly Detection

Prima di ogni backup, il sistema:
1. Scansiona la sorgente (file count, size, estensioni)
2. Cerca estensioni sospette (`.encrypted`, `.locked`, etc.)
3. Confronta con la baseline dell'ultimo backup
4. Se variazione > soglia → **BLOCCA** il backup

Questo preserva gli snapshot precedenti in caso di ransomware.

### Repository Immutabile

Gli snapshot Restic sono append-only per design. Un attaccante che compromette il server può al massimo:
- Aggiungere nuovi snapshot (che verranno rimossi dal prune)
- NON può modificare o cancellare snapshot esistenti senza la password

Per protezione aggiuntiva, considera:
- Repository su storage immutabile (S3 Object Lock, B2 Object Lock)
- Backup della password in luogo sicuro offline

## Backrest WebUI

Backrest gira come servizio systemd sulla porta **9898** e offre:

- **Dashboard**: stato repository, spazio usato, snapshot recenti
- **Snapshots**: lista, dettagli, confronto tra snapshot
- **Browse**: esplora il contenuto di qualsiasi snapshot
- **Restore**: ripristina file/cartelle con un click
- **Operations**: forget, prune, check manuali
- **Logs**: visualizzazione log in tempo reale

## File di Stato

| File | Percorso | Contenuto |
|------|----------|-----------|
| Config | `/etc/backup_system/config.yaml` | Configurazione completa |
| Password | `/etc/backup_system/restic.password` | Password repository |
| Credenziali | `/etc/backup_system/creds_*` | user/pass CIFS |
| Report | `/var/lib/backup_system/report_*.json` | Report singoli backup |
| Storico | `/var/lib/backup_system/history.json` | Ultimi 90 giorni |
| Baseline | `/var/lib/backup_system/baseline_*.json` | Stato per anomaly detection |
| Log | `/var/log/backup_system/backup_*.log` | Log completo |

## Requisiti Hardware

| Componente | Minimo | Consigliato |
|------------|--------|-------------|
| CPU | 2 core | 4+ core |
| RAM | 4 GB | 8+ GB |
| Storage OS | 50 GB SSD | 100 GB SSD |
| Storage Backup | 1.5x dati sorgente | 2x dati sorgente |
| Rete | 1 Gbps | 1 Gbps |

La deduplicazione di Restic riduce significativamente lo spazio necessario rispetto a soluzioni tradizionali.
