#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
  BACKUP SYSTEM v3.0 — Restic + Backrest
═══════════════════════════════════════════════════════════════
  Funzionalità:
    ✓ Restic: deduplicazione, crittografia nativa, snapshot
    ✓ Backrest: WebUI per gestione e monitoraggio
    ✓ Mount share Windows CIFS (sola lettura)
    ✓ Anomaly/Ransomware detection pre-backup
    ✓ Retention policy automatica (daily/weekly/monthly/yearly)
    ✓ Verifica integrità repository periodica
    ✓ Notifiche email + webhook + shoutrrr
    ✓ Backup parallelo multi-sorgente

  Requisiti:
    Python 3.10+, restic, cifs-utils, smbclient

  Eseguire come root.
═══════════════════════════════════════════════════════════════
"""

import sys
import os
import signal
import logging
import fcntl
import argparse
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml

# Aggiungi la directory dello script al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import (
    ensure_directories, pre_check_source, mount_cifs_source,
    safe_umount, is_mounted, format_bytes, format_duration
)
from restic_wrapper import ResticWrapper, BackupStats
from security import check_for_anomalies, should_skip_integrity_check, mark_integrity_check_done
from notify import save_report, send_all_notifications, build_report_text


# ═══════════════════════════════════════════════════════════
#  CONFIG + LOGGING
# ═══════════════════════════════════════════════════════════

def load_config(path: str) -> dict:
    """Carica e valida la configurazione."""
    config_path = Path(path)
    if not config_path.exists():
        sys.exit(f"[FATAL] Config not found: {path}")
    
    with open(config_path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)

    # Validazione base
    assert "sources" in cfg, "Missing 'sources' section"
    assert "restic" in cfg, "Missing 'restic' section"
    assert cfg["restic"].get("repository"), "Missing restic repository"
    
    return cfg


def setup_logging(cfg: dict) -> logging.Logger:
    """Configura il logging."""
    log_dir = Path(cfg["general"].get("log_dir", "/var/log/backup_system"))
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"backup_{datetime.now():%Y%m%d_%H%M%S}.log"

    logger = logging.getLogger("backup_system")
    logger.setLevel(getattr(logging, cfg["general"].get("log_level", "INFO")))

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-7s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    return logger


# ═══════════════════════════════════════════════════════════
#  LOCK FILE
# ═══════════════════════════════════════════════════════════

class LockFile:
    """Gestione lock file per prevenire esecuzioni parallele."""
    
    def __init__(self, path: str):
        self.path = path
        self._fh = None

    def acquire(self) -> bool:
        try:
            self._fh = open(self.path, "w")
            fcntl.flock(self._fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._fh.write(str(os.getpid()))
            self._fh.flush()
            return True
        except (IOError, OSError):
            return False

    def release(self):
        if self._fh:
            try:
                fcntl.flock(self._fh, fcntl.LOCK_UN)
                self._fh.close()
                os.unlink(self.path)
            except OSError:
                pass


# ═══════════════════════════════════════════════════════════
#  BACKUP SINGOLA SORGENTE
# ═══════════════════════════════════════════════════════════

def backup_single_source(src: dict, restic: ResticWrapper, cfg: dict) -> BackupStats:
    """Esegue il backup completo di una singola sorgente."""
    logger = logging.getLogger("backup_system")
    name = src["name"]
    stats = BackupStats(source_name=name)
    stats.start_time = datetime.now()
    
    dry_run = cfg["general"].get("dry_run", False)
    cfg_resilience = cfg.get("resilience", {})
    cfg_security = cfg.get("security", {})
    state_dir = cfg["general"].get("state_dir", "/var/lib/backup_system")

    logger.info(f"{'═' * 50}")
    logger.info(f"Source: {name}")
    logger.info(f"{'═' * 50}")

    # 1. Pre-check
    ok, msg = pre_check_source(src, cfg_resilience)
    if not ok:
        stats.skipped = True
        stats.skip_reason = msg
        stats.end_time = datetime.now()
        logger.error(f"  Pre-check failed: {msg}")
        return stats

    # 2. Mount sorgente CIFS
    if src.get("type") == "cifs":
        if not mount_cifs_source(src, cfg_resilience, dry_run):
            stats.skipped = True
            stats.skip_reason = "Mount failed"
            stats.end_time = datetime.now()
            logger.error(f"  Mount failed")
            return stats

    try:
        # 3. Anomaly detection
        source_path = src["mount_point"]
        cfg_anomaly = cfg_security.get("anomaly_detection", {})
        
        safe, anomaly_msg, _ = check_for_anomalies(
            source_path, name, cfg_anomaly, state_dir, dry_run
        )
        
        if not safe:
            stats.anomaly_blocked = True
            stats.error_message = anomaly_msg
            stats.end_time = datetime.now()
            logger.critical(f"  BACKUP BLOCKED: {anomaly_msg}")
            return stats

        # 4. Determina cosa backuppare
        include_paths = src.get("include_paths", [])
        excludes = src.get("exclude_patterns", [])
        tags = src.get("tags", []) + [name]
        hostname = cfg["general"].get("hostname", "backup-server")

        # 5. Esegui backup
        if include_paths:
            # Backup di percorsi specifici
            for subpath in include_paths:
                full_path = os.path.join(source_path, subpath)
                if os.path.exists(full_path):
                    sub_stats = restic.backup(
                        full_path,
                        tags=tags + [subpath],
                        excludes=excludes,
                        hostname=hostname
                    )
                    # Accumula statistiche
                    stats.files_new += sub_stats.files_new
                    stats.files_changed += sub_stats.files_changed
                    stats.files_unmodified += sub_stats.files_unmodified
                    stats.data_added += sub_stats.data_added
                    stats.total_files_processed += sub_stats.total_files_processed
                    if sub_stats.snapshot_id:
                        stats.snapshot_id = sub_stats.snapshot_id
                    if not sub_stats.success:
                        stats.success = False
                        stats.error_message = sub_stats.error_message
                else:
                    logger.warning(f"  Path not found: {full_path}")
            
            if not stats.error_message:
                stats.success = True
        else:
            # Backup dell'intero mount point
            backup_result = restic.backup(
                source_path,
                tags=tags,
                excludes=excludes,
                hostname=hostname
            )
            stats = backup_result
            stats.source_name = name

    except Exception as e:
        stats.success = False
        stats.error_message = str(e)
        logger.error(f"  Exception: {e}", exc_info=True)

    finally:
        # 6. Smonta sorgente
        if src.get("type") == "cifs":
            safe_umount(src["mount_point"], dry_run)

    stats.end_time = datetime.now()
    return stats


# ═══════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════

def main(config_path: str = "/etc/backup_system/config.yaml"):
    """Entry point principale."""
    cfg = load_config(config_path)
    logger = setup_logging(cfg)
    dry_run = cfg["general"].get("dry_run", False)
    state_dir = cfg["general"].get("state_dir", "/var/lib/backup_system")

    logger.info("=" * 60)
    logger.info("BACKUP SYSTEM v3.0 — Restic + Backrest")
    logger.info(f"Started: {datetime.now():%Y-%m-%d %H:%M:%S}")
    logger.info(f"Repository: {cfg['restic']['repository']}")
    if dry_run:
        logger.info("*** DRY-RUN MODE ***")
    logger.info("=" * 60)

    # Lock
    lock = LockFile(cfg["general"].get("lock_file", "/var/run/backup_system.lock"))
    if not lock.acquire():
        logger.error("Another instance is running. Exiting.")
        sys.exit(1)

    results: list[BackupStats] = []
    
    try:
        # Crea directory necessarie
        ensure_directories(cfg)

        # Inizializza wrapper Restic
        restic = ResticWrapper(cfg)

        # ── FASE 1: Init repository se necessario ──
        logger.info("Phase 1 — Repository check")
        if not restic.init_repo():
            raise RuntimeError("Failed to initialize restic repository")

        # ── FASE 2: Unlock repository (rimuovi lock stale) ──
        restic.unlock_repo()

        # ── FASE 3: Backup sorgenti ──
        sources = [s for s in cfg["sources"] if s.get("enabled", True)]
        sources.sort(key=lambda s: s.get("priority", 5))
        
        logger.info(f"Phase 2 — Backup {len(sources)} sources")
        
        parallel = cfg["general"].get("parallel_workers", 1)
        
        if parallel <= 1:
            # Sequenziale
            for src in sources:
                result = backup_single_source(src, restic, cfg)
                results.append(result)
        else:
            # Parallelo
            with ThreadPoolExecutor(max_workers=parallel) as executor:
                futures = {
                    executor.submit(backup_single_source, src, restic, cfg): src
                    for src in sources
                }
                for future in as_completed(futures):
                    src = futures[future]
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as exc:
                        logger.error(f"Exception for {src['name']}: {exc}")
                        stats = BackupStats(source_name=src["name"], error_message=str(exc))
                        stats.end_time = datetime.now()
                        results.append(stats)

        # ── FASE 4: Retention policy ──
        logger.info("Phase 3 — Applying retention policy")
        restic.apply_retention(prune=True)

        # ── FASE 5: Integrity check (periodico) ──
        cfg_integrity = cfg.get("security", {}).get("integrity_check", {})
        if cfg_integrity.get("enabled", True):
            interval = cfg_integrity.get("full_check_interval_days", 7)
            if not should_skip_integrity_check(state_dir, interval):
                logger.info("Phase 4 — Repository integrity check")
                read_pct = cfg_integrity.get("read_data_percent", 5)
                ok, msg = restic.check_repo(read_data_percent=read_pct)
                if ok:
                    mark_integrity_check_done(state_dir)
            else:
                logger.info("Phase 4 — Integrity check skipped (done recently)")

    except Exception as exc:
        logger.critical(f"CRITICAL ERROR: {exc}", exc_info=True)
        if not results:
            results.append(BackupStats(
                source_name="SYSTEM",
                error_message=str(exc)
            ))

    finally:
        # Smonta tutte le sorgenti (safety)
        for src in cfg.get("sources", []):
            mp = src.get("mount_point", "")
            if mp and is_mounted(mp):
                safe_umount(mp, dry_run)
        
        lock.release()

    # ── FASE 6: Report e notifiche ──
    logger.info("Phase 5 — Report and notifications")

    all_ok = all(
        r.success for r in results
        if not r.skipped and not r.anomaly_blocked
    )
    blocked = [r for r in results if r.anomaly_blocked]

    save_report(results, cfg)

    # Riepilogo
    logger.info("=" * 60)
    logger.info("SUMMARY")
    logger.info("=" * 60)

    for r in results:
        if r.anomaly_blocked:
            icon = "🚫"
        elif r.skipped:
            icon = "⏭️ "
        elif r.success:
            icon = "✅"
        else:
            icon = "❌"

        elapsed = f" ({format_duration(r.elapsed_seconds)})" if r.elapsed_seconds else ""
        line = f"  {icon} {r.source_name}{elapsed}"
        
        if r.success and r.snapshot_id:
            line += f" [snap:{r.snapshot_id[:8]}]"
        if r.data_added:
            line += f" +{format_bytes(r.data_added)}"
        if r.error_message:
            line += f" — {r.error_message[:60]}"
        if r.skip_reason:
            line += f" — {r.skip_reason}"
        
        logger.info(line)

    if blocked:
        logger.critical(
            f"⚠️  {len(blocked)} sources BLOCKED due to anomalies! "
            "Manual verification required."
        )

    total_data = sum(r.data_added for r in results)
    total_time = sum(r.elapsed_seconds for r in results)
    logger.info("")
    logger.info(f"Total data added: {format_bytes(total_data)}")
    logger.info(f"Total duration: {format_duration(total_time)}")
    logger.info(f"End: {datetime.now():%Y-%m-%d %H:%M:%S}")
    logger.info("=" * 60)

    send_all_notifications(cfg, results)

    sys.exit(0 if (all_ok and not blocked) else 1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Backup System v3.0 — Restic + Backrest"
    )
    parser.add_argument(
        "-c", "--config",
        default="/etc/backup_system/config.yaml",
        help="Configuration file path",
    )
    args = parser.parse_args()
    main(args.config)
