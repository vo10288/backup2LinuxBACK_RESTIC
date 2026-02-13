#!/usr/bin/env python3
"""
BACKUP SYSTEM v3.0 — Restic + Backrest

SECURITY:
- Path validati contro traversal
- Input sanitizzati
- Logging sicuro
- Nessun uso di shell=True

Requisiti:
  Python 3.10+, restic, cifs-utils, smbclient

Eseguire come root.
"""

import sys
import os
import logging
import fcntl
import re
import argparse
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import (
    ensure_directories, pre_check_source, mount_cifs_source,
    safe_umount, is_mounted, format_bytes, format_duration,
    sanitize_log_message, validate_path
)
from restic_wrapper import ResticWrapper, BackupStats
from security import check_for_anomalies, should_skip_integrity_check, mark_integrity_check_done
from notify import save_report, send_all_notifications


# ═══════════════════════════════════════════════════════════
#  CONFIG + LOGGING
# ═══════════════════════════════════════════════════════════

def load_config(path: str) -> dict:
    """Carica e valida la configurazione."""
    try:
        config_path = validate_path(path, must_exist=True)
    except ValueError as e:
        sys.exit(f"[FATAL] Config path invalid: {e}")
    
    with open(config_path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)

    if not cfg or not isinstance(cfg, dict):
        sys.exit("[FATAL] Config empty or invalid")
    
    if "sources" not in cfg:
        sys.exit("[FATAL] Missing 'sources' section")
    if "restic" not in cfg:
        sys.exit("[FATAL] Missing 'restic' section")
    if not cfg.get("restic", {}).get("repository"):
        sys.exit("[FATAL] Missing restic repository")
    
    return cfg


def setup_logging(cfg: dict) -> logging.Logger:
    """Configura il logging."""
    log_dir_str = cfg.get("general", {}).get("log_dir", "/var/log/backup_system")
    
    try:
        log_dir = Path(validate_path(log_dir_str))
    except ValueError:
        log_dir = Path("/var/log/backup_system")
    
    log_dir.mkdir(parents=True, exist_ok=True)
    
    safe_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"backup_{safe_timestamp}.log"

    logger = logging.getLogger("backup_system")
    
    log_level = cfg.get("general", {}).get("log_level", "INFO")
    valid_levels = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
    if str(log_level).upper() not in valid_levels:
        log_level = "INFO"
    
    logger.setLevel(getattr(logging, str(log_level).upper()))

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
        try:
            self.path = validate_path(path)
        except ValueError:
            self.path = "/var/run/backup_system.lock"
        self._fh = None

    def acquire(self) -> bool:
        try:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
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
#  SECURITY: PATH VALIDATION
# ═══════════════════════════════════════════════════════════

def validate_subpath(subpath: str, base_path: str) -> str:
    """
    Valida un subpath (es. include_path) assicurandosi che sia sotto base_path.
    Previene path traversal.
    """
    if not subpath:
        raise ValueError("Subpath vuoto")
    
    # Rimuovi traversal
    clean_subpath = os.path.normpath(subpath)
    
    # Rifiuta path assoluti
    if os.path.isabs(clean_subpath):
        raise ValueError("Path assoluti non consentiti")
    
    # Rifiuta se contiene ..
    if '..' in clean_subpath.split(os.sep):
        raise ValueError("Path traversal non consentito")
    
    # Costruisci path completo
    full_path = os.path.normpath(os.path.join(base_path, clean_subpath))
    
    # Verifica che sia sotto base_path
    base_resolved = os.path.realpath(base_path)
    full_resolved = os.path.realpath(full_path)
    
    if not full_resolved.startswith(base_resolved + os.sep) and full_resolved != base_resolved:
        raise ValueError("Path fuori dalla directory consentita")
    
    return full_path


# ═══════════════════════════════════════════════════════════
#  BACKUP SINGOLA SORGENTE
# ═══════════════════════════════════════════════════════════

def backup_single_source(src: dict, restic: ResticWrapper, cfg: dict) -> BackupStats:
    """Esegue il backup completo di una singola sorgente."""
    logger = logging.getLogger("backup_system")
    
    name = src.get("name", "unknown")
    safe_name = sanitize_log_message(name)
    
    stats = BackupStats(source_name=name)
    stats.start_time = datetime.now()
    
    dry_run = cfg.get("general", {}).get("dry_run", False)
    cfg_resilience = cfg.get("resilience", {})
    cfg_security = cfg.get("security", {})
    state_dir = cfg.get("general", {}).get("state_dir", "/var/lib/backup_system")

    logger.info("=" * 50)
    logger.info(f"Source: {safe_name}")
    logger.info("=" * 50)

    # 1. Pre-check
    ok, msg = pre_check_source(src, cfg_resilience)
    if not ok:
        stats.skipped = True
        stats.skip_reason = sanitize_log_message(msg)[:200]
        stats.end_time = datetime.now()
        logger.error(f"  Pre-check failed: {sanitize_log_message(msg)}")
        return stats

    # 2. Mount sorgente CIFS
    if src.get("type") == "cifs":
        if not mount_cifs_source(src, cfg_resilience, dry_run):
            stats.skipped = True
            stats.skip_reason = "Mount failed"
            stats.end_time = datetime.now()
            logger.error("  Mount failed")
            return stats

    mount_point = src.get("mount_point", "")
    
    try:
        # Valida mount point
        try:
            source_path = validate_path(mount_point, must_exist=not dry_run)
        except ValueError as e:
            stats.skipped = True
            stats.skip_reason = f"Invalid mount point: {sanitize_log_message(str(e))}"
            stats.end_time = datetime.now()
            logger.error(f"  {stats.skip_reason}")
            return stats

        # 3. Anomaly detection
        cfg_anomaly = cfg_security.get("anomaly_detection", {})
        
        safe, anomaly_msg, _ = check_for_anomalies(
            source_path, name, cfg_anomaly, state_dir, dry_run
        )
        
        if not safe:
            stats.anomaly_blocked = True
            stats.error_message = sanitize_log_message(anomaly_msg)[:500]
            stats.end_time = datetime.now()
            logger.critical(f"  BACKUP BLOCKED: {sanitize_log_message(anomaly_msg)}")
            return stats

        # 4. Determina cosa backuppare
        include_paths = src.get("include_paths", [])
        excludes = src.get("exclude_patterns", [])
        tags = src.get("tags", []) + [name]
        hostname = cfg.get("general", {}).get("hostname", "backup-server")

        # 5. Esegui backup
        if include_paths:
            # Backup di percorsi specifici
            for subpath in include_paths[:50]:  # Max 50 include paths
                try:
                    # SECURITY: Valida subpath contro traversal
                    full_path = validate_subpath(subpath, source_path)
                    
                    if os.path.exists(full_path) or dry_run:
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
                        logger.warning(f"  Path not found: {sanitize_log_message(full_path)}")
                        
                except ValueError as e:
                    logger.warning(f"  Invalid include path '{sanitize_log_message(subpath)}': {sanitize_log_message(str(e))}")
                    continue
            
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
        stats.error_message = sanitize_log_message(str(e))[:500]
        logger.error(f"  Exception: {sanitize_log_message(str(e))}", exc_info=True)

    finally:
        # 6. Smonta sorgente
        if src.get("type") == "cifs" and mount_point:
            safe_umount(mount_point, dry_run)

    stats.end_time = datetime.now()
    return stats


# ═══════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════

def main(config_path: str = "/etc/backup_system/config.yaml"):
    """Entry point principale."""
    cfg = load_config(config_path)
    logger = setup_logging(cfg)
    dry_run = cfg.get("general", {}).get("dry_run", False)
    state_dir = cfg.get("general", {}).get("state_dir", "/var/lib/backup_system")

    # Valida state_dir
    try:
        validated_state_dir = validate_path(state_dir)
        Path(validated_state_dir).mkdir(parents=True, exist_ok=True)
    except ValueError:
        validated_state_dir = "/var/lib/backup_system"
        Path(validated_state_dir).mkdir(parents=True, exist_ok=True)

    repo = cfg.get("restic", {}).get("repository", "")
    safe_repo = sanitize_log_message(repo)[:100]

    logger.info("=" * 60)
    logger.info("BACKUP SYSTEM v3.0 - Restic + Backrest")
    logger.info(f"Started: {datetime.now():%Y-%m-%d %H:%M:%S}")
    logger.info(f"Repository: {safe_repo}")
    if dry_run:
        logger.info("*** DRY-RUN MODE ***")
    logger.info("=" * 60)

    # Lock
    lock_path = cfg.get("general", {}).get("lock_file", "/var/run/backup_system.lock")
    lock = LockFile(lock_path)
    if not lock.acquire():
        logger.error("Another instance is running. Exiting.")
        sys.exit(1)

    results = []
    
    try:
        # Crea directory necessarie
        ensure_directories(cfg)

        # Inizializza wrapper Restic
        restic = ResticWrapper(cfg)

        # FASE 1: Init repository se necessario
        logger.info("Phase 1 - Repository check")
        if not restic.init_repo():
            raise RuntimeError("Failed to initialize restic repository")

        # FASE 2: Unlock repository
        restic.unlock_repo()

        # FASE 3: Backup sorgenti
        sources = [s for s in cfg.get("sources", []) if s.get("enabled", True)]
        sources.sort(key=lambda s: int(s.get("priority", 5)))
        
        logger.info(f"Phase 2 - Backup {len(sources)} sources")
        
        parallel = max(1, min(10, int(cfg.get("general", {}).get("parallel_workers", 1))))
        
        if parallel <= 1:
            for src in sources:
                try:
                    result = backup_single_source(src, restic, cfg)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Exception for source: {sanitize_log_message(str(e))}")
                    stats = BackupStats(
                        source_name=src.get("name", "unknown"),
                        error_message=sanitize_log_message(str(e))[:500]
                    )
                    stats.end_time = datetime.now()
                    results.append(stats)
        else:
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
                        src_name = src.get("name", "unknown")
                        logger.error(f"Exception for {sanitize_log_message(src_name)}: {sanitize_log_message(str(exc))}")
                        stats = BackupStats(
                            source_name=src_name,
                            error_message=sanitize_log_message(str(exc))[:500]
                        )
                        stats.end_time = datetime.now()
                        results.append(stats)

        # FASE 4: Retention policy
        logger.info("Phase 3 - Applying retention policy")
        restic.apply_retention(prune=True)

        # FASE 5: Integrity check (periodico)
        cfg_integrity = cfg.get("security", {}).get("integrity_check", {})
        if cfg_integrity.get("enabled", True):
            interval = max(1, min(365, int(cfg_integrity.get("full_check_interval_days", 7))))
            if not should_skip_integrity_check(validated_state_dir, interval):
                logger.info("Phase 4 - Repository integrity check")
                read_pct = max(0, min(100, int(cfg_integrity.get("read_data_percent", 5))))
                ok, msg = restic.check_repo(read_data_percent=read_pct)
                if ok:
                    mark_integrity_check_done(validated_state_dir)
            else:
                logger.info("Phase 4 - Integrity check skipped (done recently)")

    except Exception as exc:
        logger.critical(f"CRITICAL ERROR: {sanitize_log_message(str(exc))}", exc_info=True)
        if not results:
            results.append(BackupStats(
                source_name="SYSTEM",
                error_message=sanitize_log_message(str(exc))[:500]
            ))

    finally:
        # Smonta tutte le sorgenti
        for src in cfg.get("sources", []):
            mp = src.get("mount_point", "")
            if mp:
                try:
                    if is_mounted(mp):
                        safe_umount(mp, dry_run)
                except Exception:
                    pass
        
        lock.release()

    # FASE 6: Report e notifiche
    logger.info("Phase 5 - Report and notifications")

    all_ok = all(
        getattr(r, 'success', False) for r in results
        if not getattr(r, 'skipped', False) and not getattr(r, 'anomaly_blocked', False)
    )
    blocked = [r for r in results if getattr(r, 'anomaly_blocked', False)]

    save_report(results, cfg)

    # Riepilogo
    logger.info("=" * 60)
    logger.info("SUMMARY")
    logger.info("=" * 60)

    for r in results:
        if getattr(r, 'anomaly_blocked', False):
            icon = "[BLOCKED]"
        elif getattr(r, 'skipped', False):
            icon = "[SKIP]"
        elif getattr(r, 'success', False):
            icon = "[OK]"
        else:
            icon = "[FAIL]"

        elapsed = getattr(r, 'elapsed_seconds', 0)
        elapsed_str = f" ({format_duration(elapsed)})" if elapsed else ""
        source_name = sanitize_log_message(getattr(r, 'source_name', 'unknown'))
        line = f"  {icon} {source_name}{elapsed_str}"
        
        snapshot_id = getattr(r, 'snapshot_id', '')
        if getattr(r, 'success', False) and snapshot_id:
            line += f" [snap:{snapshot_id[:8]}]"
        
        data_added = getattr(r, 'data_added', 0)
        if data_added:
            line += f" +{format_bytes(data_added)}"
        
        error_msg = getattr(r, 'error_message', '')
        if error_msg:
            line += f" - {sanitize_log_message(error_msg)[:60]}"
        
        skip_reason = getattr(r, 'skip_reason', '')
        if skip_reason:
            line += f" - {sanitize_log_message(skip_reason)}"
        
        logger.info(line)

    if blocked:
        logger.critical(
            f"!!! {len(blocked)} sources BLOCKED due to anomalies! "
            "Manual verification required."
        )

    total_data = sum(getattr(r, 'data_added', 0) for r in results)
    total_time = sum(getattr(r, 'elapsed_seconds', 0) for r in results)
    logger.info("")
    logger.info(f"Total data added: {format_bytes(total_data)}")
    logger.info(f"Total duration: {format_duration(total_time)}")
    logger.info(f"End: {datetime.now():%Y-%m-%d %H:%M:%S}")
    logger.info("=" * 60)

    send_all_notifications(cfg, results)

    sys.exit(0 if (all_ok and not blocked) else 1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Backup System v3.0 - Restic + Backrest"
    )
    parser.add_argument(
        "-c", "--config",
        default="/etc/backup_system/config.yaml",
        help="Configuration file path",
    )
    args = parser.parse_args()
    main(args.config)
