"""
restic_wrapper.py — Wrapper Python per restic CLI.
Gestisce backup, restore, snapshots, forget, prune, check.

SECURITY:
- Tag, hostname, exclude patterns validati prima dell'uso
- Nessun uso di shell=True
- Error message sanitizzati per logging
- Timeout su tutte le operazioni
"""

import os
import json
import subprocess
import logging
import re
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

from core import run_cmd, get_restic_env, format_bytes, format_duration, sanitize_log_message, validate_path

logger = logging.getLogger("backup_system")


# ═══════════════════════════════════════════════════════════
#  SECURITY: VALIDATION FUNCTIONS
# ═══════════════════════════════════════════════════════════

def sanitize_tag(tag: str) -> str:
    """
    Sanitizza un tag per restic.
    Tag validi: alfanumerici, trattini, underscore, punti.
    """
    if not tag:
        return ""
    # Solo caratteri sicuri
    sanitized = re.sub(r'[^a-zA-Z0-9_.-]', '_', str(tag))
    # Limita lunghezza
    return sanitized[:100]


def sanitize_hostname(hostname: str) -> str:
    """
    Sanitizza un hostname per restic.
    """
    if not hostname:
        return ""
    # Pattern hostname valido
    sanitized = re.sub(r'[^a-zA-Z0-9._-]', '', str(hostname))
    return sanitized[:253]


def sanitize_exclude_pattern(pattern: str) -> str:
    """
    Sanitizza un pattern di esclusione per restic.
    Permette wildcards ma rimuove caratteri pericolosi.
    """
    if not pattern:
        return ""
    # Rimuovi caratteri shell pericolosi (mantieni * e ? per i pattern)
    sanitized = re.sub(r'[;&|`$\n\r\x00]', '', str(pattern))
    # Limita lunghezza
    return sanitized[:500]


def sanitize_snapshot_id(snapshot_id: str) -> str:
    """
    Valida un ID snapshot restic.
    Gli ID sono hex strings o 'latest'.
    """
    if not snapshot_id:
        raise ValueError("Snapshot ID vuoto")
    
    snapshot_id = str(snapshot_id).strip()
    
    # 'latest' è valido
    if snapshot_id.lower() == "latest":
        return "latest"
    
    # Gli ID restic sono stringhe hex
    if not re.match(r'^[a-fA-F0-9]{8,64}$', snapshot_id):
        raise ValueError(f"Snapshot ID non valido")
    
    return snapshot_id


@dataclass
class BackupStats:
    """Statistiche di un backup."""
    source_name: str
    success: bool = False
    snapshot_id: str = ""
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    files_new: int = 0
    files_changed: int = 0
    files_unmodified: int = 0
    dirs_new: int = 0
    dirs_changed: int = 0
    dirs_unmodified: int = 0
    data_added: int = 0
    total_files_processed: int = 0
    total_bytes_processed: int = 0
    error_message: str = ""
    skipped: bool = False
    skip_reason: str = ""
    anomaly_blocked: bool = False

    @property
    def elapsed_seconds(self) -> float:
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0

    def to_dict(self) -> dict:
        return {
            "source_name": self.source_name[:200],  # Limita lunghezza
            "success": self.success,
            "snapshot_id": self.snapshot_id[:64] if self.snapshot_id else "",
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "files_new": int(self.files_new),
            "files_changed": int(self.files_changed),
            "files_unmodified": int(self.files_unmodified),
            "data_added": int(self.data_added),
            "data_added_human": format_bytes(self.data_added),
            "total_files_processed": int(self.total_files_processed),
            "total_bytes_processed": int(self.total_bytes_processed),
            "error_message": self.error_message[:500],  # Limita lunghezza
            "skipped": bool(self.skipped),
            "skip_reason": self.skip_reason[:200],
            "anomaly_blocked": bool(self.anomaly_blocked),
        }


class ResticWrapper:
    """Wrapper per operazioni restic."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.env = get_restic_env(cfg)
        self.dry_run = cfg.get("general", {}).get("dry_run", False)

    def _run_restic(self, args: list[str], timeout: int = 3600,
                    capture_json: bool = False) -> subprocess.CompletedProcess:
        """
        Esegue un comando restic.
        SECURITY: args è una lista, mai shell=True.
        """
        cmd = ["restic"] + args
        if capture_json and "--json" not in args:
            cmd.append("--json")
        
        # Log sanitizzato
        safe_args = [sanitize_log_message(a)[:50] for a in args[:10]]
        logger.debug(f"Restic: restic {' '.join(safe_args)}...")
        
        full_env = os.environ.copy()
        full_env.update(self.env)
        
        # Limita timeout
        timeout = max(30, min(86400, int(timeout)))  # 30s - 24h
        
        return subprocess.run(
            cmd, capture_output=True, text=True, 
            timeout=timeout, env=full_env
        )

    # ═══════════════════════════════════════════════════════
    #  REPOSITORY
    # ═══════════════════════════════════════════════════════

    def init_repo(self) -> bool:
        """Inizializza il repository se non esiste."""
        # Verifica se esiste già
        result = self._run_restic(["snapshots", "--json"], timeout=30)
        if result.returncode == 0:
            logger.info("Repository already initialized")
            return True

        logger.info("Initializing new restic repository...")
        if self.dry_run:
            logger.info("  [DRY-RUN] Would init repository")
            return True

        result = self._run_restic(["init"], timeout=120)
        if result.returncode == 0:
            logger.info("Repository initialized successfully")
            return True
        
        logger.error(f"Failed to init repository: {sanitize_log_message(result.stderr)}")
        return False

    def check_repo(self, read_data_percent: int = 0) -> tuple[bool, str]:
        """Verifica l'integrità del repository."""
        logger.info("Checking repository integrity...")
        
        args = ["check"]
        
        # Valida percentuale
        read_data_percent = max(0, min(100, int(read_data_percent)))
        if read_data_percent > 0:
            args.append(f"--read-data-subset={read_data_percent}%")
        
        if self.dry_run:
            logger.info("  [DRY-RUN] Would check repository")
            return True, "dry-run"

        result = self._run_restic(args, timeout=7200)
        if result.returncode == 0:
            logger.info("Repository check passed")
            return True, "ok"
        
        error = sanitize_log_message(result.stderr.strip())
        logger.error(f"Repository check FAILED: {error}")
        return False, error[:500]

    def unlock_repo(self) -> bool:
        """Rimuove lock stale dal repository."""
        logger.info("Removing stale locks...")
        result = self._run_restic(["unlock"], timeout=60)
        return result.returncode == 0

    # ═══════════════════════════════════════════════════════
    #  BACKUP
    # ═══════════════════════════════════════════════════════

    def backup(self, source_path: str, tags: list[str] = None,
               excludes: list[str] = None, hostname: str = None) -> BackupStats:
        """
        Esegue backup di un percorso.
        SECURITY: Tutti i parametri vengono validati.
        """
        stats = BackupStats(source_name=source_path)
        stats.start_time = datetime.now()

        # Valida source path
        try:
            validated_source = validate_path(source_path, must_exist=True)
        except ValueError as e:
            stats.error_message = f"Invalid source path: {sanitize_log_message(str(e))}"
            stats.end_time = datetime.now()
            logger.error(f"  Backup ERROR: {stats.error_message}")
            return stats

        args = ["backup", validated_source, "--json"]
        
        # Tags (sanitizzati)
        if tags:
            for tag in tags[:20]:  # Max 20 tags
                safe_tag = sanitize_tag(tag)
                if safe_tag:
                    args += ["--tag", safe_tag]
        
        # Hostname custom (sanitizzato)
        if hostname:
            safe_hostname = sanitize_hostname(hostname)
            if safe_hostname:
                args += ["--host", safe_hostname]
        
        # Esclusioni (sanitizzate)
        if excludes:
            for pattern in excludes[:50]:  # Max 50 esclusioni
                safe_pattern = sanitize_exclude_pattern(pattern)
                if safe_pattern:
                    args += ["--exclude", safe_pattern]
        
        # Compressione (valori fissi permessi)
        compression = self.cfg.get("restic", {}).get("compression", "auto")
        if compression in ("off", "max"):
            args += ["--compression", compression]

        logger.info(f"  Starting restic backup: {sanitize_log_message(validated_source)}")
        
        if self.dry_run:
            logger.info("  [DRY-RUN] Would backup")
            stats.success = True
            stats.end_time = datetime.now()
            return stats

        try:
            result = self._run_restic(args, timeout=14400)
            stats.end_time = datetime.now()

            # Parse JSON output
            if result.returncode == 0:
                stats.success = True
                # Restic output è una serie di JSON lines
                for line in result.stderr.splitlines():
                    try:
                        data = json.loads(line)
                        if data.get("message_type") == "summary":
                            stats.files_new = int(data.get("files_new", 0))
                            stats.files_changed = int(data.get("files_changed", 0))
                            stats.files_unmodified = int(data.get("files_unmodified", 0))
                            stats.dirs_new = int(data.get("dirs_new", 0))
                            stats.dirs_changed = int(data.get("dirs_changed", 0))
                            stats.dirs_unmodified = int(data.get("dirs_unmodified", 0))
                            stats.data_added = int(data.get("data_added", 0))
                            stats.total_files_processed = int(data.get("total_files_processed", 0))
                            stats.total_bytes_processed = int(data.get("total_bytes_processed", 0))
                            
                            # Snapshot ID (validato)
                            snap_id = data.get("snapshot_id", "")
                            if snap_id and re.match(r'^[a-fA-F0-9]+$', snap_id):
                                stats.snapshot_id = snap_id[:64]
                    except (json.JSONDecodeError, ValueError, TypeError):
                        continue

                logger.info(
                    f"  Backup OK — snapshot {stats.snapshot_id[:8] if stats.snapshot_id else 'N/A'} | "
                    f"{stats.files_new} new, {stats.files_changed} changed | "
                    f"+{format_bytes(stats.data_added)} | "
                    f"{format_duration(stats.elapsed_seconds)}"
                )
            else:
                stats.success = False
                stats.error_message = sanitize_log_message(result.stderr.strip())[:500]
                logger.error(f"  Backup FAILED: {stats.error_message[:200]}")

        except subprocess.TimeoutExpired:
            stats.success = False
            stats.error_message = "Timeout"
            stats.end_time = datetime.now()
            logger.error("  Backup TIMEOUT")
        except Exception as e:
            stats.success = False
            stats.error_message = sanitize_log_message(str(e))[:500]
            stats.end_time = datetime.now()
            logger.error(f"  Backup ERROR: {sanitize_log_message(str(e))}")

        return stats

    # ═══════════════════════════════════════════════════════
    #  SNAPSHOTS
    # ═══════════════════════════════════════════════════════

    def list_snapshots(self, tags: list[str] = None, 
                       host: str = None) -> list[dict]:
        """Lista gli snapshot nel repository."""
        args = ["snapshots", "--json"]
        
        if tags:
            for tag in tags[:10]:
                safe_tag = sanitize_tag(tag)
                if safe_tag:
                    args += ["--tag", safe_tag]
        
        if host:
            safe_host = sanitize_hostname(host)
            if safe_host:
                args += ["--host", safe_host]

        result = self._run_restic(args, timeout=120)
        if result.returncode != 0:
            logger.error(f"Failed to list snapshots: {sanitize_log_message(result.stderr)}")
            return []

        try:
            data = json.loads(result.stdout)
            if isinstance(data, list):
                return data
            return []
        except json.JSONDecodeError:
            return []

    def get_latest_snapshot(self, tags: list[str] = None) -> dict | None:
        """Ottiene l'ultimo snapshot."""
        args = ["snapshots", "--json", "--latest", "1"]
        
        if tags:
            for tag in tags[:10]:
                safe_tag = sanitize_tag(tag)
                if safe_tag:
                    args += ["--tag", safe_tag]

        result = self._run_restic(args, timeout=60)
        if result.returncode != 0:
            return None

        try:
            snapshots = json.loads(result.stdout)
            if isinstance(snapshots, list) and snapshots:
                return snapshots[0]
            return None
        except (json.JSONDecodeError, IndexError):
            return None

    # ═══════════════════════════════════════════════════════
    #  RETENTION (FORGET + PRUNE)
    # ═══════════════════════════════════════════════════════

    def apply_retention(self, tags: list[str] = None, 
                        prune: bool = True) -> tuple[bool, str]:
        """Applica la retention policy e opzionalmente prune."""
        retention = self.cfg.get("retention", {})
        
        args = ["forget"]
        
        # Policy (valori numerici validati)
        retention_opts = [
            ("keep_last", "--keep-last"),
            ("keep_hourly", "--keep-hourly"),
            ("keep_daily", "--keep-daily"),
            ("keep_weekly", "--keep-weekly"),
            ("keep_monthly", "--keep-monthly"),
            ("keep_yearly", "--keep-yearly"),
        ]
        
        for key, flag in retention_opts:
            value = retention.get(key)
            if value is not None:
                try:
                    int_value = max(0, min(9999, int(value)))
                    if int_value > 0:
                        args += [flag, str(int_value)]
                except (ValueError, TypeError):
                    pass
        
        # keep_within (formato: 1y2m3d)
        keep_within = retention.get("keep_within", "")
        if keep_within and re.match(r'^[0-9ymdh]+$', str(keep_within)):
            args += ["--keep-within", str(keep_within)[:20]]

        # Tags filter
        if tags:
            for tag in tags[:10]:
                safe_tag = sanitize_tag(tag)
                if safe_tag:
                    args += ["--tag", safe_tag]

        # Prune insieme
        if prune:
            args.append("--prune")

        logger.info(f"Applying retention policy...")
        
        if self.dry_run:
            logger.info("  [DRY-RUN] Would apply retention")
            return True, "dry-run"

        result = self._run_restic(args, timeout=7200)
        if result.returncode == 0:
            logger.info("Retention policy applied successfully")
            return True, "ok"
        
        error = sanitize_log_message(result.stderr.strip())
        logger.error(f"Retention FAILED: {error[:200]}")
        return False, error[:500]

    # ═══════════════════════════════════════════════════════
    #  RESTORE
    # ═══════════════════════════════════════════════════════

    def restore(self, snapshot_id: str, target_path: str,
                include: list[str] = None) -> bool:
        """Ripristina uno snapshot."""
        # Valida snapshot ID
        try:
            safe_snapshot = sanitize_snapshot_id(snapshot_id)
        except ValueError as e:
            logger.error(f"Invalid snapshot ID: {sanitize_log_message(str(e))}")
            return False
        
        # Valida target path
        try:
            validated_target = validate_path(target_path)
        except ValueError as e:
            logger.error(f"Invalid target path: {sanitize_log_message(str(e))}")
            return False
        
        args = ["restore", safe_snapshot, "--target", validated_target]
        
        if include:
            for path in include[:50]:
                # Sanitizza i path di inclusione
                safe_path = re.sub(r'[;&|`$\n\r\x00]', '', str(path))[:500]
                if safe_path:
                    args += ["--include", safe_path]

        logger.info(f"Restoring snapshot {safe_snapshot[:8]} to {sanitize_log_message(validated_target)}")
        
        result = self._run_restic(args, timeout=14400)
        if result.returncode == 0:
            logger.info("Restore completed successfully")
            return True
        
        logger.error(f"Restore FAILED: {sanitize_log_message(result.stderr)}")
        return False

    def ls_snapshot(self, snapshot_id: str, path: str = "/") -> list[dict]:
        """Lista i file in uno snapshot."""
        try:
            safe_snapshot = sanitize_snapshot_id(snapshot_id)
        except ValueError:
            return []
        
        args = ["ls", safe_snapshot, "--json"]
        
        if path and path != "/":
            # Sanitizza path
            safe_path = re.sub(r'[;&|`$\n\r\x00]', '', str(path))[:500]
            if safe_path:
                args.append(safe_path)

        result = self._run_restic(args, timeout=300)
        if result.returncode != 0:
            return []

        files = []
        for line in result.stdout.splitlines():
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    files.append(data)
            except json.JSONDecodeError:
                continue
        return files

    # ═══════════════════════════════════════════════════════
    #  STATS
    # ═══════════════════════════════════════════════════════

    def stats(self) -> dict:
        """Statistiche del repository."""
        result = self._run_restic(["stats", "--json"], timeout=300)
        if result.returncode != 0:
            return {}
        
        try:
            data = json.loads(result.stdout)
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}

    def diff(self, snapshot1: str, snapshot2: str) -> dict:
        """Differenze tra due snapshot."""
        try:
            safe_snap1 = sanitize_snapshot_id(snapshot1)
            safe_snap2 = sanitize_snapshot_id(snapshot2)
        except ValueError:
            return {}
        
        result = self._run_restic(["diff", safe_snap1, safe_snap2, "--json"], timeout=600)
        if result.returncode != 0:
            return {}
        
        # Parse diff output
        changes = {"added": [], "removed": [], "modified": []}
        for line in result.stdout.splitlines():
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    change_type = data.get("type", "other")
                    if change_type in changes:
                        changes[change_type].append(data)
            except json.JSONDecodeError:
                continue
        return changes
