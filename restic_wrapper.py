"""
restic_wrapper.py — Wrapper Python per restic CLI.
Gestisce backup, restore, snapshots, forget, prune, check.
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

from core import run_cmd, get_restic_env, format_bytes, format_duration

logger = logging.getLogger("backup_system")


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
            "source_name": self.source_name,
            "success": self.success,
            "snapshot_id": self.snapshot_id,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "files_new": self.files_new,
            "files_changed": self.files_changed,
            "files_unmodified": self.files_unmodified,
            "data_added": self.data_added,
            "data_added_human": format_bytes(self.data_added),
            "total_files_processed": self.total_files_processed,
            "total_bytes_processed": self.total_bytes_processed,
            "error_message": self.error_message,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "anomaly_blocked": self.anomaly_blocked,
        }


class ResticWrapper:
    """Wrapper per operazioni restic."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.env = get_restic_env(cfg)
        self.dry_run = cfg["general"].get("dry_run", False)

    def _run_restic(self, args: list[str], timeout: int = 3600,
                    capture_json: bool = False) -> subprocess.CompletedProcess:
        """Esegue un comando restic."""
        cmd = ["restic"] + args
        if capture_json and "--json" not in args:
            cmd.append("--json")
        
        logger.debug(f"Restic: {' '.join(cmd)}")
        
        full_env = os.environ.copy()
        full_env.update(self.env)
        
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
        
        logger.error(f"Failed to init repository: {result.stderr}")
        return False

    def check_repo(self, read_data_percent: int = 0) -> tuple[bool, str]:
        """Verifica l'integrità del repository."""
        logger.info("Checking repository integrity...")
        
        args = ["check"]
        if read_data_percent > 0:
            args.append(f"--read-data-subset={read_data_percent}%")
        
        if self.dry_run:
            logger.info("  [DRY-RUN] Would check repository")
            return True, "dry-run"

        result = self._run_restic(args, timeout=7200)
        if result.returncode == 0:
            logger.info("Repository check passed")
            return True, "ok"
        
        error = result.stderr.strip()
        logger.error(f"Repository check FAILED: {error}")
        return False, error

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
        Returns: BackupStats con i risultati.
        """
        stats = BackupStats(source_name=source_path)
        stats.start_time = datetime.now()

        args = ["backup", source_path, "--json"]
        
        # Tags
        if tags:
            for tag in tags:
                args += ["--tag", tag]
        
        # Hostname custom
        if hostname:
            args += ["--host", hostname]
        
        # Esclusioni
        if excludes:
            for pattern in excludes:
                args += ["--exclude", pattern]
        
        # Compressione
        compression = self.cfg["restic"].get("compression", "auto")
        if compression and compression != "auto":
            args += ["--compression", compression]

        logger.info(f"  Starting restic backup: {source_path}")
        
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
                            stats.files_new = data.get("files_new", 0)
                            stats.files_changed = data.get("files_changed", 0)
                            stats.files_unmodified = data.get("files_unmodified", 0)
                            stats.dirs_new = data.get("dirs_new", 0)
                            stats.dirs_changed = data.get("dirs_changed", 0)
                            stats.dirs_unmodified = data.get("dirs_unmodified", 0)
                            stats.data_added = data.get("data_added", 0)
                            stats.total_files_processed = data.get("total_files_processed", 0)
                            stats.total_bytes_processed = data.get("total_bytes_processed", 0)
                            stats.snapshot_id = data.get("snapshot_id", "")
                    except json.JSONDecodeError:
                        continue

                logger.info(
                    f"  Backup OK — snapshot {stats.snapshot_id[:8]} | "
                    f"{stats.files_new} new, {stats.files_changed} changed | "
                    f"+{format_bytes(stats.data_added)} | "
                    f"{format_duration(stats.elapsed_seconds)}"
                )
            else:
                stats.success = False
                stats.error_message = result.stderr.strip()[-500:]
                logger.error(f"  Backup FAILED: {stats.error_message}")

        except subprocess.TimeoutExpired:
            stats.success = False
            stats.error_message = "Timeout"
            stats.end_time = datetime.now()
            logger.error("  Backup TIMEOUT")
        except Exception as e:
            stats.success = False
            stats.error_message = str(e)
            stats.end_time = datetime.now()
            logger.error(f"  Backup ERROR: {e}")

        return stats

    # ═══════════════════════════════════════════════════════
    #  SNAPSHOTS
    # ═══════════════════════════════════════════════════════

    def list_snapshots(self, tags: list[str] = None, 
                       host: str = None) -> list[dict]:
        """Lista gli snapshot nel repository."""
        args = ["snapshots", "--json"]
        if tags:
            for tag in tags:
                args += ["--tag", tag]
        if host:
            args += ["--host", host]

        result = self._run_restic(args, timeout=120)
        if result.returncode != 0:
            logger.error(f"Failed to list snapshots: {result.stderr}")
            return []

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

    def get_latest_snapshot(self, tags: list[str] = None) -> dict | None:
        """Ottiene l'ultimo snapshot."""
        args = ["snapshots", "--json", "--latest", "1"]
        if tags:
            for tag in tags:
                args += ["--tag", tag]

        result = self._run_restic(args, timeout=60)
        if result.returncode != 0:
            return None

        try:
            snapshots = json.loads(result.stdout)
            return snapshots[0] if snapshots else None
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
        
        # Policy
        if retention.get("keep_last"):
            args += ["--keep-last", str(retention["keep_last"])]
        if retention.get("keep_hourly"):
            args += ["--keep-hourly", str(retention["keep_hourly"])]
        if retention.get("keep_daily"):
            args += ["--keep-daily", str(retention["keep_daily"])]
        if retention.get("keep_weekly"):
            args += ["--keep-weekly", str(retention["keep_weekly"])]
        if retention.get("keep_monthly"):
            args += ["--keep-monthly", str(retention["keep_monthly"])]
        if retention.get("keep_yearly"):
            args += ["--keep-yearly", str(retention["keep_yearly"])]
        if retention.get("keep_within"):
            args += ["--keep-within", retention["keep_within"]]

        # Tags filter
        if tags:
            for tag in tags:
                args += ["--tag", tag]

        # Prune insieme
        if prune:
            args.append("--prune")

        logger.info(f"Applying retention policy: {' '.join(args)}")
        
        if self.dry_run:
            logger.info("  [DRY-RUN] Would apply retention")
            return True, "dry-run"

        result = self._run_restic(args, timeout=7200)
        if result.returncode == 0:
            logger.info("Retention policy applied successfully")
            return True, "ok"
        
        error = result.stderr.strip()
        logger.error(f"Retention FAILED: {error}")
        return False, error

    # ═══════════════════════════════════════════════════════
    #  RESTORE
    # ═══════════════════════════════════════════════════════

    def restore(self, snapshot_id: str, target_path: str,
                include: list[str] = None) -> bool:
        """Ripristina uno snapshot."""
        args = ["restore", snapshot_id, "--target", target_path]
        
        if include:
            for path in include:
                args += ["--include", path]

        logger.info(f"Restoring snapshot {snapshot_id} to {target_path}")
        
        result = self._run_restic(args, timeout=14400)
        if result.returncode == 0:
            logger.info("Restore completed successfully")
            return True
        
        logger.error(f"Restore FAILED: {result.stderr}")
        return False

    def ls_snapshot(self, snapshot_id: str, path: str = "/") -> list[dict]:
        """Lista i file in uno snapshot."""
        args = ["ls", snapshot_id, "--json"]
        if path != "/":
            args.append(path)

        result = self._run_restic(args, timeout=300)
        if result.returncode != 0:
            return []

        files = []
        for line in result.stdout.splitlines():
            try:
                files.append(json.loads(line))
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
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {}

    def diff(self, snapshot1: str, snapshot2: str) -> dict:
        """Differenze tra due snapshot."""
        result = self._run_restic(["diff", snapshot1, snapshot2, "--json"], timeout=600)
        if result.returncode != 0:
            return {}
        
        # Parse diff output
        changes = {"added": [], "removed": [], "modified": []}
        for line in result.stdout.splitlines():
            try:
                data = json.loads(line)
                # Restic diff format
                changes.setdefault(data.get("type", "other"), []).append(data)
            except json.JSONDecodeError:
                continue
        return changes
