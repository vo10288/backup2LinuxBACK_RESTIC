"""
core.py — Funzioni fondamentali: mount, umount, pre-check, utility.
"""

import os
import subprocess
import time
import logging
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger("backup_system")


@dataclass
class SourceStatus:
    """Stato di una sorgente."""
    name: str
    reachable: bool = False
    mounted: bool = False
    error: str = ""


def run_cmd(cmd: list[str], timeout: int = 60, check: bool = False,
            capture: bool = True, env: dict = None) -> subprocess.CompletedProcess:
    """Wrapper per subprocess.run con logging."""
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    logger.debug(f"CMD: {' '.join(cmd)}")
    return subprocess.run(
        cmd, capture_output=capture, text=True, timeout=timeout, 
        check=check, env=full_env
    )


def is_mounted(mount_point: str) -> bool:
    """Verifica se un path è attualmente un mount point."""
    result = run_cmd(["mountpoint", "-q", mount_point], timeout=5)
    return result.returncode == 0


def get_mount_device(mount_point: str) -> str:
    """Ottiene il device montato su un mount point."""
    try:
        result = run_cmd(["findmnt", "-n", "-o", "SOURCE", mount_point], timeout=5)
        return result.stdout.strip() if result.returncode == 0 else ""
    except:
        return ""


# ═══════════════════════════════════════════════════════════
#  PRE-CHECK SORGENTI
# ═══════════════════════════════════════════════════════════

def ping_host(host: str, timeout: int = 3) -> bool:
    """Verifica raggiungibilità via ping."""
    result = run_cmd(["ping", "-c", "1", "-W", str(timeout), host], timeout=timeout + 2)
    return result.returncode == 0


def check_smb_share(unc: str, credentials_file: str, timeout: int = 10) -> bool:
    """Verifica che la share SMB sia accessibile."""
    cmd = [
        "smbclient", unc, 
        f"--authentication-file={credentials_file}",
        "-c", "exit"
    ]
    result = run_cmd(cmd, timeout=timeout + 5)
    return result.returncode == 0


def pre_check_source(src: dict, cfg_resilience: dict) -> tuple[bool, str]:
    """
    Esegue pre-check su una sorgente.
    Returns: (ok, message)
    """
    if not cfg_resilience.get("pre_check", {}).get("enabled", True):
        return True, "pre-check disabled"

    host = src.get("host", "")
    if not host:
        # Estrai host da UNC
        unc = src.get("unc", "")
        parts = unc.replace("\\", "/").strip("/").split("/")
        host = parts[0] if parts else ""

    if not host:
        return True, "no host configured"

    # Ping
    ping_timeout = cfg_resilience["pre_check"].get("ping_timeout", 3)
    if not ping_host(host, ping_timeout):
        return False, f"host {host} unreachable (ping timeout)"

    # SMB check per sorgenti CIFS
    if src.get("type") == "cifs":
        smb_timeout = cfg_resilience["pre_check"].get("smb_timeout", 10)
        cred = src.get("credentials_file", "")
        if cred and os.path.exists(cred):
            if not check_smb_share(src["unc"], cred, smb_timeout):
                return False, f"share {src['unc']} not accessible"

    return True, "ok"


# ═══════════════════════════════════════════════════════════
#  MOUNT / UMOUNT
# ═══════════════════════════════════════════════════════════

def safe_mount(device: str, mount_point: str, fstype: str = "",
               options: str = "", dry_run: bool = False,
               retries: int = 1, retry_delay: int = 5) -> bool:
    """Monta con retry e backoff."""
    mp = Path(mount_point)
    mp.mkdir(parents=True, exist_ok=True)

    if is_mounted(mount_point):
        logger.info(f"  Already mounted: {mount_point}")
        return True

    cmd = ["mount"]
    if fstype:
        cmd += ["-t", fstype]
    if options:
        cmd += ["-o", options]
    cmd += [device, mount_point]

    for attempt in range(1, retries + 1):
        logger.info(f"  Mount (attempt {attempt}/{retries}): {device} → {mount_point}")
        if dry_run:
            return True

        result = run_cmd(cmd, timeout=60)
        if result.returncode == 0:
            return True

        err = result.stderr.strip()
        logger.warning(f"  Mount failed: {err}")

        if attempt < retries:
            delay = retry_delay * (2 ** (attempt - 1))
            logger.info(f"  Waiting {delay}s before retry...")
            time.sleep(delay)

    logger.error(f"  Mount FAILED after {retries} attempts: {device}")
    return False


def safe_umount(mount_point: str, dry_run: bool = False, force: bool = False) -> bool:
    """Smonta un mount point in modo sicuro."""
    if not is_mounted(mount_point):
        return True

    cmd = ["umount"]
    if force:
        cmd.append("-l")  # lazy umount
    cmd.append(mount_point)

    logger.info(f"  Umount: {mount_point}")
    if dry_run:
        return True

    result = run_cmd(cmd, timeout=60)
    if result.returncode != 0:
        if not force:
            logger.warning("  Umount failed, retrying with lazy umount...")
            return safe_umount(mount_point, dry_run, force=True)
        logger.error(f"  Umount FAILED: {mount_point}")
        return False
    return True


def mount_cifs_source(src: dict, cfg_resilience: dict, dry_run: bool = False) -> bool:
    """Monta una sorgente CIFS."""
    if src.get("type") != "cifs":
        return True  # Non CIFS, niente da montare

    cred = src.get("credentials_file", "")
    opts_parts = []
    if cred and os.path.exists(cred):
        opts_parts.append(f"credentials={cred}")
    extra = src.get("mount_options", "")
    if extra:
        opts_parts.append(extra)

    retries = cfg_resilience.get("mount_retries", 3)
    delay = cfg_resilience.get("mount_retry_delay", 5)

    return safe_mount(
        device=src["unc"],
        mount_point=src["mount_point"],
        fstype="cifs",
        options=",".join(opts_parts),
        dry_run=dry_run,
        retries=retries,
        retry_delay=delay,
    )


def unmount_all_sources(sources: list, dry_run: bool = False):
    """Smonta tutte le sorgenti."""
    for src in sources:
        mp = src.get("mount_point", "")
        if mp and is_mounted(mp):
            safe_umount(mp, dry_run)


# ═══════════════════════════════════════════════════════════
#  UTILITY
# ═══════════════════════════════════════════════════════════

def ensure_directories(cfg: dict):
    """Crea le directory necessarie."""
    dirs = [
        cfg["general"].get("log_dir", "/var/log/backup_system"),
        cfg["general"].get("state_dir", "/var/lib/backup_system"),
        cfg["restic"].get("cache_dir", "/var/cache/restic"),
        Path(cfg["restic"]["repository"]).parent if cfg["restic"]["repository"].startswith("/") else None,
    ]
    for d in dirs:
        if d:
            Path(d).mkdir(parents=True, exist_ok=True)


def get_restic_env(cfg: dict) -> dict:
    """Ottiene le variabili d'ambiente per restic."""
    env = {}
    
    # Repository
    env["RESTIC_REPOSITORY"] = cfg["restic"]["repository"]
    
    # Password
    pwd_file = cfg["restic"].get("password_file")
    if pwd_file and os.path.exists(pwd_file):
        env["RESTIC_PASSWORD_FILE"] = pwd_file
    
    # Cache
    cache_dir = cfg["restic"].get("cache_dir")
    if cache_dir:
        env["RESTIC_CACHE_DIR"] = cache_dir
    
    # Compressione
    compression = cfg["restic"].get("compression", "auto")
    if compression:
        env["RESTIC_COMPRESSION"] = compression

    return env


def format_bytes(n: int) -> str:
    """Formatta bytes in formato leggibile."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def format_duration(seconds: float) -> str:
    """Formatta durata in formato leggibile."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m}m {s}s"
    return f"{m}m {s}s"
