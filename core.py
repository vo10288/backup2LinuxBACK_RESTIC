"""
core.py — Funzioni fondamentali: mount, umount, pre-check, utility.

SECURITY:
- Tutti i path vengono validati contro path traversal
- Input per comandi shell validati con whitelist
- Logging sanitizzato contro log injection
- Nessun uso di shell=True
"""

import os
import re
import subprocess
import time
import logging
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger("backup_system")


# ═══════════════════════════════════════════════════════════
#  SECURITY: SANITIZATION FUNCTIONS
# ═══════════════════════════════════════════════════════════

def sanitize_log_message(msg) -> str:
    """
    Sanitizza un messaggio per il log.
    Previene log injection rimuovendo newline e caratteri di controllo.
    """
    if msg is None:
        return ""
    sanitized = str(msg).replace('\n', '\\n').replace('\r', '\\r')
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', sanitized)
    return sanitized[:1000]  # Limita lunghezza


def validate_path(path: str, base_path: str = None, must_exist: bool = False) -> str:
    """
    Valida e normalizza un path.
    Previene path traversal (../).
    
    Args:
        path: Il path da validare
        base_path: Se specificato, verifica che path sia sotto questa directory
        must_exist: Se True, verifica che il path esista
    
    Returns:
        Il path normalizzato
        
    Raises:
        ValueError se il path non è valido
    """
    if not path:
        raise ValueError("Path vuoto non consentito")
    
    # Normalizza il path
    normalized = os.path.normpath(os.path.abspath(path))
    
    # Verifica traversal
    if '..' in normalized.split(os.sep):
        raise ValueError(f"Path traversal rilevato: {sanitize_log_message(path)}")
    
    # Se c'è una base, verifica che sia sotto di essa
    if base_path:
        base_normalized = os.path.normpath(os.path.abspath(base_path))
        if not normalized.startswith(base_normalized + os.sep) and normalized != base_normalized:
            raise ValueError(f"Path fuori dalla directory consentita")
    
    if must_exist and not os.path.exists(normalized):
        raise ValueError(f"Path non esiste: {sanitize_log_message(normalized)}")
    
    return normalized


def validate_hostname(host: str) -> str:
    """
    Valida un hostname o IP.
    Previene command injection.
    """
    if not host:
        raise ValueError("Hostname vuoto")
    
    # Pattern per hostname/IP valido
    # Hostname: lettere, numeri, punti, trattini
    # IP: numeri e punti
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,253}[a-zA-Z0-9]$|^[a-zA-Z0-9]$', host):
        raise ValueError(f"Hostname non valido: {sanitize_log_message(host)}")
    
    return host


def validate_unc_path(unc: str) -> str:
    """
    Valida un percorso UNC per share Windows.
    Formato: //host/share o \\\\host\\share
    """
    if not unc:
        raise ValueError("UNC path vuoto")
    
    # Normalizza a forward slash
    normalized = unc.replace("\\", "/")
    
    # Pattern UNC valido
    if not re.match(r'^//[a-zA-Z0-9._-]+/[a-zA-Z0-9$._-]+(/[a-zA-Z0-9._-]*)*$', normalized):
        raise ValueError(f"UNC path non valido: {sanitize_log_message(unc)}")
    
    return normalized


def sanitize_mount_options(options: str) -> str:
    """
    Sanitizza le opzioni di mount.
    Rimuove caratteri pericolosi che potrebbero causare injection.
    """
    if not options:
        return ""
    # Rimuovi caratteri shell pericolosi
    sanitized = re.sub(r'[;&|`$\n\r\x00]', '', options)
    return sanitized[:500]


@dataclass
class SourceStatus:
    """Stato di una sorgente."""
    name: str
    reachable: bool = False
    mounted: bool = False
    error: str = ""


def run_cmd(cmd: list[str], timeout: int = 60, check: bool = False,
            capture: bool = True, env: dict = None) -> subprocess.CompletedProcess:
    """
    Wrapper per subprocess.run con logging.
    SECURITY: cmd deve essere una lista (mai shell=True).
    """
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    
    # Log sanitizzato (non mostrare password o dati sensibili)
    safe_cmd = []
    for i, c in enumerate(cmd):
        if 'password' in cmd[i-1].lower() if i > 0 else False:
            safe_cmd.append('***')
        else:
            safe_cmd.append(sanitize_log_message(c))
    
    logger.debug(f"CMD: {' '.join(safe_cmd[:10])}...")  # Limita lunghezza log
    
    return subprocess.run(
        cmd, capture_output=capture, text=True, timeout=timeout, 
        check=check, env=full_env
    )


def is_mounted(mount_point: str) -> bool:
    """Verifica se un path è attualmente un mount point."""
    try:
        validated_mp = validate_path(mount_point)
        result = run_cmd(["mountpoint", "-q", validated_mp], timeout=5)
        return result.returncode == 0
    except ValueError:
        return False


def get_mount_device(mount_point: str) -> str:
    """Ottiene il device montato su un mount point."""
    try:
        validated_mp = validate_path(mount_point)
        result = run_cmd(["findmnt", "-n", "-o", "SOURCE", validated_mp], timeout=5)
        return result.stdout.strip() if result.returncode == 0 else ""
    except (ValueError, Exception):
        return ""


# ═══════════════════════════════════════════════════════════
#  PRE-CHECK SORGENTI
# ═══════════════════════════════════════════════════════════

def ping_host(host: str, timeout: int = 3) -> bool:
    """Verifica raggiungibilità via ping."""
    try:
        validated_host = validate_hostname(host)
        timeout_int = max(1, min(30, int(timeout)))  # Limita timeout
        result = run_cmd(
            ["ping", "-c", "1", "-W", str(timeout_int), validated_host], 
            timeout=timeout_int + 2
        )
        return result.returncode == 0
    except ValueError as e:
        logger.warning(f"Ping host validation failed: {sanitize_log_message(str(e))}")
        return False


def check_smb_share(unc: str, credentials_file: str, timeout: int = 10) -> bool:
    """Verifica che la share SMB sia accessibile."""
    try:
        validated_unc = validate_unc_path(unc)
        validated_creds = validate_path(credentials_file, must_exist=True)
        timeout_int = max(5, min(60, int(timeout)))
        
        cmd = [
            "smbclient", validated_unc, 
            f"--authentication-file={validated_creds}",
            "-c", "exit"
        ]
        result = run_cmd(cmd, timeout=timeout_int + 5)
        return result.returncode == 0
    except ValueError as e:
        logger.warning(f"SMB check validation failed: {sanitize_log_message(str(e))}")
        return False


def pre_check_source(src: dict, cfg_resilience: dict) -> tuple[bool, str]:
    """
    Esegue pre-check su una sorgente.
    Returns: (ok, message)
    """
    if not cfg_resilience.get("pre_check", {}).get("enabled", True):
        return True, "pre-check disabled"

    host = src.get("host", "")
    if not host:
        # Estrai host da UNC in modo sicuro
        unc = src.get("unc", "")
        parts = unc.replace("\\", "/").strip("/").split("/")
        host = parts[0] if parts else ""

    if not host:
        return True, "no host configured"

    # Valida host prima del ping
    try:
        validate_hostname(host)
    except ValueError as e:
        return False, f"invalid hostname: {sanitize_log_message(str(e))}"

    # Ping
    ping_timeout = int(cfg_resilience["pre_check"].get("ping_timeout", 3))
    if not ping_host(host, ping_timeout):
        return False, f"host {sanitize_log_message(host)} unreachable (ping timeout)"

    # SMB check per sorgenti CIFS
    if src.get("type") == "cifs":
        smb_timeout = int(cfg_resilience["pre_check"].get("smb_timeout", 10))
        cred = src.get("credentials_file", "")
        if cred:
            try:
                validate_path(cred, must_exist=True)
                unc = src.get("unc", "")
                validate_unc_path(unc)
                if not check_smb_share(unc, cred, smb_timeout):
                    return False, f"share not accessible"
            except ValueError as e:
                return False, f"validation error: {sanitize_log_message(str(e))}"

    return True, "ok"


# ═══════════════════════════════════════════════════════════
#  MOUNT / UMOUNT
# ═══════════════════════════════════════════════════════════

def safe_mount(device: str, mount_point: str, fstype: str = "",
               options: str = "", dry_run: bool = False,
               retries: int = 1, retry_delay: int = 5) -> bool:
    """Monta con retry e backoff."""
    try:
        validated_mp = validate_path(mount_point)
    except ValueError as e:
        logger.error(f"Mount point validation failed: {sanitize_log_message(str(e))}")
        return False
    
    mp = Path(validated_mp)
    mp.mkdir(parents=True, exist_ok=True)

    if is_mounted(validated_mp):
        logger.info(f"  Already mounted: {sanitize_log_message(validated_mp)}")
        return True

    cmd = ["mount"]
    if fstype:
        # Valida fstype
        safe_fstype = re.sub(r'[^a-zA-Z0-9._-]', '', fstype)[:20]
        cmd += ["-t", safe_fstype]
    if options:
        safe_options = sanitize_mount_options(options)
        cmd += ["-o", safe_options]
    cmd += [device, validated_mp]

    retries = max(1, min(10, int(retries)))
    retry_delay = max(1, min(60, int(retry_delay)))

    for attempt in range(1, retries + 1):
        logger.info(f"  Mount (attempt {attempt}/{retries}): {sanitize_log_message(device)} -> {sanitize_log_message(validated_mp)}")
        if dry_run:
            return True

        result = run_cmd(cmd, timeout=60)
        if result.returncode == 0:
            return True

        err = sanitize_log_message(result.stderr.strip())
        logger.warning(f"  Mount failed: {err}")

        if attempt < retries:
            delay = retry_delay * (2 ** (attempt - 1))
            delay = min(delay, 300)  # Max 5 minuti
            logger.info(f"  Waiting {delay}s before retry...")
            time.sleep(delay)

    logger.error(f"  Mount FAILED after {retries} attempts")
    return False


def safe_umount(mount_point: str, dry_run: bool = False, force: bool = False) -> bool:
    """Smonta un mount point in modo sicuro."""
    try:
        validated_mp = validate_path(mount_point)
    except ValueError as e:
        logger.error(f"Umount validation failed: {sanitize_log_message(str(e))}")
        return False
    
    if not is_mounted(validated_mp):
        return True

    cmd = ["umount"]
    if force:
        cmd.append("-l")  # lazy umount
    cmd.append(validated_mp)

    logger.info(f"  Umount: {sanitize_log_message(validated_mp)}")
    if dry_run:
        return True

    result = run_cmd(cmd, timeout=60)
    if result.returncode != 0:
        if not force:
            logger.warning("  Umount failed, retrying with lazy umount...")
            return safe_umount(validated_mp, dry_run, force=True)
        logger.error(f"  Umount FAILED: {sanitize_log_message(validated_mp)}")
        return False
    return True


def mount_cifs_source(src: dict, cfg_resilience: dict, dry_run: bool = False) -> bool:
    """Monta una sorgente CIFS."""
    if src.get("type") != "cifs":
        return True  # Non CIFS, niente da montare

    try:
        unc = validate_unc_path(src.get("unc", ""))
    except ValueError as e:
        logger.error(f"UNC validation failed: {sanitize_log_message(str(e))}")
        return False

    cred = src.get("credentials_file", "")
    opts_parts = []
    
    if cred:
        try:
            validated_cred = validate_path(cred, must_exist=True)
            opts_parts.append(f"credentials={validated_cred}")
        except ValueError as e:
            logger.error(f"Credentials validation failed: {sanitize_log_message(str(e))}")
            return False
    
    extra = src.get("mount_options", "")
    if extra:
        safe_extra = sanitize_mount_options(extra)
        opts_parts.append(safe_extra)

    retries = int(cfg_resilience.get("mount_retries", 3))
    delay = int(cfg_resilience.get("mount_retry_delay", 5))

    return safe_mount(
        device=unc,
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
        if mp:
            try:
                if is_mounted(mp):
                    safe_umount(mp, dry_run)
            except Exception as e:
                logger.warning(f"Error unmounting {sanitize_log_message(mp)}: {sanitize_log_message(str(e))}")


# ═══════════════════════════════════════════════════════════
#  UTILITY
# ═══════════════════════════════════════════════════════════

def ensure_directories(cfg: dict):
    """Crea le directory necessarie."""
    dirs = [
        cfg.get("general", {}).get("log_dir", "/var/log/backup_system"),
        cfg.get("general", {}).get("state_dir", "/var/lib/backup_system"),
        cfg.get("restic", {}).get("cache_dir", "/var/cache/restic"),
    ]
    
    # Repository locale
    repo = cfg.get("restic", {}).get("repository", "")
    if repo and repo.startswith("/"):
        dirs.append(str(Path(repo).parent))
    
    for d in dirs:
        if d:
            try:
                validated_dir = validate_path(d)
                Path(validated_dir).mkdir(parents=True, exist_ok=True)
            except ValueError as e:
                logger.warning(f"Could not create directory: {sanitize_log_message(str(e))}")


def get_restic_env(cfg: dict) -> dict:
    """Ottiene le variabili d'ambiente per restic."""
    env = {}
    
    # Repository
    repo = cfg.get("restic", {}).get("repository", "")
    if repo:
        env["RESTIC_REPOSITORY"] = repo
    
    # Password file
    pwd_file = cfg.get("restic", {}).get("password_file", "")
    if pwd_file:
        try:
            validated_pwd = validate_path(pwd_file, must_exist=True)
            env["RESTIC_PASSWORD_FILE"] = validated_pwd
        except ValueError as e:
            logger.warning(f"Password file validation failed: {sanitize_log_message(str(e))}")
    
    # Cache
    cache_dir = cfg.get("restic", {}).get("cache_dir", "")
    if cache_dir:
        try:
            validated_cache = validate_path(cache_dir)
            env["RESTIC_CACHE_DIR"] = validated_cache
        except ValueError:
            pass
    
    # Compressione (valori fissi permessi)
    compression = cfg.get("restic", {}).get("compression", "auto")
    valid_compression = ("auto", "off", "max")
    if compression in valid_compression:
        env["RESTIC_COMPRESSION"] = compression

    return env


def format_bytes(n) -> str:
    """Formatta bytes in formato leggibile."""
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "0 B"
    
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def format_duration(seconds) -> str:
    """Formatta durata in formato leggibile."""
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return "0s"
    
    if seconds < 60:
        return f"{seconds:.0f}s"
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m}m {s}s"
    return f"{m}m {s}s"
