"""
security.py — Anomaly detection e verifiche di sicurezza pre-backup.
Rileva pattern sospetti (ransomware) confrontando con snapshot precedenti.

SECURITY:
- Nomi sorgente sanitizzati per uso come nomi file
- Path validati contro traversal
- Symlink non seguiti durante scansione
- Logging sanitizzato
"""

import os
import json
import re
import logging
from datetime import datetime
from pathlib import Path
from collections import Counter

logger = logging.getLogger("backup_system")


# ═══════════════════════════════════════════════════════════
#  SECURITY: SANITIZATION
# ═══════════════════════════════════════════════════════════

def sanitize_log_message(msg) -> str:
    """Sanitizza un messaggio per il log."""
    if msg is None:
        return ""
    sanitized = str(msg).replace('\n', '\\n').replace('\r', '\\r')
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', sanitized)
    return sanitized[:1000]


def sanitize_source_name(name: str) -> str:
    """
    Sanitizza un nome sorgente per uso come nome file.
    Previene path traversal e caratteri pericolosi.
    """
    if not name:
        return "unknown"
    
    # Rimuovi path traversal
    sanitized = name.replace('..', '_').replace('/', '_').replace('\\', '_')
    
    # Solo caratteri sicuri
    sanitized = re.sub(r'[^a-zA-Z0-9_.-]', '_', sanitized)
    
    # Rimuovi underscore multipli
    sanitized = re.sub(r'_+', '_', sanitized)
    
    # Limita lunghezza
    sanitized = sanitized[:100].strip('_')
    
    return sanitized or "unknown"


def validate_path(path: str, base_path: str = None, must_exist: bool = False) -> str:
    """Valida e normalizza un path."""
    if not path:
        raise ValueError("Path vuoto")
    
    normalized = os.path.normpath(os.path.abspath(path))
    
    if '..' in normalized.split(os.sep):
        raise ValueError("Path traversal rilevato")
    
    if base_path:
        base_normalized = os.path.normpath(os.path.abspath(base_path))
        if not normalized.startswith(base_normalized + os.sep) and normalized != base_normalized:
            raise ValueError("Path fuori dalla directory consentita")
    
    if must_exist and not os.path.exists(normalized):
        raise ValueError(f"Path non esiste")
    
    return normalized


def validate_state_dir(state_dir: str) -> str:
    """Valida la directory di stato."""
    return validate_path(state_dir)


def get_baseline_path(state_dir: str, source_name: str) -> str:
    """Ottiene il path sicuro per il file baseline."""
    safe_name = sanitize_source_name(source_name)
    validated_dir = validate_state_dir(state_dir)
    return os.path.join(validated_dir, f"baseline_{safe_name}.json")


def load_source_baseline(state_dir: str, source_name: str) -> dict | None:
    """Carica la baseline precedente di una sorgente."""
    try:
        path = get_baseline_path(state_dir, source_name)
        if not os.path.exists(path):
            return None
        
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return None
            return data
    except (json.JSONDecodeError, OSError, ValueError) as e:
        logger.warning(f"Could not load baseline: {sanitize_log_message(str(e))}")
        return None


def save_source_baseline(state_dir: str, source_name: str, baseline: dict):
    """Salva la baseline corrente di una sorgente."""
    try:
        validated_dir = validate_state_dir(state_dir)
        Path(validated_dir).mkdir(parents=True, exist_ok=True)
        
        path = get_baseline_path(state_dir, source_name)
        
        with open(path, "w", encoding='utf-8') as f:
            json.dump(baseline, f, indent=2)
    except (ValueError, OSError) as e:
        logger.error(f"Could not save baseline: {sanitize_log_message(str(e))}")


def scan_directory(path: str, max_files: int = 100000) -> dict:
    """
    Scansiona una directory e raccoglie statistiche.
    SECURITY: Non segue symlink, valida path.
    
    Returns: {
        "timestamp": ...,
        "total_files": ...,
        "total_size": ...,
        "extensions": {".docx": 100, ...},
        "sample_files": [...],
    }
    """
    baseline = {
        "timestamp": datetime.now().isoformat(),
        "total_files": 0,
        "total_size": 0,
        "extensions": Counter(),
        "sample_files": [],
    }

    try:
        validated_path = validate_path(path, must_exist=True)
    except ValueError as e:
        logger.warning(f"Scan path validation failed: {sanitize_log_message(str(e))}")
        baseline["extensions"] = dict(baseline["extensions"])
        return baseline

    try:
        file_count = 0
        max_files = max(100, min(500000, int(max_files)))
        
        for root, dirs, files in os.walk(validated_path, followlinks=False):  # SECURITY: followlinks=False
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            # Verifica che siamo ancora sotto il path base
            try:
                validate_path(root, base_path=validated_path)
            except ValueError:
                continue
            
            for fname in files:
                if file_count >= max_files:
                    logger.warning(f"Scan limit reached ({max_files} files)")
                    break
                
                # Skip hidden files
                if fname.startswith('.'):
                    continue
                
                fpath = os.path.join(root, fname)
                
                # SECURITY: Non seguire symlink
                if os.path.islink(fpath):
                    continue
                
                try:
                    stat = os.stat(fpath, follow_symlinks=False)
                    
                    # Solo file regolari
                    if not os.path.isfile(fpath):
                        continue
                    
                    baseline["total_files"] += 1
                    baseline["total_size"] += stat.st_size
                    
                    # Estensione (sanitizzata)
                    ext = Path(fname).suffix.lower()[:20]
                    baseline["extensions"][ext] += 1
                    
                    # Campiona alcuni file
                    if len(baseline["sample_files"]) < 100:
                        try:
                            rel_path = os.path.relpath(fpath, validated_path)
                            # Verifica che il path relativo non contenga traversal
                            if '..' not in rel_path.split(os.sep):
                                baseline["sample_files"].append({
                                    "path": rel_path[:500],  # Limita lunghezza
                                    "size": stat.st_size,
                                    "mtime": stat.st_mtime,
                                })
                        except ValueError:
                            pass
                    
                    file_count += 1
                except OSError:
                    continue
            
            if file_count >= max_files:
                break

    except OSError as e:
        logger.warning(f"Error scanning {sanitize_log_message(path)}: {sanitize_log_message(str(e))}")

    # Converti Counter in dict per JSON
    baseline["extensions"] = dict(baseline["extensions"])
    
    return baseline


def check_for_anomalies(source_path: str, source_name: str,
                        cfg_anomaly: dict, state_dir: str,
                        dry_run: bool = False) -> tuple[bool, str, dict]:
    """
    Analizza una sorgente per rilevare anomalie (ransomware, corruzione).
    
    Returns: (safe, message, current_baseline)
        safe=True → procedi con il backup
        safe=False → BLOCCA il backup
    """
    if not cfg_anomaly.get("enabled", True):
        return True, "anomaly detection disabled", {}

    safe_name = sanitize_log_message(source_name)
    logger.info(f"  Scanning for anomalies: {safe_name}")

    if dry_run:
        return True, "dry-run", {}

    # Valida path sorgente
    try:
        validated_source = validate_path(source_path, must_exist=True)
    except ValueError as e:
        return False, f"source path invalid: {sanitize_log_message(str(e))}", {}

    # Scansiona lo stato corrente
    current = scan_directory(validated_source)
    
    # Cerca estensioni sospette
    suspicious_exts = cfg_anomaly.get("suspicious_extensions", [])
    found_suspicious = {}
    for ext in suspicious_exts:
        # Normalizza estensione
        ext_clean = str(ext).lower().strip()[:20]
        count = current["extensions"].get(ext_clean, 0)
        if count > 0:
            found_suspicious[ext_clean] = count

    if found_suspicious:
        msg = f"SUSPICIOUS EXTENSIONS FOUND (possible ransomware): {found_suspicious}"
        logger.critical(f"  {sanitize_log_message(msg)}")
        return False, msg, current

    # Carica baseline precedente
    previous = load_source_baseline(state_dir, source_name)
    
    if previous is None:
        logger.info(f"  No previous baseline, saving first scan")
        save_source_baseline(state_dir, source_name, current)
        return True, "first baseline saved", current

    # Confronta con la baseline
    warnings = []
    
    prev_files = int(previous.get("total_files", 0))
    curr_files = int(current["total_files"])
    prev_size = int(previous.get("total_size", 0))
    curr_size = int(current["total_size"])

    # Variazione numero file
    if prev_files > 0:
        change_pct = abs(curr_files - prev_files) / prev_files * 100
        max_change = float(cfg_anomaly.get("max_change_percent", 50))
        if change_pct > max_change:
            warnings.append(
                f"File count change: {change_pct:.1f}% (threshold: {max_change}%)"
            )

        # File nuovi
        if curr_files > prev_files:
            new_pct = (curr_files - prev_files) / prev_files * 100
            max_new = float(cfg_anomaly.get("max_new_files_percent", 40))
            if new_pct > max_new:
                warnings.append(
                    f"New files: {new_pct:.1f}% (threshold: {max_new}%)"
                )

        # File cancellati
        if curr_files < prev_files:
            del_pct = (prev_files - curr_files) / prev_files * 100
            max_del = float(cfg_anomaly.get("max_deleted_percent", 30))
            if del_pct > max_del:
                warnings.append(
                    f"Deleted files: {del_pct:.1f}% (threshold: {max_del}%)"
                )

    # Variazione dimensione totale (riduzione anomala)
    if prev_size > 0:
        shrink_pct = (prev_size - curr_size) / prev_size * 100
        if shrink_pct > 30:
            warnings.append(
                f"Size reduction: {shrink_pct:.1f}% (suspicious)"
            )

    if warnings:
        msg = f"ANOMALIES DETECTED: " + "; ".join(warnings)
        logger.critical(f"  {sanitize_log_message(msg)}")
        # NON aggiornare la baseline (conserva il riferimento buono)
        return False, msg, current

    # Tutto ok: aggiorna baseline
    save_source_baseline(state_dir, source_name, current)
    
    logger.info(
        f"  Anomaly check OK: {curr_files:,} files, "
        f"{curr_size / (1024**3):.2f} GB "
        f"(delta: {curr_files - prev_files:+,} files, "
        f"{(curr_size - prev_size) / (1024**2):+,.1f} MB)"
    )
    
    return True, "ok", current


def get_integrity_marker_path(state_dir: str) -> str:
    """Ottiene il path per il marker di integrity check."""
    validated_dir = validate_state_dir(state_dir)
    return os.path.join(validated_dir, "last_integrity_check.json")


def should_skip_integrity_check(state_dir: str, interval_days: int = 7) -> bool:
    """Verifica se è necessario fare un integrity check completo."""
    try:
        marker_file = get_integrity_marker_path(state_dir)
    except ValueError:
        return False
    
    if not os.path.exists(marker_file):
        return False
    
    try:
        with open(marker_file, encoding='utf-8') as f:
            data = json.load(f)
        
        if not isinstance(data, dict) or "timestamp" not in data:
            return False
        
        last_check = datetime.fromisoformat(data["timestamp"])
        days_since = (datetime.now() - last_check).days
        return days_since < max(1, min(365, int(interval_days)))
    except (json.JSONDecodeError, OSError, KeyError, ValueError):
        return False


def mark_integrity_check_done(state_dir: str):
    """Registra che è stato fatto un integrity check."""
    try:
        validated_dir = validate_state_dir(state_dir)
        Path(validated_dir).mkdir(parents=True, exist_ok=True)
        
        marker_file = get_integrity_marker_path(state_dir)
        
        with open(marker_file, "w", encoding='utf-8') as f:
            json.dump({"timestamp": datetime.now().isoformat()}, f)
    except (ValueError, OSError) as e:
        logger.warning(f"Could not mark integrity check: {sanitize_log_message(str(e))}")
