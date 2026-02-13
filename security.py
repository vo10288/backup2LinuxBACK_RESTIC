"""
security.py — Anomaly detection e verifiche di sicurezza pre-backup.
Rileva pattern sospetti (ransomware) confrontando con snapshot precedenti.
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from collections import Counter

logger = logging.getLogger("backup_system")


def load_source_baseline(state_dir: str, source_name: str) -> dict | None:
    """Carica la baseline precedente di una sorgente."""
    safe_name = source_name.replace("/", "_").replace(" ", "_")
    path = os.path.join(state_dir, f"baseline_{safe_name}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def save_source_baseline(state_dir: str, source_name: str, baseline: dict):
    """Salva la baseline corrente di una sorgente."""
    Path(state_dir).mkdir(parents=True, exist_ok=True)
    safe_name = source_name.replace("/", "_").replace(" ", "_")
    path = os.path.join(state_dir, f"baseline_{safe_name}.json")
    with open(path, "w") as f:
        json.dump(baseline, f, indent=2)


def scan_directory(path: str, max_files: int = 100000) -> dict:
    """
    Scansiona una directory e raccoglie statistiche.
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
        file_count = 0
        for root, dirs, files in os.walk(path):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for fname in files:
                if file_count >= max_files:
                    break
                    
                fpath = os.path.join(root, fname)
                try:
                    stat = os.stat(fpath)
                    baseline["total_files"] += 1
                    baseline["total_size"] += stat.st_size
                    
                    ext = Path(fname).suffix.lower()
                    baseline["extensions"][ext] += 1
                    
                    # Campiona alcuni file
                    if len(baseline["sample_files"]) < 100:
                        baseline["sample_files"].append({
                            "path": os.path.relpath(fpath, path),
                            "size": stat.st_size,
                            "mtime": stat.st_mtime,
                        })
                    
                    file_count += 1
                except OSError:
                    continue
            
            if file_count >= max_files:
                break

    except OSError as e:
        logger.warning(f"Error scanning {path}: {e}")

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

    logger.info(f"  Scanning for anomalies: {source_name}")

    if dry_run:
        return True, "dry-run", {}

    # Scansiona lo stato corrente
    current = scan_directory(source_path)
    
    # Cerca estensioni sospette
    suspicious_exts = cfg_anomaly.get("suspicious_extensions", [])
    found_suspicious = {}
    for ext in suspicious_exts:
        count = current["extensions"].get(ext, 0)
        if count > 0:
            found_suspicious[ext] = count

    if found_suspicious:
        msg = f"SUSPICIOUS EXTENSIONS FOUND (possible ransomware): {found_suspicious}"
        logger.critical(f"  {msg}")
        return False, msg, current

    # Carica baseline precedente
    previous = load_source_baseline(state_dir, source_name)
    
    if previous is None:
        logger.info(f"  No previous baseline, saving first scan")
        save_source_baseline(state_dir, source_name, current)
        return True, "first baseline saved", current

    # Confronta con la baseline
    warnings = []
    
    prev_files = previous.get("total_files", 0)
    curr_files = current["total_files"]
    prev_size = previous.get("total_size", 0)
    curr_size = current["total_size"]

    # Variazione numero file
    if prev_files > 0:
        change_pct = abs(curr_files - prev_files) / prev_files * 100
        max_change = cfg_anomaly.get("max_change_percent", 50)
        if change_pct > max_change:
            warnings.append(
                f"File count change: {change_pct:.1f}% (threshold: {max_change}%)"
            )

        # File nuovi
        if curr_files > prev_files:
            new_pct = (curr_files - prev_files) / prev_files * 100
            max_new = cfg_anomaly.get("max_new_files_percent", 40)
            if new_pct > max_new:
                warnings.append(
                    f"New files: {new_pct:.1f}% (threshold: {max_new}%)"
                )

        # File cancellati
        if curr_files < prev_files:
            del_pct = (prev_files - curr_files) / prev_files * 100
            max_del = cfg_anomaly.get("max_deleted_percent", 30)
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
        logger.critical(f"  {msg}")
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


def should_skip_integrity_check(state_dir: str, 
                                 interval_days: int = 7) -> bool:
    """Verifica se è necessario fare un integrity check completo."""
    marker_file = os.path.join(state_dir, "last_integrity_check.json")
    
    if not os.path.exists(marker_file):
        return False
    
    try:
        with open(marker_file) as f:
            data = json.load(f)
        last_check = datetime.fromisoformat(data["timestamp"])
        days_since = (datetime.now() - last_check).days
        return days_since < interval_days
    except (json.JSONDecodeError, OSError, KeyError):
        return False


def mark_integrity_check_done(state_dir: str):
    """Registra che è stato fatto un integrity check."""
    Path(state_dir).mkdir(parents=True, exist_ok=True)
    marker_file = os.path.join(state_dir, "last_integrity_check.json")
    with open(marker_file, "w") as f:
        json.dump({"timestamp": datetime.now().isoformat()}, f)
