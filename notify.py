"""
notify.py — Notifiche email, webhook e report.

SECURITY:
- Logging sanitizzato
- Email subject/body sanitizzati
- Webhook payload costruito come dict (no template injection)
- Nomi file report validati
"""

import os
import json
import smtplib
import re
import urllib.request
import urllib.error
import logging
import subprocess
from pathlib import Path
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr

from core import format_bytes, format_duration, sanitize_log_message, validate_path

logger = logging.getLogger("backup_system")


# ═══════════════════════════════════════════════════════════
#  SECURITY: SANITIZATION
# ═══════════════════════════════════════════════════════════

def sanitize_email_header(text: str, max_length: int = 200) -> str:
    """
    Sanitizza testo per header email.
    Rimuove caratteri che potrebbero causare header injection.
    """
    if not text:
        return ""
    # Rimuovi newline e carriage return (header injection)
    sanitized = str(text).replace('\n', ' ').replace('\r', ' ')
    # Rimuovi caratteri di controllo
    sanitized = re.sub(r'[\x00-\x1f\x7f]', '', sanitized)
    return sanitized[:max_length]


def sanitize_email_body(text: str) -> str:
    """
    Sanitizza testo per body email.
    Mantiene newline ma rimuove altri caratteri di controllo.
    """
    if not text:
        return ""
    # Rimuovi caratteri di controllo eccetto newline e tab
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', str(text))
    return sanitized


def validate_email(email: str) -> str:
    """
    Valida un indirizzo email.
    Pattern semplificato ma sicuro.
    """
    if not email:
        raise ValueError("Email vuota")
    
    email = str(email).strip()
    
    # Pattern email base
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        raise ValueError(f"Email non valida")
    
    if len(email) > 254:
        raise ValueError("Email troppo lunga")
    
    return email


def validate_state_dir(state_dir: str) -> str:
    """Valida la directory di stato."""
    return validate_path(state_dir)


def save_report(results: list, cfg: dict, extra_info: dict = None) -> str:
    """Salva un report JSON."""
    state_dir = cfg.get("general", {}).get("state_dir", "/var/lib/backup_system")
    
    try:
        validated_state_dir = validate_state_dir(state_dir)
    except ValueError as e:
        logger.error(f"State dir validation failed: {sanitize_log_message(str(e))}")
        return ""
    
    Path(validated_state_dir).mkdir(parents=True, exist_ok=True)

    now = datetime.now()
    
    # Calcola statistiche in modo sicuro
    total_ok = sum(1 for r in results if getattr(r, 'success', False))
    total_fail = sum(1 for r in results if not getattr(r, 'success', False) and not getattr(r, 'skipped', False))
    total_skip = sum(1 for r in results if getattr(r, 'skipped', False))
    total_blocked = sum(1 for r in results if getattr(r, 'anomaly_blocked', False))

    # Hostname sanitizzato
    hostname = cfg.get("general", {}).get("hostname", "backup-server")
    safe_hostname = re.sub(r'[^a-zA-Z0-9._-]', '_', str(hostname))[:100]

    report = {
        "timestamp": now.isoformat(),
        "hostname": safe_hostname,
        "total_sources": len(results),
        "success": total_ok,
        "failed": total_fail,
        "skipped": total_skip,
        "anomaly_blocked": total_blocked,
        "all_ok": total_fail == 0 and total_blocked == 0,
        "total_data_added": sum(getattr(r, 'data_added', 0) for r in results),
        "total_files_new": sum(getattr(r, 'files_new', 0) for r in results),
        "total_files_changed": sum(getattr(r, 'files_changed', 0) for r in results),
        "total_elapsed_seconds": sum(getattr(r, 'elapsed_seconds', 0) for r in results),
        "sources": [],
    }
    
    # Sanitizza i dati delle sorgenti
    for r in results:
        if hasattr(r, 'to_dict'):
            report["sources"].append(r.to_dict())
        else:
            report["sources"].append({
                "source_name": sanitize_log_message(getattr(r, 'source_name', 'unknown'))[:200],
                "success": bool(getattr(r, 'success', False)),
            })

    if extra_info and isinstance(extra_info, dict):
        # Sanitizza extra_info
        for k, v in extra_info.items():
            safe_key = re.sub(r'[^a-zA-Z0-9_]', '_', str(k))[:50]
            if isinstance(v, str):
                report[safe_key] = sanitize_log_message(v)[:500]
            elif isinstance(v, (int, float, bool)):
                report[safe_key] = v

    # Nome file sicuro
    safe_timestamp = now.strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(validated_state_dir, f"report_{safe_timestamp}.json")
    
    try:
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    except OSError as e:
        logger.error(f"Could not save report: {sanitize_log_message(str(e))}")
        return ""

    # Aggiorna storico (ultimi 90 giorni)
    history_file = os.path.join(validated_state_dir, "history.json")
    history = []
    
    if os.path.exists(history_file):
        try:
            with open(history_file, encoding="utf-8") as f:
                history = json.load(f)
                if not isinstance(history, list):
                    history = []
        except (json.JSONDecodeError, OSError):
            history = []

    # Summary per storico (senza dettagli sorgenti)
    summary = {k: v for k, v in report.items() if k != "sources"}
    history.append(summary)

    # Mantieni ultimi 90 giorni
    if len(history) > 90:
        history = history[-90:]

    try:
        with open(history_file, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
    except OSError as e:
        logger.warning(f"Could not save history: {sanitize_log_message(str(e))}")

    logger.info(f"Report saved: {sanitize_log_message(report_file)}")
    return report_file


def build_report_text(results: list, cfg: dict) -> str:
    """Costruisce il testo del report."""
    lines = []
    now = datetime.now()
    
    hostname = cfg.get("general", {}).get("hostname", "backup-server")
    safe_hostname = re.sub(r'[^a-zA-Z0-9._-]', '_', str(hostname))[:100]

    total_ok = sum(1 for r in results if getattr(r, 'success', False))
    total_fail = sum(1 for r in results if not getattr(r, 'success', False) and not getattr(r, 'skipped', False))
    total_skip = sum(1 for r in results if getattr(r, 'skipped', False))
    total_blocked = sum(1 for r in results if getattr(r, 'anomaly_blocked', False))
    all_ok = total_fail == 0 and total_blocked == 0

    status_emoji = "[OK]" if all_ok else "[ERRORS]"
    
    lines.append(f"{status_emoji} RESTIC BACKUP REPORT - {safe_hostname}")
    lines.append(f"   {now:%Y-%m-%d %H:%M:%S}")
    lines.append("=" * 55)
    lines.append("")
    lines.append(f"Result: {total_ok} OK / {total_fail} failed / {total_skip} skipped / {total_blocked} blocked")
    lines.append(f"Data added:  {format_bytes(sum(getattr(r, 'data_added', 0) for r in results))}")
    lines.append(f"New files:   {sum(getattr(r, 'files_new', 0) for r in results):,}")
    lines.append(f"Changed:     {sum(getattr(r, 'files_changed', 0) for r in results):,}")
    lines.append(f"Duration:    {format_duration(sum(getattr(r, 'elapsed_seconds', 0) for r in results))}")
    lines.append("")
    lines.append("-" * 55)

    for r in results:
        source_name = sanitize_email_body(getattr(r, 'source_name', 'unknown'))[:100]
        
        if getattr(r, 'anomaly_blocked', False):
            icon = "[BLOCKED]"
            status = "BLOCKED (anomaly detected)"
        elif getattr(r, 'skipped', False):
            icon = "[SKIP]"
            skip_reason = sanitize_email_body(getattr(r, 'skip_reason', 'N/A'))[:100]
            status = f"SKIPPED: {skip_reason}"
        elif getattr(r, 'success', False):
            icon = "[OK]"
            snap_id = getattr(r, 'snapshot_id', '')[:8] or 'N/A'
            data_added = format_bytes(getattr(r, 'data_added', 0))
            elapsed = format_duration(getattr(r, 'elapsed_seconds', 0))
            files_new = getattr(r, 'files_new', 0)
            status = f"OK | snap:{snap_id} | +{files_new} new | {data_added} | {elapsed}"
        else:
            icon = "[FAIL]"
            error_msg = sanitize_email_body(getattr(r, 'error_message', 'Unknown error'))[:80]
            status = f"FAILED: {error_msg}"

        lines.append(f"  {icon} {source_name}")
        lines.append(f"     {status}")
        lines.append("")

    lines.append("-" * 55)
    lines.append("Backup System v3.0 - Restic + Backrest")
    
    return "\n".join(lines)


def send_email(cfg: dict, results: list):
    """Invia notifica email."""
    email_cfg = cfg.get("notifications", {}).get("email", {})
    if not email_cfg.get("enabled", False):
        return

    all_ok = all(getattr(r, 'success', False) for r in results 
                 if not getattr(r, 'skipped', False) and not getattr(r, 'anomaly_blocked', False))
    
    if email_cfg.get("only_on_error", False) and all_ok:
        return

    hostname = cfg.get("general", {}).get("hostname", "backup-server")
    safe_hostname = sanitize_email_header(hostname)
    status = "OK" if all_ok else "ERRORS"
    subject = sanitize_email_header(f"[Backup] {safe_hostname} - {status}")

    body = sanitize_email_body(build_report_text(results, cfg))

    # Valida email
    try:
        smtp_user = validate_email(email_cfg.get("smtp_user", ""))
        recipients = []
        for r in email_cfg.get("recipients", []):
            try:
                recipients.append(validate_email(r))
            except ValueError:
                logger.warning(f"Invalid recipient email, skipping")
        
        if not recipients:
            logger.error("No valid recipients")
            return
            
    except ValueError as e:
        logger.error(f"Email validation failed: {sanitize_log_message(str(e))}")
        return

    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        smtp_server = str(email_cfg.get("smtp_server", ""))
        smtp_port = int(email_cfg.get("smtp_port", 587))
        smtp_port = max(1, min(65535, smtp_port))
        
        with smtplib.SMTP(smtp_server, smtp_port, timeout=30) as srv:
            if email_cfg.get("smtp_tls", True):
                srv.starttls()
            srv.login(smtp_user, email_cfg.get("smtp_password", ""))
            srv.sendmail(smtp_user, recipients, msg.as_string())
        logger.info("Email notification sent")
    except Exception as e:
        logger.error(f"Email send failed: {sanitize_log_message(str(e))}")


def send_webhook(cfg: dict, results: list):
    """
    Invia notifica via webhook generico.
    SECURITY: Payload costruito come dict Python (no template injection).
    """
    wh_cfg = cfg.get("notifications", {}).get("webhook", {})
    if not wh_cfg.get("enabled", False):
        return

    url = wh_cfg.get("url", "")
    if not url:
        logger.warning("Webhook URL not configured")
        return

    all_ok = all(getattr(r, 'success', False) for r in results 
                 if not getattr(r, 'skipped', False) and not getattr(r, 'anomaly_blocked', False))
    
    hostname = cfg.get("general", {}).get("hostname", "backup-server")
    safe_hostname = re.sub(r'[^a-zA-Z0-9._-]', '_', str(hostname))[:100]
    status = "OK" if all_ok else "ERRORS"

    total_ok = sum(1 for r in results if getattr(r, 'success', False))
    total_fail = sum(1 for r in results if not getattr(r, 'success', False) and not getattr(r, 'skipped', False))

    # Payload costruito come dict (sicuro)
    payload = {
        "text": f"*Backup {safe_hostname}*: {status}\n{total_ok} OK, {total_fail} failed",
        "username": "Backup System",
    }

    try:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status < 300:
                logger.info("Webhook sent")
            else:
                logger.warning(f"Webhook response: HTTP {resp.status}")
    except urllib.error.URLError as e:
        logger.error(f"Webhook failed: {sanitize_log_message(str(e))}")
    except Exception as e:
        logger.error(f"Webhook error: {sanitize_log_message(str(e))}")


def send_shoutrrr(cfg: dict, results: list):
    """
    Invia notifica via shoutrrr.
    SECURITY: Messaggio sanitizzato prima dell'invio.
    """
    shoutrrr_cfg = cfg.get("notifications", {}).get("shoutrrr", {})
    if not shoutrrr_cfg.get("enabled", False):
        return

    urls = shoutrrr_cfg.get("urls", [])
    if not urls or not isinstance(urls, list):
        return

    all_ok = all(getattr(r, 'success', False) for r in results 
                 if not getattr(r, 'skipped', False) and not getattr(r, 'anomaly_blocked', False))
    
    hostname = cfg.get("general", {}).get("hostname", "backup-server")
    safe_hostname = re.sub(r'[^a-zA-Z0-9._-]', '_', str(hostname))[:100]
    status = "OK" if all_ok else "ERRORS"
    
    # Messaggio sanitizzato
    message = f"Backup {safe_hostname}: {status}"
    message = re.sub(r'[;&|`$\n\r]', '', message)[:200]

    for url in urls[:10]:  # Max 10 URLs
        if not url or not isinstance(url, str):
            continue
        
        try:
            result = subprocess.run(
                ["shoutrrr", "send", "--url", url, message],
                capture_output=True, timeout=30
            )
            if result.returncode == 0:
                logger.info("Shoutrrr notification sent")
            else:
                logger.warning(f"Shoutrrr returned code {result.returncode}")
        except FileNotFoundError:
            logger.warning("shoutrrr not installed, skipping")
            break
        except subprocess.TimeoutExpired:
            logger.warning("Shoutrrr timeout")
        except Exception as e:
            logger.error(f"Shoutrrr failed: {sanitize_log_message(str(e))}")


def send_all_notifications(cfg: dict, results: list):
    """Invia tutte le notifiche configurate."""
    send_email(cfg, results)
    send_webhook(cfg, results)
    send_shoutrrr(cfg, results)
