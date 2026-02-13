"""
notify.py — Notifiche email, webhook e report.
"""

import os
import json
import smtplib
import urllib.request
import urllib.error
import logging
import subprocess
from pathlib import Path
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from core import format_bytes, format_duration

logger = logging.getLogger("backup_system")


def save_report(results: list, cfg: dict, extra_info: dict = None) -> str:
    """Salva un report JSON."""
    state_dir = cfg["general"].get("state_dir", "/var/lib/backup_system")
    Path(state_dir).mkdir(parents=True, exist_ok=True)

    now = datetime.now()
    
    total_ok = sum(1 for r in results if r.success)
    total_fail = sum(1 for r in results if not r.success and not r.skipped)
    total_skip = sum(1 for r in results if r.skipped)
    total_blocked = sum(1 for r in results if r.anomaly_blocked)

    report = {
        "timestamp": now.isoformat(),
        "hostname": cfg["general"].get("hostname", "backup-server"),
        "total_sources": len(results),
        "success": total_ok,
        "failed": total_fail,
        "skipped": total_skip,
        "anomaly_blocked": total_blocked,
        "all_ok": total_fail == 0 and total_blocked == 0,
        "total_data_added": sum(r.data_added for r in results),
        "total_files_new": sum(r.files_new for r in results),
        "total_files_changed": sum(r.files_changed for r in results),
        "total_elapsed_seconds": sum(r.elapsed_seconds for r in results),
        "sources": [r.to_dict() for r in results],
    }

    if extra_info:
        report.update(extra_info)

    # Salva report singolo
    report_file = os.path.join(state_dir, f"report_{now:%Y%m%d_%H%M%S}.json")
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)

    # Aggiorna storico (ultimi 90 giorni)
    history_file = os.path.join(state_dir, "history.json")
    history = []
    if os.path.exists(history_file):
        try:
            with open(history_file) as f:
                history = json.load(f)
        except (json.JSONDecodeError, OSError):
            history = []

    # Summary per storico
    summary = {k: v for k, v in report.items() if k != "sources"}
    history.append(summary)

    # Mantieni ultimi 90 giorni
    if len(history) > 90:
        history = history[-90:]

    with open(history_file, "w") as f:
        json.dump(history, f, indent=2)

    logger.info(f"Report saved: {report_file}")
    return report_file


def build_report_text(results: list, cfg: dict) -> str:
    """Costruisce il testo del report."""
    lines = []
    now = datetime.now()
    hostname = cfg["general"].get("hostname", "backup-server")

    total_ok = sum(1 for r in results if r.success)
    total_fail = sum(1 for r in results if not r.success and not r.skipped)
    total_skip = sum(1 for r in results if r.skipped)
    total_blocked = sum(1 for r in results if r.anomaly_blocked)
    all_ok = total_fail == 0 and total_blocked == 0

    status_emoji = "✅" if all_ok else "❌"
    
    lines.append(f"{status_emoji} RESTIC BACKUP REPORT — {hostname}")
    lines.append(f"   {now:%Y-%m-%d %H:%M:%S}")
    lines.append("=" * 55)
    lines.append("")
    lines.append(f"Result: {total_ok} OK / {total_fail} failed / {total_skip} skipped / {total_blocked} blocked")
    lines.append(f"Data added:  {format_bytes(sum(r.data_added for r in results))}")
    lines.append(f"New files:   {sum(r.files_new for r in results):,}")
    lines.append(f"Changed:     {sum(r.files_changed for r in results):,}")
    lines.append(f"Duration:    {format_duration(sum(r.elapsed_seconds for r in results))}")
    lines.append("")
    lines.append("-" * 55)

    for r in results:
        if r.anomaly_blocked:
            icon = "🚫"
            status = "BLOCKED (anomaly detected)"
        elif r.skipped:
            icon = "⏭️"
            status = f"SKIPPED: {r.skip_reason}"
        elif r.success:
            icon = "✅"
            status = (f"OK | snap:{r.snapshot_id[:8] if r.snapshot_id else 'N/A'} | "
                     f"+{r.files_new} new | {format_bytes(r.data_added)} | "
                     f"{format_duration(r.elapsed_seconds)}")
        else:
            icon = "❌"
            status = f"FAILED: {r.error_message[:80]}"

        lines.append(f"  {icon} {r.source_name}")
        lines.append(f"     {status}")
        lines.append("")

    lines.append("-" * 55)
    lines.append("Backup System v3.0 — Restic + Backrest")
    
    return "\n".join(lines)


def send_email(cfg: dict, results: list):
    """Invia notifica email."""
    email_cfg = cfg.get("notifications", {}).get("email", {})
    if not email_cfg.get("enabled", False):
        return

    all_ok = all(r.success for r in results if not r.skipped and not r.anomaly_blocked)
    if email_cfg.get("only_on_error", False) and all_ok:
        return

    hostname = cfg["general"].get("hostname", "backup-server")
    status = "OK" if all_ok else "ERRORS"
    subject = f"[Backup] {hostname} — {status}"

    body = build_report_text(results, cfg)

    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = email_cfg["smtp_user"]
    msg["To"] = ", ".join(email_cfg["recipients"])
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        with smtplib.SMTP(email_cfg["smtp_server"], email_cfg["smtp_port"]) as srv:
            if email_cfg.get("smtp_tls", True):
                srv.starttls()
            srv.login(email_cfg["smtp_user"], email_cfg["smtp_password"])
            srv.sendmail(email_cfg["smtp_user"], email_cfg["recipients"], msg.as_string())
        logger.info("Email notification sent")
    except Exception as e:
        logger.error(f"Email send failed: {e}")


def send_webhook(cfg: dict, results: list):
    """Invia notifica via webhook generico."""
    wh_cfg = cfg.get("notifications", {}).get("webhook", {})
    if not wh_cfg.get("enabled", False):
        return

    all_ok = all(r.success for r in results if not r.skipped and not r.anomaly_blocked)
    hostname = cfg["general"].get("hostname", "backup-server")
    status = "✅ OK" if all_ok else "❌ ERRORS"

    total_ok = sum(1 for r in results if r.success)
    total_fail = sum(1 for r in results if not r.success and not r.skipped)

    # Payload JSON generico (compatibile con Slack/Discord)
    payload = {
        "text": f"*Backup {hostname}*: {status}\n{total_ok} OK, {total_fail} failed",
        "username": "Backup System",
    }

    url = wh_cfg["url"]
    try:
        data = json.dumps(payload).encode("utf-8")
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
        logger.error(f"Webhook failed: {e}")


def send_shoutrrr(cfg: dict, results: list):
    """Invia notifica via shoutrrr (supporta molti servizi)."""
    shoutrrr_cfg = cfg.get("notifications", {}).get("shoutrrr", {})
    if not shoutrrr_cfg.get("enabled", False):
        return

    urls = shoutrrr_cfg.get("urls", [])
    if not urls:
        return

    all_ok = all(r.success for r in results if not r.skipped and not r.anomaly_blocked)
    hostname = cfg["general"].get("hostname", "backup-server")
    status = "OK" if all_ok else "ERRORS"
    
    message = f"Backup {hostname}: {status}"

    for url in urls:
        try:
            # shoutrrr send --url "slack://..." "message"
            subprocess.run(
                ["shoutrrr", "send", "--url", url, message],
                capture_output=True, timeout=30
            )
            logger.info(f"Shoutrrr notification sent")
        except FileNotFoundError:
            logger.warning("shoutrrr not installed, skipping")
            break
        except Exception as e:
            logger.error(f"Shoutrrr failed: {e}")


def send_all_notifications(cfg: dict, results: list):
    """Invia tutte le notifiche configurate."""
    send_email(cfg, results)
    send_webhook(cfg, results)
    send_shoutrrr(cfg, results)
