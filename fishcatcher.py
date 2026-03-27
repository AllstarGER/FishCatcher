#!/usr/bin/env python3
"""FishCatcher — AI-gestützter Phishing-Filter für IMAP-Postfächer."""

import imaplib
import email
from email.header import decode_header
import re
import os
import sys
import fcntl
import logging
import configparser
import subprocess
from email.utils import parseaddr

# --- Konfiguration ---
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
LOCK_FILE = "/tmp/fishcatcher.lock"
LOG_FILE = "/var/log/fishcatcher.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("fishcatcher")

# --- Dringlichkeits-Keywords ---
URGENCY_KEYWORDS = [
    r"konto.*gesperrt", r"account.*suspend", r"verify your",
    r"sofort.*handeln", r"immediate.*action", r"dringend",
    r"passwort.*ablauf", r"password.*expir", r"unauthorized.*access",
    r"confirm.*identity", r"identität.*bestätigen",
    r"click.*here.*or.*your.*account", r"klicken.*sie.*hier.*sonst",
    r"letzte.*warnung", r"final.*warning", r"sicherheits.*warnung",
    r"ungewöhnliche.*aktivität", r"unusual.*activity",
    r"zahlung.*fehlgeschlagen", r"payment.*failed",
    r"steuererstattung", r"tax.*refund",
    r"gewonnen", r"you.*won", r"prize",
    r"lotterie", r"lottery",
]

# --- Verdächtige Anhang-Typen ---
SUSPICIOUS_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".pif", ".com", ".msi", ".ps1"}

# --- URL-Shortener Domains ---
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "rebrand.ly", "cutt.ly"}


def decode_mime_header(header_value):
    """Dekodiert MIME-kodierte Header-Werte."""
    if not header_value:
        return ""
    parts = decode_header(header_value)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(part)
    return " ".join(decoded)


def get_body(msg):
    """Extrahiert den Body einer E-Mail (plain text bevorzugt, sonst HTML)."""
    body_plain = ""
    body_html = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain" and not body_plain:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    body_plain = payload.decode(charset, errors="replace")
            elif ct == "text/html" and not body_html:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    body_html = payload.decode(charset, errors="replace")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace")
            if msg.get_content_type() == "text/html":
                body_html = text
            else:
                body_plain = text
    return body_plain or body_html


def extract_urls(text):
    """Extrahiert URLs aus Text."""
    return re.findall(r'https?://[^\s<>"\']+', text, re.IGNORECASE)


def check_auth_results(msg):
    """Prüft SPF/DKIM/DMARC aus Authentication-Results Header."""
    score = 0
    auth = msg.get("Authentication-Results", "")
    if not auth:
        return 0
    auth_lower = auth.lower()
    if "spf=fail" in auth_lower or "spf=softfail" in auth_lower:
        score += 10
    if "dkim=fail" in auth_lower or "dkim=none" in auth_lower:
        score += 10
    if "dmarc=fail" in auth_lower or "dmarc=none" in auth_lower:
        score += 5
    return min(score, 25)


def check_from_reply_mismatch(msg):
    """Prüft ob From-Domain und Reply-To-Domain unterschiedlich sind."""
    from_addr = parseaddr(msg.get("From", ""))[1].lower()
    reply_to = parseaddr(msg.get("Reply-To", ""))[1].lower()
    if not reply_to or not from_addr:
        return 0
    from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
    reply_domain = reply_to.split("@")[-1] if "@" in reply_to else ""
    if from_domain and reply_domain and from_domain != reply_domain:
        return 20
    return 0


def check_urls(body):
    """Prüft URLs auf verdächtige Muster."""
    urls = extract_urls(body)
    if not urls:
        return 0
    score = 0
    for url in urls:
        # IP-basierte URLs
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
            score += 10
        # URL-Shortener
        for shortener in URL_SHORTENERS:
            if shortener in url.lower():
                score += 5
                break
        # HTTP statt HTTPS bei Login/Banking-Keywords
        if url.startswith("http://") and re.search(r'login|bank|secure|account|paypal|verify', url, re.I):
            score += 10
    return min(score, 20)


def check_urgency_keywords(body, subject):
    """Prüft auf Dringlichkeits-Keywords."""
    text = (subject + " " + body).lower()
    matches = sum(1 for kw in URGENCY_KEYWORDS if re.search(kw, text))
    if matches >= 3:
        return 15
    elif matches >= 1:
        return 8
    return 0


def check_html_forms(body):
    """Prüft auf HTML-Formulare in der Mail."""
    if re.search(r'<form[\s>]|<input[\s>]', body, re.I):
        return 15
    return 0


def check_attachments(msg):
    """Prüft auf verdächtige Anhänge."""
    if not msg.is_multipart():
        return 0
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            filename = decode_mime_header(filename).lower()
            ext = os.path.splitext(filename)[1]
            if ext in SUSPICIOUS_EXTENSIONS:
                return 10
    return 0


def check_encoding_tricks(msg):
    """Prüft auf Encoding-Tricks im Absender."""
    from_header = msg.get("From", "")
    # Unicode-Homoglyphen im Display-Name
    display_name = parseaddr(from_header)[0]
    if display_name:
        # Kyrillische oder andere non-ASCII Zeichen die lateinisch aussehen
        if re.search(r'[\u0400-\u04FF\u0500-\u052F]', display_name):
            return 10
    return 0


def calculate_score(msg):
    """Berechnet den Phishing-Score einer Mail."""
    body = get_body(msg)
    subject = decode_mime_header(msg.get("Subject", ""))
    details = []

    checks = [
        ("auth_results", check_auth_results(msg)),
        ("from_reply_mismatch", check_from_reply_mismatch(msg)),
        ("suspicious_urls", check_urls(body)),
        ("urgency_keywords", check_urgency_keywords(body, subject)),
        ("html_forms", check_html_forms(body)),
        ("suspicious_attachments", check_attachments(msg)),
        ("encoding_tricks", check_encoding_tricks(msg)),
    ]

    total = 0
    for name, points in checks:
        if points > 0:
            details.append(f"{name}={points}")
            total += points

    return min(total, 100), details


def ask_kimi(msg, config):
    """Fragt Kimi ob eine E-Mail Phishing ist."""
    kimi_bin = config.get("kimi", "binary")
    subject = decode_mime_header(msg.get("Subject", ""))
    from_addr = msg.get("From", "")
    body = get_body(msg)[:2000]  # Max 2000 Zeichen

    prompt = (
        f"Analysiere diese E-Mail auf Phishing-Merkmale.\n"
        f"Von: {from_addr}\n"
        f"Betreff: {subject}\n"
        f"Body (gekürzt):\n{body}\n\n"
        f"Antworte NUR mit dem Wort PHISHING oder SAFE, gefolgt von einer kurzen Begründung (1 Zeile)."
    )

    try:
        result = subprocess.run(
            [kimi_bin, "--quiet", "-p", prompt],
            capture_output=True, text=True, timeout=120
        )
        output = result.stdout.strip()
        log.info(f"Kimi Antwort: {output[:200]}")
        return output.upper().startswith("PHISHING")
    except subprocess.TimeoutExpired:
        log.warning("Kimi Timeout nach 120s")
        return False
    except Exception as e:
        log.error(f"Kimi Fehler: {e}")
        return False


def ensure_fish_folder(imap_conn, folder_name):
    """Erstellt den Fish-Ordner falls nicht vorhanden."""
    status, folders = imap_conn.list()
    if status == "OK":
        for f in folders:
            if isinstance(f, bytes) and folder_name.encode() in f:
                return
    imap_conn.create(folder_name)
    imap_conn.subscribe(folder_name)
    log.info(f"Ordner '{folder_name}' erstellt")


def move_to_fish(imap_conn, uid, folder_fish):
    """Verschiebt eine Mail in den Fish-Ordner."""
    result = imap_conn.uid("COPY", uid, folder_fish)
    if result[0] == "OK":
        imap_conn.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
        imap_conn.expunge()
        return True
    return False


def process_mailbox(config):
    """Hauptlogik: Verbindet sich mit IMAP und prüft ungelesene Mails."""
    server = config.get("imap", "server")
    port = config.getint("imap", "port")
    user = config.get("imap", "user")
    password = config.get("imap", "password")
    folder_inbox = config.get("imap", "folder_inbox")
    folder_fish = config.get("imap", "folder_fish")
    threshold_auto = config.getint("thresholds", "auto_fish")
    threshold_kimi = config.getint("thresholds", "kimi_check")

    conn = imaplib.IMAP4_SSL(server, port)
    conn.login(user, password)
    log.info(f"IMAP Login erfolgreich: {user}@{server}")

    ensure_fish_folder(conn, folder_fish)
    conn.select(folder_inbox)

    status, data = conn.uid("SEARCH", None, "UNSEEN")
    if status != "OK" or not data[0]:
        log.info("Keine ungelesenen Mails")
        conn.logout()
        return

    uids = data[0].split()
    log.info(f"{len(uids)} ungelesene Mail(s) gefunden")

    moved = 0
    for uid in uids:
        status, msg_data = conn.uid("FETCH", uid, "(RFC822)")
        if status != "OK":
            continue

        raw_email = msg_data[0][1]
        msg = email.message_from_bytes(raw_email)
        subject = decode_mime_header(msg.get("Subject", ""))
        from_addr = msg.get("From", "")

        score, details = calculate_score(msg)
        detail_str = ", ".join(details) if details else "none"
        log.info(f"Mail: '{subject}' von {from_addr} — Score: {score} ({detail_str})")

        if score >= threshold_auto:
            log.info(f"  → PHISHING (Score {score} >= {threshold_auto}), verschiebe nach {folder_fish}")
            if move_to_fish(conn, uid, folder_fish):
                moved += 1
        elif score >= threshold_kimi:
            log.info(f"  → Score {score}, frage Kimi...")
            if ask_kimi(msg, config):
                log.info(f"  → Kimi: PHISHING, verschiebe nach {folder_fish}")
                if move_to_fish(conn, uid, folder_fish):
                    moved += 1
            else:
                log.info(f"  → Kimi: SAFE, belasse in INBOX")
        else:
            log.info(f"  → SAFE (Score {score} < {threshold_kimi})")

    log.info(f"Fertig. {moved} Mail(s) nach {folder_fish} verschoben")
    conn.logout()


def main():
    # Lockfile
    lock_fd = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit(0)  # Bereits laufend

    try:
        config = configparser.RawConfigParser()
        config.read(CONFIG_PATH)
        process_mailbox(config)
    except Exception as e:
        log.error(f"Fehler: {e}", exc_info=True)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()
        try:
            os.unlink(LOCK_FILE)
        except OSError:
            pass


if __name__ == "__main__":
    main()
