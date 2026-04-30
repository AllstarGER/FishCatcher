#!/usr/bin/env python3
import argparse
import fcntl
import logging
import re
import sys
import unicodedata
from configparser import ConfigParser
from dataclasses import dataclass
from datetime import datetime, timedelta
from email.header import decode_header
from email.parser import BytesParser
from email.policy import default
from email.utils import getaddresses
from pathlib import Path
from zoneinfo import ZoneInfo

import imaplib
import mysql.connector

BACKEND_ENV_PATH = Path("/home/users/wao/www/werksarzt-online.de/portal/Health-Card-Backend/.env")
IMAP_CONFIG_PATH = Path("/opt/fishcatcher/config.ini")
LOG_PATH = Path("/var/log/portal-auto-reply-cleaner.log")
LOCK_PATH = Path("/tmp/portal-auto-reply-cleaner.lock")
LOCAL_TZ = ZoneInfo("Europe/Berlin")


@dataclass(frozen=True)
class InviteEvent:
    invite_id: int
    patient_id: int
    round_id: int
    sent_at: datetime
    subject: str
    firstname: str
    secondname: str
    emails: tuple[str, ...]


@dataclass(frozen=True)
class MailHeader:
    uid: bytes
    internal_date: datetime
    subject: str
    from_header: str
    message_id: str


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def load_imap_config(path: Path) -> dict[str, str]:
    cfg = ConfigParser(interpolation=None)
    read_files = cfg.read(path)
    if not read_files or "imap" not in cfg:
        raise RuntimeError(f"IMAP config not found or missing [imap]: {path}")
    section = cfg["imap"]
    return {
        "server": section["server"],
        "port": section.get("port", "993"),
        "user": section["user"],
        "password": section["password"],
        "folder": section.get("folder_inbox", "INBOX"),
    }


def connect_db(env_path: Path):
    env = load_env(env_path)
    is_prod = env.get("APP_MODE") == "prod"
    if env.get("APP_MODE") not in {"prod", "dev"}:
        raise RuntimeError("APP_MODE in backend .env must be prod or dev")
    suffix = "LIVE" if is_prod else "DEV"
    return mysql.connector.connect(
        host=env[f"DB_HOST_{suffix}"],
        user=env[f"DB_USER_{suffix}"],
        password=env[f"DB_USER_PASS_{suffix}"],
        database=env[f"DB_NAME_{suffix}"],
        connection_timeout=10,
    )


def normalize_text(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value or "")
    ascii_text = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]+", "", ascii_text.lower())


def normalize_subject(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def normalize_email(value: str) -> str:
    return (value or "").strip().lower()


def split_email(value: str) -> tuple[str, str]:
    email = normalize_email(value)
    if "@" not in email:
        return email, ""
    local, domain = email.rsplit("@", 1)
    return local, domain


def parse_mysql_datetime(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")
    if dt.tzinfo is None:
        return dt.replace(tzinfo=LOCAL_TZ)
    return dt.astimezone(LOCAL_TZ)


def decode_mime(value: str) -> str:
    if not value:
        return ""
    decoded: list[str] = []
    for payload, charset in decode_header(value):
        if isinstance(payload, bytes):
            decoded.append(payload.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(payload)
    return "".join(decoded)


def parse_internaldate(meta: str) -> datetime | None:
    match = re.search(r'INTERNALDATE "([^"]+)"', meta)
    if not match:
        return None
    return datetime.strptime(match.group(1), "%d-%b-%Y %H:%M:%S %z").astimezone(LOCAL_TZ)


def imap_date(value: datetime) -> str:
    return value.strftime("%d-%b-%Y")


def fetch_invites(conn, lookback_hours: int) -> list[InviteEvent]:
    cutoff = datetime.now(LOCAL_TZ).replace(tzinfo=None) - timedelta(hours=lookback_hours)
    query = """
        SELECT ai.id AS invite_id,
               ai.patient_id,
               ai.round_id,
               ai.created_at,
               ai.t_subject,
               p.firstname,
               p.secondname,
               p.email,
               p.email2
        FROM tbl_ap_invite ai
        JOIN tbl_patient p ON p.id = ai.patient_id
        WHERE ai.created_at >= %s
          AND COALESCE(p.email, '') != ''
        ORDER BY ai.created_at ASC
    """
    cursor = conn.cursor(dictionary=True)
    cursor.execute(query, (cutoff.strftime("%Y-%m-%d %H:%M:%S"),))
    invites: list[InviteEvent] = []
    for row in cursor.fetchall():
        sent_at = parse_mysql_datetime(row["created_at"])
        if not sent_at:
            continue
        emails = tuple(
            sorted(
                {
                    normalize_email(email)
                    for email in (row.get("email"), row.get("email2"))
                    if normalize_email(email)
                }
            )
        )
        if not emails:
            continue
        invites.append(
            InviteEvent(
                invite_id=int(row["invite_id"]),
                patient_id=int(row["patient_id"]),
                round_id=int(row["round_id"]),
                sent_at=sent_at,
                subject=row.get("t_subject") or "",
                firstname=row.get("firstname") or "",
                secondname=row.get("secondname") or "",
                emails=emails,
            )
        )
    cursor.close()
    return invites


def subject_matches(mail_subject: str, invite_subject: str) -> bool:
    subject = normalize_subject(mail_subject)
    if not subject.startswith("automatische antwort"):
        return False
    expected = normalize_subject(invite_subject)
    if expected and expected not in subject:
        return False
    return True


def sender_matches(from_header: str, invite: InviteEvent) -> bool:
    parsed = getaddresses([from_header])
    invite_emails = set(invite.emails)
    invite_domains = {split_email(email)[1] for email in invite.emails if split_email(email)[1]}
    first = normalize_text(invite.firstname)
    last = normalize_text(invite.secondname)

    for display, address in parsed:
        sender = normalize_email(address)
        if sender in invite_emails:
            return True

        local, domain = split_email(sender)
        if not domain or domain not in invite_domains:
            continue

        local_norm = normalize_text(local)
        display_norm = normalize_text(display)
        combined = f"{display_norm}{local_norm}"
        if first and last and first in combined and last in combined:
            return True

    return False


def find_matching_invite(
    header: MailHeader, invites: list[InviteEvent], window: timedelta
) -> InviteEvent | None:
    for invite in invites:
        if header.internal_date < invite.sent_at:
            continue
        if header.internal_date > invite.sent_at + window:
            continue
        if not subject_matches(header.subject, invite.subject):
            continue
        if not sender_matches(header.from_header, invite):
            continue
        return invite
    return None


def fetch_auto_reply_headers(mail, since: datetime, before: datetime) -> list[MailHeader]:
    status, data = mail.uid(
        "SEARCH",
        None,
        "SINCE",
        imap_date(since),
        "BEFORE",
        imap_date(before),
        "SUBJECT",
        '"Automatische Antwort"',
    )
    if status != "OK":
        raise RuntimeError(f"IMAP SEARCH failed: {status}")

    uids = data[0].split() if data and data[0] else []
    headers: list[MailHeader] = []
    for uid in uids:
        status, fetched = mail.uid(
            "FETCH",
            uid,
            "(FLAGS INTERNALDATE BODY.PEEK[HEADER.FIELDS (DATE FROM SUBJECT FROM MESSAGE-ID)])",
        )
        if status != "OK":
            logging.warning("FETCH failed for UID %s: %s", uid.decode(errors="replace"), status)
            continue

        meta = ""
        raw_header = b""
        for item in fetched:
            if not isinstance(item, tuple):
                continue
            meta = item[0].decode(errors="replace")
            raw_header = item[1]
            break

        internal_date = parse_internaldate(meta)
        if not internal_date:
            logging.warning("Could not parse INTERNALDATE for UID %s", uid.decode(errors="replace"))
            continue

        msg = BytesParser(policy=default).parsebytes(raw_header)
        headers.append(
            MailHeader(
                uid=uid,
                internal_date=internal_date,
                subject=decode_mime(msg.get("Subject", "")),
                from_header=msg.get("From", ""),
                message_id=msg.get("Message-ID", ""),
            )
        )
    return headers


def setup_logging(verbose: bool) -> None:
    handlers: list[logging.Handler] = [logging.FileHandler(LOG_PATH)]
    if verbose:
        handlers.append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=handlers,
    )


def acquire_lock(path: Path):
    lock_file = path.open("w")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        logging.info("Another run is still active; exiting")
        return None
    return lock_file


def expunge_deleted_uids(mail, uids: list[bytes]) -> None:
    if not uids:
        return
    uid_set = b",".join(uids).decode()
    capabilities = {cap.decode(errors="replace").upper() for cap in getattr(mail, "capabilities", ())}
    if "UIDPLUS" in capabilities:
        status, _ = mail.uid("EXPUNGE", uid_set)
        if status != "OK":
            raise RuntimeError(f"UID EXPUNGE failed for {uid_set}: {status}")
        return

    status, _ = mail.expunge()
    if status != "OK":
        raise RuntimeError(f"EXPUNGE failed: {status}")


def run(args) -> int:
    setup_logging(args.verbose or args.dry_run)
    lock_file = acquire_lock(LOCK_PATH)
    if lock_file is None:
        return 0

    conn = connect_db(args.backend_env)
    try:
        invites = fetch_invites(conn, args.lookback_hours)
    finally:
        conn.close()

    if not invites:
        logging.info("No recent invites found")
        lock_file.close()
        return 0

    earliest = min(invite.sent_at for invite in invites) - timedelta(minutes=5)
    latest = max(invite.sent_at for invite in invites) + timedelta(hours=args.window_hours)
    before = latest + timedelta(days=1)
    window = timedelta(hours=args.window_hours)

    imap_cfg = load_imap_config(args.imap_config)
    mail = imaplib.IMAP4_SSL(imap_cfg["server"], int(imap_cfg["port"]))
    try:
        mail.login(imap_cfg["user"], imap_cfg["password"])
        status, _ = mail.select(f'"{imap_cfg["folder"]}"', readonly=args.dry_run)
        if status != "OK":
            raise RuntimeError(f"Could not select IMAP folder {imap_cfg['folder']}: {status}")

        headers = fetch_auto_reply_headers(mail, earliest, before)
        matched = []
        deleted_uids: list[bytes] = []
        for header in headers:
            invite = find_matching_invite(header, invites, window)
            if not invite:
                continue
            matched.append((header, invite))
            uid_text = header.uid.decode(errors="replace")
            sender = getaddresses([header.from_header])[0][1] if getaddresses([header.from_header]) else header.from_header
            if args.dry_run:
                logging.info(
                    "DRY-RUN would delete UID %s invite=%s patient=%s round=%s sent=%s from=%s subject=%s message_id=%s",
                    uid_text,
                    invite.invite_id,
                    invite.patient_id,
                    invite.round_id,
                    invite.sent_at.isoformat(),
                    sender,
                    header.subject,
                    header.message_id,
                )
            else:
                status, _ = mail.uid("STORE", header.uid, "+FLAGS.SILENT", r"(\Deleted)")
                if status != "OK":
                    logging.error("Could not mark UID %s deleted: %s", uid_text, status)
                    continue
                deleted_uids.append(header.uid)
                logging.info(
                    "Deleted auto-reply UID %s invite=%s patient=%s round=%s sent=%s from=%s subject=%s message_id=%s",
                    uid_text,
                    invite.invite_id,
                    invite.patient_id,
                    invite.round_id,
                    invite.sent_at.isoformat(),
                    sender,
                    header.subject,
                    header.message_id,
                )

        if deleted_uids and not args.dry_run:
            expunge_deleted_uids(mail, deleted_uids)

        logging.info(
            "Finished: invites=%s auto_reply_headers=%s matched=%s dry_run=%s",
            len(invites),
            len(headers),
            len(matched),
            args.dry_run,
        )
    finally:
        try:
            mail.close()
        except Exception:
            pass
        mail.logout()
        lock_file.close()

    return 0


def parse_args():
    parser = argparse.ArgumentParser(description="Delete automatic replies to portal invite mails.")
    parser.add_argument("--dry-run", action="store_true", help="Log matches without deleting.")
    parser.add_argument("--verbose", action="store_true", help="Also log to stdout.")
    parser.add_argument("--lookback-hours", type=int, default=96)
    parser.add_argument("--window-hours", type=int, default=24)
    parser.add_argument("--backend-env", type=Path, default=BACKEND_ENV_PATH)
    parser.add_argument("--imap-config", type=Path, default=IMAP_CONFIG_PATH)
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(run(parse_args()))
