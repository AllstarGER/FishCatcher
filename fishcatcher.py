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
import shutil
import html
import time
import unicodedata
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlparse
from email.utils import parseaddr

# --- Konfiguration ---
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
LOCK_FILE = "/tmp/fishcatcher.lock"
LOG_FILE = "/var/log/fishcatcher.log"
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".last_uid")
UIDVALIDITY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".uidvalidity")
DEFAULT_SPAM_FOLDER = "Spam"
DEFAULT_SPAMASSASSIN_THRESHOLD = 8.0
DEFAULT_SPAMASSASSIN_TIMEOUT = 20
DEFAULT_SPAMASSASSIN_MAX_BYTES = 750000

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
    r"sofort.*handeln", r"immediate.*action",
    r"passwort.*ablauf", r"password.*expir", r"unauthorized.*access",
    r"confirm.*identity", r"identität.*bestätigen",
    r"click.*here.*or.*your.*account", r"klicken.*sie.*hier.*sonst",
    r"letzte.*warnung", r"final.*warning", r"sicherheits.*warnung",
    r"ungewöhnliche.*aktivität", r"unusual.*activity",
    r"zahlung.*fehlgeschlagen", r"payment.*failed",
    r"zahlung.*fällig", r"zahlung.*faellig", r"fälliger.*betrag",
    r"faelliger.*betrag", r"rechnung.*fällig", r"rechnung.*faellig",
    r"domain.*verlänger", r"domain.*verlaenger", r"verlänger.*domain",
    r"verlaenger.*domain", r"domain.*gesperrt",
    r"dienste.*gesperrt", r"service.*suspend", r"service.*gesperrt",
    r"zugang.*gesperrt", r"login.*erforderlich",
    r"steuererstattung", r"tax.*refund",
    r"abgleich.*erforderlich", r"aktion.*erforderlich", r"handlung.*erforderlich",
    r"freigabe.*erforderlich", r"verifizierung.*(?:offen|nötig|noetig|erforderlich)",
    r"bestätigung.*(?:offen|nötig|noetig)", r"profil.*eingeschränkt",
    r"steuer.*(?:übermittlung|uebermittlung|erklärung|erklaerung).*(?:notwendig|erforderlich)",
    r"gewonnen", r"you.*won", r"prize",
    r"lotterie", r"lottery",
]

# --- Verdächtige Anhang-Typen ---
SUSPICIOUS_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".pif", ".com", ".msi", ".ps1"}

# --- URL-Shortener Domains ---
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "rebrand.ly", "cutt.ly"}

URL_PATTERN = re.compile(r'https?://[^\s<>"\'\[\]]+', re.I)
DOMAIN_TEXT_PATTERN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.I)
LINK_REWRITE_TARGET_PARAMS = {
    "safelinks.protection.outlook.com": ("url",),
}
FILE_LIKE_LINK_TEXT_TLDS = {
    "7z", "bat", "bin", "bmp", "csv", "doc", "docx", "exe", "gif", "ics",
    "jpeg", "jpg", "js", "json", "pdf", "png", "ppt", "pptx", "rar", "rtf",
    "svg", "txt", "webp", "xls", "xlsx", "xml", "zip",
}

SUSPICIOUS_TLDS = {
    "shop", "xyz", "top", "club", "info", "online", "site", "website",
    "buzz", "click", "link", "win", "bid", "loan", "racing", "review",
    "stream", "gq", "cf", "tk", "ml", "ga", "icu", "rest", "monster",
    "live", "cfd", "sbs", "cyou", "lol", "quest", "bond", "zip", "mov", "pw",
}

# Freemail-Anbieter: Absender dort sind Privatpersonen. Ein Anzeigename wie
# "Service", "Verwaltung" oder "ELSTER Info" von Freemail ist ein Phishing-Signal.
FREEMAIL_DOMAINS = {
    "gmx.de", "gmx.net", "gmx.com", "gmx.at", "gmx.ch", "gmx.us", "gmx.co.uk",
    "web.de", "t-online.de", "gmail.com", "googlemail.com", "hotmail.com", "hotmail.de",
    "outlook.com", "outlook.de", "live.com", "live.de", "yahoo.com", "yahoo.de",
    "icloud.com", "me.com", "aol.com", "aol.de", "mail.de", "posteo.de", "proton.me",
    "protonmail.com", "mail.com", "email.com", "usa.com", "europe.com", "post.com",
    "consultant.com", "engineer.com", "dr.com", "myself.com",
    # Zoho-Sammelabsender ohne eigene Domain ("Abrechnungsservice", "1Blu.de" Fakes)
    "zohosubscriptions.com", "zoho.com", "zoho.eu", "zohomail.com", "zohomail.eu",
}
# Freemail-Domains, die im deutschen Alltag praktisch nie vorkommen, aber in
# jeder beobachteten Phishing-Welle (gmx.us, mail.com-Familie).
EXOTIC_FREEMAIL_DOMAINS = {
    "gmx.us", "gmx.co.uk", "mail.com", "email.com", "usa.com", "europe.com",
    "post.com", "consultant.com", "engineer.com", "dr.com", "myself.com",
}
# Wortende statt Wortgrenze: deutsche Komposita wie "Erstattungshinweis" oder
# "Kundenservice" muessen treffen.
INSTITUTIONAL_DISPLAY_PATTERN = re.compile(
    r"\b\w*(?:service|support|kundenservice|kundendienst|info|team|verwaltung|sachbearbeitung|"
    r"sachbearbeiter|filiale|zentrale|buchhaltung|rechnung|zahlung|hinweis|mitteilung|"
    r"benachrichtigung|sicherheit|security|ticket|beratung|kontakt|bank|sparkasse|elster|"
    r"finanzamt|steuer|zoll|behörde|behoerde|polizei|inkasso|mahnung|kundenkonto|"
    r"no-?reply|noreply|administrator|admin|it-abteilung|helpdesk)\b",
    re.I,
)

LEGIT_BUSINESS_TLDS = {"de", "com", "net", "org", "eu", "at", "ch"}
COMMON_VISIBLE_DOMAIN_TLDS = LEGIT_BUSINESS_TLDS | SUSPICIOUS_TLDS | {
    "ai", "app", "be", "ca", "co", "dev", "dk", "es", "fi", "fr", "io",
    "it", "me", "nl", "no", "pl", "se", "uk", "us",
}
GENERIC_BANK_CLAIM_PATTERN = re.compile(
    r"\b(?:(?P<separated>[a-z0-9][a-z0-9-]{1,40})\s+bank|(?P<compound>[a-z0-9][a-z0-9-]{1,40}bank))\b",
    re.I,
)
NON_FINANCIAL_BANK_CLAIM_TOKENS = {
    "bloodbank",
    "blutbank",
    "datenbank",
    "databank",
    "samenbank",
    "spermabank",
    "biobank",
    "gewebebank",
}
BANK_ABUSE_CONTEXT_PATTERNS = [
    r"\bkonto\b", r"\baccount\b", r"\bzugang\b", r"\blogin\b",
    r"\bonline\s*banking\b", r"\bbanking\b", r"\bsecurego\b",
    r"\bprofil\b", r"\bkarte\b", r"\bdaten(?:abgleich|stand)?\b",
    r"\baktualis", r"\bbestätig", r"\bbestaetig", r"\bprüfung\b",
    r"\bpruefung\b", r"\bstatusmeldung\b", r"\bsicherheit",
    r"\bverifiz", r"\baktion\s+erforderlich\b",
]
GERMAN_ASCII_REPLACEMENTS = {
    "ä": "ae",
    "ö": "oe",
    "ü": "ue",
    "ß": "ss",
}

# --- Bekannte sichere Domains (CDN, SaaS, Business-Tools) ---
SAFE_URL_DOMAINS = {
    "microsoft.com", "teams.microsoft.com", "outlook.com", "office.com", "office365.com",
    "google.com", "googleusercontent.com", "googleapis.com", "gstatic.com",
    "hubspot.com", "hubspot.net", "hsforms.com",
    "linkedin.com", "xing.com",
    "zoom.us", "webex.com", "gotomeeting.com",
    "dropbox.com", "onedrive.live.com", "sharepoint.com",
    "mailchimp.com", "constantcontact.com", "sendinblue.com",
    "youtube.com", "vimeo.com",
    "github.com", "gitlab.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazonaws.com",
    "cloudflare.com",
    "wa-o.de", "werksarzt-online.de", "baz-west.de",
}

# Bank names must be reviewed by Claude even when the heuristic score is low.
BANK_BRAND_PATTERNS = [
    r"\bvolksbank\b",
    r"\bvr\s*(?:banking|bank|eg)\b",
    r"\bsparkasse\b",
    r"\bpostbank\b",
    r"\bdkb\b",
    r"\btf\s*bank\b",
    r"\btfbank\b",
    r"\bapo\s*bank\b",
    r"\bapobank\b",
    r"\bapotheker\s*(?:und|&)?\s*(?:aerzte|ärzte)?\s*bank\b",
    r"\btargobank\b",
    r"\bdeutsche\s+bank\b",
    r"\bcommerzbank\b",
    r"\bing(?:-diba)?\b",
    r"\bcomdirect\b",
    r"\bconsorsbank\b",
    r"\bn26\b",
]

LEGIT_BANK_DOMAINS = {
    "volksbank.de",
    "vr.de",
    "vr-bank.de",
    "sparkasse.de",
    "sparkasse-siegen.de",
    "s-web.de",
    "postbank.de",
    "dkb.de",
    "tfbank.de",
    "apobank.de",
    "targobank.de",
    "deutsche-bank.de",
    "commerzbank.de",
    "ing.de",
    "ing-diba.de",
    "comdirect.de",
    "consorsbank.de",
    "n26.com",
}

# Allgemeine Markenregeln: Wenn eine bekannte Marke in Anzeigename/Betreff
# auftaucht, muss die From-Domain zu einer bekannten legitimen Domain passen.
# Body-only Treffer werden nur mit Phishing-Kontext gewertet, um normale
# Kundenantworten oder Signaturen nicht zu hart zu bestrafen.
BRAND_SPOOFING_RULES = [
    {
        "name": "1blu",
        "patterns": [r"\b1\s*blu\b"],
        "domains": {"1blu.de"},
        "body_context": "hosting",
    },
    {
        "name": "IONOS",
        "patterns": [r"\bionos\b", r"\b1\s*&\s*1\b", r"\b1\s*und\s*1\b", r"\b1und1\b"],
        "domains": {"ionos.de", "ionos.com", "1und1.de", "1und1.com"},
        "body_context": "hosting",
    },
    {
        "name": "STRATO",
        "patterns": [r"\bstrato\b"],
        "domains": {"strato.de", "strato.com"},
        "body_context": "hosting",
    },
    {
        "name": "All-Inkl",
        "patterns": [r"\ball-?inkl\b", r"\ballinkl\b"],
        "domains": {"all-inkl.com", "all-inkl.de"},
        "body_context": "hosting",
    },
    {
        "name": "Host Europe",
        "patterns": [r"\bhost\s*europe\b"],
        "domains": {"hosteurope.de", "hosteurope.com"},
        "body_context": "hosting",
    },
    {
        "name": "DomainFactory",
        "patterns": [r"\bdomain\s*factory\b", r"\bdomainfactory\b"],
        "domains": {"df.eu", "domainfactory.de"},
        "body_context": "hosting",
    },
    {
        "name": "United Domains",
        "patterns": [r"\bunited\s*domains\b", r"\bunited-domains\b"],
        "domains": {"united-domains.de", "united-domains.com"},
        "body_context": "hosting",
    },
    {
        "name": "GMX",
        "patterns": [r"\bgmx\b"],
        "domains": {"gmx.de", "gmx.net", "gmx.com"},
        "body_context": "account",
    },
    {
        "name": "WEB.DE",
        "patterns": [r"\bweb\.de\b"],
        "domain_patterns": [r"^web\.de$"],
        "domains": {"web.de"},
        "body_context": "account",
    },
    {
        "name": "Telekom",
        "patterns": [r"\btelekom\b", r"\bt-?online\b", r"\bt-?systems\b"],
        "domains": {"telekom.de", "t-online.de", "t-systems.de"},
        "body_context": "account",
    },
    {
        "name": "Vodafone",
        "patterns": [r"\bvodafone\b"],
        "domains": {"vodafone.de", "vodafone.com"},
        "body_context": "account",
    },
    {
        "name": "O2",
        "patterns": [r"\bo2\s*(?:online|business|kundenservice|service|rechnung)\b", r"\btelefonica\b", r"\btelefónica\b"],
        "contextual_display_patterns": [r"^\s*o2\s*$"],
        "contextual_subject_patterns": [r"\bo2\b"],
        "domains": {"o2online.de", "telefonica.de", "telefonica.com"},
        "body_context": "account",
    },
    {
        "name": "PayPal",
        "patterns": [r"\bpay\s*pal\b", r"\bpaypal\b"],
        "domains": {"paypal.com", "paypal.de"},
        "body_context": "payment",
    },
    {
        "name": "Amazon",
        "patterns": [r"\bamazon\b"],
        "domains": {"amazon.de", "amazon.com", "amazonaws.com"},
        "body_context": "payment",
    },
    {
        "name": "eBay",
        "patterns": [r"\bebay\b"],
        "domains": {"ebay.de", "ebay.com"},
        "body_context": "payment",
    },
    {
        "name": "DHL",
        "patterns": [r"\bdhl\b", r"\bdeutsche\s*post\b"],
        "domains": {"dhl.de", "dhl.com", "deutschepost.de"},
        "body_context": "delivery",
    },
    {
        "name": "Hermes",
        "patterns": [r"\bhermes\b"],
        "domains": {"hermesworld.com", "myhermes.de"},
        "body_context": "delivery",
    },
    {
        "name": "DPD",
        "patterns": [r"\bdpd\b"],
        "domains": {"dpd.de", "dpd.com", "dpdgroup.com"},
        "body_context": "delivery",
    },
    {
        "name": "UPS",
        "patterns": [r"\bups\b"],
        "domains": {"ups.com"},
        "body_context": "delivery",
    },
    {
        "name": "GLS",
        "patterns": [r"\bgls\b"],
        "domains": {"gls-group.com", "gls-pakete.de"},
        "body_context": "delivery",
    },
    {
        "name": "FedEx",
        "patterns": [r"\bfedex\b", r"\bfed\s*ex\b"],
        "domains": {"fedex.com"},
        "body_context": "delivery",
    },
    {
        "name": "Microsoft",
        "patterns": [r"\bmicrosoft\b", r"\boffice\s*365\b", r"\bmicrosoft\s*365\b"],
        "domain_patterns": [r"\bmicrosoft\b", r"microsoft\s*365", r"office\s*365"],
        "domains": {"microsoft.com", "microsoft.de", "microsoft365.com", "office.com", "office365.com"},
        "consumer_domains": {"outlook.com", "hotmail.com", "live.com"},
        "body_context": "account",
    },
    {
        "name": "Google",
        "patterns": [r"\bgoogle\b"],
        "domain_patterns": [r"\bgoogle\b"],
        "domains": {"google.com", "google.de"},
        "consumer_domains": {"gmail.com"},
        "body_context": "account",
    },
    {
        "name": "Apple",
        "patterns": [r"\bapple\b", r"\bicloud\b"],
        "domains": {"apple.com", "icloud.com"},
        "body_context": "account",
    },
    {
        "name": "Adobe",
        "patterns": [r"\badobe\b"],
        "domains": {"adobe.com"},
        "body_context": "document",
    },
    {
        "name": "DocuSign",
        "patterns": [r"\bdocusign\b", r"\bdocu\s*sign\b"],
        "domains": {"docusign.com", "docusign.net"},
        "body_context": "document",
    },
    {
        "name": "Dropbox",
        "patterns": [r"\bdropbox\b"],
        "domains": {"dropbox.com", "dropboxmail.com"},
        "body_context": "document",
    },
    {
        "name": "LinkedIn",
        "patterns": [r"\blinkedin\b", r"\blinked\s*in\b"],
        "domains": {"linkedin.com", "linkedinmail.com"},
        "body_context": "account",
    },
    {
        "name": "XING",
        "patterns": [r"\bxing\b"],
        "domains": {"xing.com"},
        "body_context": "account",
    },
    {
        "name": "ELSTER",
        "patterns": [r"\belster\b", r"\bfinanzamt\b", r"\bbundeszentralamt\b", r"\bsteuererstattung\b"],
        "domains": {"elster.de", "bzst.de", "bundesfinanzministerium.de", "finanzverwaltung.nrw.de"},
        "body_context": "payment",
    },
    {
        "name": "Doctolib",
        "patterns": [r"\bdoctolib\b"],
        "domains": {"doctolib.de", "doctolib.com", "doctolib.fr"},
        "body_context": "account",
    },
    {
        "name": "Netflix",
        "patterns": [r"\bnetflix\b"],
        "domains": {"netflix.com"},
        "body_context": "account",
    },
    {
        "name": "ADAC",
        "patterns": [r"\badac\b"],
        "domains": {"adac.de"},
        "body_context": "delivery",
    },
    {
        "name": "Mercedes-Benz",
        "patterns": [r"\bmercedes(?:\s|-)*benz\b", r"\bmercedes\b"],
        "domains": {"mercedes-benz.de", "mercedes-benz.com", "mercedes.me"},
        "body_context": "payment",
    },
]

BRAND_BODY_CONTEXT_PATTERNS = {
    "hosting": [
        r"\bdomain(?:s)?\b", r"\bhosting\b", r"\bvertrag\b",
        r"\brechnung\b", r"\bverlänger", r"\bfaellig\b", r"\bfällig\b",
        r"\bgesperrt\b", r"\bzahlung\b",
    ],
    "account": [
        r"\bkonto\b", r"\baccount\b", r"\blogin\b", r"\bpasswort\b",
        r"\bverify\b", r"\bverifiz", r"\bbestätig", r"\bgesperrt\b",
        r"\bsicherheits", r"\bsecurity\b", r"\balert\b", r"\bablauf\b",
        r"\bexpire", r"\bläuft\s+ab\b", r"\blaeuft\s+ab\b",
    ],
    "payment": [
        r"\brechnung\b", r"\bzahlung\b", r"\bbezahlen\b", r"\bfällig\b",
        r"\bfaellig\b", r"\bmahnung\b", r"\bbetrag\b", r"\bkarte\b",
        r"\berstattung\b", r"\bübermittlung\b", r"\buebermittlung\b", r"\bsteuer",
    ],
    "delivery": [
        r"\bpaket\b", r"\bsendung\b", r"\bliefer", r"\bzoll\b",
        r"\bgebühr\b", r"\bgebuehr\b", r"\badresse\b",
    ],
    "document": [
        r"\bdokument", r"\bdocument", r"\bvertrag\b", r"\buntersch",
        r"\bsign", r"\bsignatur\b", r"\bfreigabe\b", r"\bgeteilt\b",
        r"\bshared\b", r"\bdatei\b", r"\bfile\b",
    ],
}


def decode_mime_header(header_value):
    """Dekodiert MIME-kodierte Header-Werte."""
    if not header_value:
        return ""
    parts = decode_header(header_value)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            try:
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            except (LookupError, TypeError):
                decoded.append(part.decode("utf-8", errors="replace"))
        else:
            decoded.append(part)
    return " ".join(decoded)


def normalize_match_text(text):
    """Normalisiert Text fuer Regex-Matching, inkl. Zero-Width-Zeichen."""
    text = html.unescape(str(text or ""))
    text = unicodedata.normalize("NFKC", text)
    chars = []
    for char in text:
        category = unicodedata.category(char)
        if category == "Cf":
            continue
        if category.startswith("C"):
            if char.isspace():
                chars.append(" ")
            continue
        chars.append(char)
    return re.sub(r"\s+", " ", "".join(chars)).strip().casefold()


def ascii_match_text(text):
    text = normalize_match_text(text)
    for source, target in GERMAN_ASCII_REPLACEMENTS.items():
        text = text.replace(source, target)
    return text


def compact_match_text(text):
    return re.sub(r"[^a-z0-9]+", "", ascii_match_text(text))


def get_body(msg):
    """Extrahiert Plaintext und HTML, damit HTML-only Links sichtbar bleiben."""
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
    if body_plain and body_html and body_html not in body_plain:
        return body_plain + "\n\n--- HTML ---\n" + body_html
    return body_plain or body_html


def iter_url_matches(text):
    return URL_PATTERN.finditer(text or "")


def extract_urls(text):
    """Extrahiert URLs aus Text."""
    return [match.group(0) for match in iter_url_matches(text)]


class LinkTextParser(HTMLParser):
    """Extrahiert sichtbaren Anchor-Text mit zugehoerigem href."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self._active = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        href = ""
        for name, value in attrs:
            if name.lower() == "href":
                href = value or ""
                break
        self._active.append({"href": href, "text": []})

    def handle_data(self, data):
        if self._active:
            self._active[-1]["text"].append(data)

    def handle_endtag(self, tag):
        if tag.lower() != "a" or not self._active:
            return
        link = self._active.pop()
        self.links.append((link["href"], "".join(link["text"])))

    def finish(self):
        while self._active:
            link = self._active.pop()
            self.links.append((link["href"], "".join(link["text"])))


def extract_html_links(body):
    parser = LinkTextParser()
    try:
        parser.feed(body or "")
        parser.close()
        parser.finish()
    except Exception:
        return []
    return parser.links


def safe_urlparse(value):
    """urlparse ohne ValueError: kaputte URLs (z.B. 'http://x.de]' → 'Invalid IPv6 URL')
    duerfen nie den ganzen Lauf abbrechen."""
    try:
        return urlparse(value)
    except ValueError:
        return urlparse("")


def get_url_domain(value):
    value = html.unescape(value or "").strip().strip("<>\"'")
    value = value.rstrip(").,;:!?]}")
    if not value:
        return ""
    parsed = safe_urlparse(value)
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        return ""
    if not parsed.netloc and not parsed.scheme:
        parsed = safe_urlparse("https://" + value)
    return normalize_domain(parsed.hostname or "")


def domains_equivalent_or_nested(visible_domain, href_domain):
    visible_domain = normalize_domain(visible_domain)
    href_domain = normalize_domain(href_domain)
    if not visible_domain or not href_domain:
        return False
    return domain_matches(href_domain, {visible_domain}) or domain_matches(visible_domain, {href_domain})


def get_link_rewrite_target_params(href_domain):
    for rewrite_domain, params in LINK_REWRITE_TARGET_PARAMS.items():
        if domain_matches(href_domain, {rewrite_domain}):
            return params
    return ()


def extract_rewritten_href_domains(href):
    return {domain for domain in (get_url_domain(url) for url in extract_rewritten_href_urls(href)) if domain}


def extract_rewritten_href_urls(href):
    href = html.unescape(href or "").strip()
    parsed = safe_urlparse(href)
    href_domain = normalize_domain(parsed.hostname or "")
    target_params = get_link_rewrite_target_params(href_domain)
    if not target_params:
        return []
    urls = []
    query = parse_qs(parsed.query, keep_blank_values=False)
    for param in target_params:
        for value in query.get(param, []):
            if get_url_domain(value):
                urls.append(value)
    return urls


def looks_like_dotted_abbreviation(text, start, end, candidate, domain):
    labels = domain.split(".")
    if len(labels) < 2 or get_domain_tld(domain) in COMMON_VISIBLE_DOMAIN_TLDS:
        return False
    if any(len(label) > 2 or re.search(r"[-0-9]", label) for label in labels[:-1]):
        return False
    raw_labels = candidate.split(".")
    has_abbreviation_casing = any(any(char.isupper() for char in label) for label in raw_labels)
    has_trailing_period = end < len(text) and text[end] == "."
    return has_abbreviation_casing or has_trailing_period


def extract_visible_link_domains(text):
    text = html.unescape(text or "")
    domains = set()
    url_spans = []
    for match in iter_url_matches(text):
        url_spans.append(match.span())
        domain = get_url_domain(match.group(0))
        if domain:
            domains.add(domain)
    for match in DOMAIN_TEXT_PATTERN.finditer(text):
        start, end = match.span()
        if any(start >= url_start and end <= url_end for url_start, url_end in url_spans):
            continue
        domain = normalize_domain(match.group(0))
        tld = get_domain_tld(domain)
        if tld not in FILE_LIKE_LINK_TEXT_TLDS and not looks_like_dotted_abbreviation(
            text, start, end, match.group(0), domain
        ):
            domains.add(domain)
    return domains


def is_safe_url(url):
    """Prüft ob eine URL zu einer bekannten sicheren Domain gehört."""
    try:
        # Domain aus URL extrahieren
        domain = re.search(r'https?://([^/:\s]+)', url, re.I)
        if not domain:
            return False
        domain = domain.group(1).lower()
        # Prüfe ob die Domain oder eine Parent-Domain in der Whitelist ist
        for safe in SAFE_URL_DOMAINS:
            if domain == safe or domain.endswith("." + safe):
                return True
    except Exception:
        pass
    return False


def check_auth_results(msg):
    """Prüft SPF/DKIM/DMARC aus Authentication-Results Header.

    Unterscheidet zwischen 'fail' (aktiv gescheitert, verdächtig)
    und 'none' (nicht konfiguriert, bei kleinen Firmen normal).
    """
    score = 0
    auth = msg.get("Authentication-Results", "")
    if not auth:
        return 0
    auth_lower = auth.lower()

    # SPF fail ist ein starkes Signal
    if "spf=fail" in auth_lower:
        score += 15
    elif "spf=softfail" in auth_lower:
        score += 5

    # DKIM fail (aktiv gescheitert) vs. none (nicht konfiguriert)
    if "dkim=fail" in auth_lower:
        score += 15
    # dkim=none ist bei kleinen Firmen normal → keine Punkte

    # DMARC fail vs. none
    if "dmarc=fail" in auth_lower:
        score += 10
    # dmarc=none ist bei kleinen Firmen normal → keine Punkte

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
    """Prüft URLs auf verdächtige Muster. Ignoriert bekannte sichere Domains."""
    urls = extract_urls(body)
    if not urls:
        return 0
    score = 0
    for url in urls:
        effective_urls = extract_rewritten_href_urls(url) or [url]
        for effective_url in effective_urls:
            # Bekannte sichere Domains überspringen; bei Rewrite-Links zählt das echte Ziel.
            if is_safe_url(effective_url):
                continue
            # IP-basierte URLs
            if re.search(r'https?://\d+\.\d+\.\d+\.\d+', effective_url):
                score += 10
            # URL-Shortener
            for shortener in URL_SHORTENERS:
                if shortener in effective_url.lower():
                    score += 5
                    break
            # HTTP statt HTTPS bei Login/Banking-Keywords
            if effective_url.startswith("http://") and re.search(r'login|bank|secure|account|paypal|verify', effective_url, re.I):
                score += 10
    return min(score, 20)


def get_link_text_href_mismatch_score(body):
    """Flaggt Links, deren sichtbare Domain nicht zur tatsaechlichen href-Domain passt."""
    for href, text in extract_html_links(body):
        href_domain = get_url_domain(href)
        if not href_domain:
            continue
        rewritten_domains = extract_rewritten_href_domains(href)
        for visible_domain in extract_visible_link_domains(text):
            if not visible_domain:
                continue
            if rewritten_domains:
                if any(domains_equivalent_or_nested(visible_domain, rewritten_domain) for rewritten_domain in rewritten_domains):
                    continue
                return 35
            if domains_equivalent_or_nested(visible_domain, href_domain):
                continue
            return 35
    return 0


def has_link_text_href_mismatch_signal(body):
    return get_link_text_href_mismatch_score(body) >= 30


def get_spamc_binary(config):
    return config.get("spamassassin", "spamc_binary", fallback=shutil.which("spamc") or "")


def get_spamassassin_binary(config):
    return config.get("spamassassin", "spamassassin_binary", fallback=shutil.which("spamassassin") or "")


def is_spamassassin_configured(config):
    return (
        config.has_section("spamassassin")
        and config.getboolean("spamassassin", "enabled", fallback=False)
        and bool(get_spamc_binary(config) or get_spamassassin_binary(config))
    )


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


INVISIBLE_CHAR_PATTERN = re.compile(r"[\u00ad\u200b-\u200f\u2060-\u2064\u206a-\u206f\ufeff\u180e]")
# Latein und Kyrillisch/Griechisch im selben Wort = Homoglyphen-Trick (z.B. "Spаrkasse").
MIXED_SCRIPT_WORD_PATTERN = re.compile(
    r"(?:[A-Za-z][\u0370-\u03FF\u0400-\u052F]|[\u0370-\u03FF\u0400-\u052F][A-Za-z])"
)


def has_invisible_chars(text):
    return bool(INVISIBLE_CHAR_PATTERN.search(html.unescape(text or "")))


def check_encoding_tricks(msg):
    """Prüft auf Encoding-Tricks in Absendername und Betreff.

    Unsichtbare Zeichen (Zero-Width, Soft-Hyphen, BOM) in Anzeigename oder
    Betreff kommen in normaler Post nicht vor; in der Praxis waren 31/31 solcher
    Mails Phishing (apoBank-/Volksbank-/ELSTER-Welle 2026). Rein kyrillische
    Namen sind dagegen normale Patienten und zaehlen nicht.
    """
    from_header = decode_mime_header(msg.get("From", ""))
    subject = decode_mime_header(msg.get("Subject", ""))
    display_name = parseaddr(from_header)[0] or from_header
    if has_invisible_chars(display_name) or has_invisible_chars(subject):
        return 45
    if MIXED_SCRIPT_WORD_PATTERN.search(display_name) or MIXED_SCRIPT_WORD_PATTERN.search(subject):
        return 30
    return 0


def has_encoding_trick_signal(msg):
    return check_encoding_tricks(msg) >= 30


def check_freemail_institution(msg):
    """Freemail-Absender mit Institutions-Anzeigename ("Service", "Verwaltung", "ELSTER Info")."""
    from_domain = get_from_domain(msg)
    if not domain_matches(from_domain, FREEMAIL_DOMAINS):
        return 0
    score = 0
    display_name = parseaddr(decode_mime_header(msg.get("From", "")))[0]
    display_text = normalize_match_text(display_name)
    if display_text and "@" not in display_text and INSTITUTIONAL_DISPLAY_PATTERN.search(display_text):
        score += 25
    if domain_matches(from_domain, EXOTIC_FREEMAIL_DOMAINS):
        score += 15
    return score


def check_from_domain_spoofing(msg):
    """Prüft ob die Absender-Domain eine bekannte Marke imitiert.

    Flaggt nur bei verdächtigen TLDs oder offensichtlichen Typos.
    Regionale Varianten (sparkasse-siegen.de etc.) sind legitim.
    """
    from_addr = parseaddr(msg.get("From", ""))[1].lower()
    if not from_addr or "@" not in from_addr:
        return 0
    domain = from_addr.split("@")[-1]
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""

    # Bekannte Marken die oft imitiert werden
    brands = ["telekom", "paypal", "amazon", "dhl", "sparkasse", "volksbank",
              "postbank", "microsoft", "google", "apple", "netflix", "dkb"]

    for brand in brands:
        if brand in domain:
            # Verdächtige TLD + Markenname = starkes Signal
            if tld in SUSPICIOUS_TLDS:
                return 20
            # Bekannte Marke aber mit ungewöhnlicher Länder-TLD (telekomro.com → .com aber "ro" im Namen)
            if tld in LEGIT_BUSINESS_TLDS and domain not in _get_legit_domains(brand):
                # Nur flaggen wenn die Domain wie ein Typo aussieht
                if re.search(r'[0-9]|(.)\1{2,}', domain):  # Zahlen oder Zeichenwiederholungen
                    return 15
            # Ausländische TLD die nicht zu DE-Marken passt
            if tld not in LEGIT_BUSINESS_TLDS and tld not in SUSPICIOUS_TLDS:
                return 10
    return 0


def normalize_domain(domain):
    """Normalisiert Domains aus Headern/URLs für robuste Vergleiche."""
    return (domain or "").strip().strip(".").lower()


def domain_matches(domain, allowed_domains):
    domain = normalize_domain(domain)
    if not domain:
        return False
    return any(domain == allowed or domain.endswith("." + allowed) for allowed in allowed_domains)


def get_from_domain(msg):
    from_addr = parseaddr(msg.get("From", ""))[1].lower()
    if not from_addr or "@" not in from_addr:
        return ""
    return normalize_domain(from_addr.split("@")[-1])


def get_domain_tld(domain):
    domain = normalize_domain(domain)
    return domain.rsplit(".", 1)[-1] if "." in domain else ""


def brand_pattern_matches(patterns, text):
    text = normalize_match_text(text)
    return any(re.search(pattern, text, re.I) for pattern in patterns)


def brand_matches_domain(rule, domain):
    """Erkennt Marken auch in verschleierten Domains wie microsoft-login.example."""
    domain = normalize_domain(domain)
    if not domain:
        return False
    patterns = rule.get("domain_patterns", rule["patterns"])
    domain_with_separators = re.sub(r"[-_.]+", " ", domain)
    domain_compact = re.sub(r"[^a-z0-9]+", "", domain)
    return (
        brand_pattern_matches(patterns, domain)
        or brand_pattern_matches(patterns, domain_with_separators)
        or brand_pattern_matches(patterns, domain_compact)
    )


def body_has_brand_context(context, subject, body):
    patterns = BRAND_BODY_CONTEXT_PATTERNS.get(context, [])
    if not patterns:
        return False
    text = normalize_match_text(" ".join([subject or "", (body or "")[:3000]]))
    return any(re.search(pattern, text, re.I) for pattern in patterns)


def get_brand_spoofing_score(msg, body=None):
    """Bewertet bekannte Marken auf fremden Absender-Domains."""
    if body is None:
        body = get_body(msg)

    subject = decode_mime_header(msg.get("Subject", ""))
    from_header = decode_mime_header(msg.get("From", ""))
    display_name = parseaddr(from_header)[0]
    from_domain = get_from_domain(msg)
    from_tld = get_domain_tld(from_domain)
    subject_text = normalize_match_text(subject)
    display_text = normalize_match_text(display_name)
    body_text = normalize_match_text((body or "")[:3000])
    from_addr = parseaddr(from_header)[1].lower()
    local_part = from_addr.split("@", 1)[0] if "@" in from_addr else ""
    local_text = normalize_match_text(re.sub(r"[-_.+]+", " ", local_part))

    for rule in BRAND_SPOOFING_RULES:
        if domain_matches(from_domain, rule["domains"]):
            continue

        subject_brand = brand_pattern_matches(rule["patterns"], subject_text)
        display_brand = brand_pattern_matches(rule["patterns"], display_text)
        contextual_display_brand = brand_pattern_matches(rule.get("contextual_display_patterns", []), display_text)
        contextual_subject_brand = brand_pattern_matches(rule.get("contextual_subject_patterns", []), subject_text)
        local_brand = brand_pattern_matches(rule.get("domain_patterns", rule["patterns"]), local_text)
        body_brand = brand_pattern_matches(rule["patterns"], body_text)
        domain_brand = brand_matches_domain(rule, from_domain)
        suspicious_tld = from_tld in SUSPICIOUS_TLDS
        consumer_domain = domain_matches(from_domain, rule.get("consumer_domains", set()))
        has_abuse_context = body_has_brand_context(rule.get("body_context"), subject, body) or text_has_bank_abuse_context(
            subject, body[:3000]
        )

        # Der Anzeigename behauptet eine Marke, aber die From-Domain passt nicht.
        # Das ist das stärkste generische Spoofing-Signal.
        if display_brand:
            if consumer_domain and not has_abuse_context:
                continue
            return 45 if suspicious_tld else 40

        # Sehr kurze Marken wie O2 brauchen den Missbrauchskontext separat:
        # "O2 Saettigung" soll harmlos bleiben, "O2" + "Login erforderlich" nicht.
        if contextual_display_brand and has_abuse_context:
            return 45 if suspicious_tld else 40

        # Markenname steckt in einer fremden Domain, z.B.
        # mercedes-benz.de.ejharris.com oder telekom-login.example.
        if domain_brand:
            return 40 if suspicious_tld else 35

        # Gmail/Outlook/Hotmail sind nutzerkontrolliert. Betreff- oder
        # Local-Part-Markennennungen sind dort zu laut; nur der Anzeigename
        # darf oben mit Missbrauchskontext als starkes Signal zaehlen.
        if consumer_domain:
            continue

        # Betreff-only Markennennung zaehlt nur mit typischem Missbrauchskontext.
        # Body-only Mentions sind normale Drittanbieter-/Weiterleitungsinhalte.
        if (subject_brand or contextual_subject_brand or local_brand or body_brand) and has_abuse_context:
            return 30

    return 0


def has_brand_spoofing_signal(msg, body=None):
    return get_brand_spoofing_score(msg, body) >= 30


def text_has_bank_abuse_context(*parts):
    text = normalize_match_text(" ".join(part or "" for part in parts))
    return any(re.search(pattern, text, re.I) for pattern in BANK_ABUSE_CONTEXT_PATTERNS)


def extract_generic_bank_claim_tokens(text, allow_compound=True):
    """Extrahiert behauptete Banknamen wie 'apoBank' oder 'Muster Bank'."""
    text = ascii_match_text(text)
    tokens = set()
    for match in GENERIC_BANK_CLAIM_PATTERN.finditer(text):
        compound = match.group("compound")
        if compound and not allow_compound:
            continue
        token_text = compound or f"{match.group('separated')} bank"
        token = compact_match_text(token_text)
        if len(token) >= 5 and token not in {"bank", "onlinebank"} | NON_FINANCIAL_BANK_CLAIM_TOKENS:
            tokens.add(token)
    return tokens


def bank_pattern_matches_domain(domain):
    domain = normalize_domain(domain)
    if not domain:
        return False
    domain_with_separators = re.sub(r"[-_.]+", " ", domain)
    domain_compact = compact_match_text(domain)
    return (
        brand_pattern_matches(BANK_BRAND_PATTERNS, domain)
        or brand_pattern_matches(BANK_BRAND_PATTERNS, domain_with_separators)
        or brand_pattern_matches(BANK_BRAND_PATTERNS, domain_compact)
    )


def sender_domain_matches_generic_bank_claim(from_domain, claim_tokens):
    from_domain = normalize_domain(from_domain)
    if get_domain_tld(from_domain) in SUSPICIOUS_TLDS:
        return False
    labels = from_domain.split(".")
    if len(labels) < 2:
        return False
    sender_stem = compact_match_text(labels[-2])
    return any(sender_stem == token for token in claim_tokens)


def get_bank_claim_parts(msg):
    subject = decode_mime_header(msg.get("Subject", ""))
    from_header = decode_mime_header(msg.get("From", ""))
    display_name = parseaddr(from_header)[0]
    return subject, display_name


def get_bank_sender_claim_mismatch_score(msg, body=None):
    """Flaggt Bank-Absenderclaims, deren From-Domain nicht zur behaupteten Bank passt."""
    if body is None:
        body = get_body(msg)

    subject, display_name = get_bank_claim_parts(msg)
    from_domain = get_from_domain(msg)
    if not from_domain:
        return 0

    has_context = text_has_bank_abuse_context(subject, body[:1000])
    from_header = decode_mime_header(msg.get("From", ""))
    from_addr = parseaddr(from_header)[1].lower()
    local_part = from_addr.split("@", 1)[0] if "@" in from_addr else ""
    local_text = re.sub(r"[-_.+]+", " ", local_part)
    display_known = brand_pattern_matches(BANK_BRAND_PATTERNS, display_name)
    subject_known = brand_pattern_matches(BANK_BRAND_PATTERNS, subject)
    domain_known = bank_pattern_matches_domain(from_domain)
    local_known = brand_pattern_matches(BANK_BRAND_PATTERNS, local_text) and has_context
    body_known = brand_pattern_matches(BANK_BRAND_PATTERNS, (body or "")[:3000]) and has_context
    display_tokens = extract_generic_bank_claim_tokens(display_name, allow_compound=has_context)
    subject_tokens = extract_generic_bank_claim_tokens(subject) if has_context else set()
    claim_tokens = display_tokens | subject_tokens

    if not (display_known or subject_known or domain_known or local_known or body_known or claim_tokens):
        return 0
    if domain_matches(from_domain, LEGIT_BANK_DOMAINS):
        return 0
    if claim_tokens and sender_domain_matches_generic_bank_claim(from_domain, claim_tokens):
        return 0
    return 30


def has_bank_sender_claim_mismatch_signal(msg, body=None):
    return get_bank_sender_claim_mismatch_score(msg, body) >= 30


def has_bank_brand_signal(msg, body=None):
    if body is None:
        body = get_body(msg)
    return has_bank_sender_claim_mismatch_signal(msg, body)


def check_bank_brand_mismatch(msg, body=None):
    """Bank/VR/Sparkasse-Absender von fremden Domains sind ein starkes Signal."""
    return get_bank_sender_claim_mismatch_score(msg, body)


def requires_claude_review(msg, body=None):
    if body is None:
        body = get_body(msg)
    return (
        has_bank_sender_claim_mismatch_signal(msg, body)
        or has_brand_spoofing_signal(msg, body)
        or has_link_text_href_mismatch_signal(body)
        or has_encoding_trick_signal(msg)
    )


def parse_spamassassin_score(output):
    """Extrahiert Score und Schwelle aus spamc oder spamassassin Ausgabe."""
    match = re.search(r"(?<![\w.-])(-?\d+(?:\.\d+)?)/(-?\d+(?:\.\d+)?)(?![\w.-])", output)
    if match:
        return float(match.group(1)), float(match.group(2))

    match = re.search(
        r"\bscore=(-?\d+(?:\.\d+)?)\s+required=(-?\d+(?:\.\d+)?)\b",
        output,
        re.IGNORECASE,
    )
    if match:
        return float(match.group(1)), float(match.group(2))

    match = re.search(
        r"\((-?\d+(?:\.\d+)?)\s+points,\s+(-?\d+(?:\.\d+)?)\s+required\)",
        output,
        re.IGNORECASE,
    )
    if match:
        return float(match.group(1)), float(match.group(2))

    return None


def build_spamassassin_result(output, truncated, scanner_name):
    parsed = parse_spamassassin_score(output)
    if not parsed:
        log.warning(f"{scanner_name} Antwort nicht parsebar: {output[:200]}")
        return None

    score, threshold = parsed
    if threshold <= 0:
        log.warning(f"{scanner_name} lieferte unbrauchbaren Schwellwert: {output[:200]}")
        return None

    return {
        "score": score,
        "threshold": threshold,
        "truncated": truncated,
    }


def check_spamassassin_fallback(scan_bytes, truncated, timeout, config):
    spamassassin_bin = get_spamassassin_binary(config)
    if not spamassassin_bin:
        return None

    try:
        result = subprocess.run(
            [spamassassin_bin, "-t"],
            input=scan_bytes,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        log.warning(f"SpamAssassin Fallback Timeout nach {timeout}s")
        return None
    except Exception as e:
        log.warning(f"SpamAssassin Fallback Fehler: {e}")
        return None

    output = (result.stdout or b"").decode("utf-8", errors="replace").strip()
    if result.returncode != 0:
        stderr = (result.stderr or b"").decode("utf-8", errors="replace").strip()
        log.warning(f"spamassassin Fallback Fehler (exit {result.returncode}): {(stderr or output)[:200]}")
        return None

    return build_spamassassin_result(output, truncated, "spamassassin")


def check_spamassassin(raw_email, config):
    """Fragt SpamAssassin über spamc ab und gibt Score/Schwellwert zurück."""
    if not is_spamassassin_configured(config):
        return None

    spamc_bin = get_spamc_binary(config)
    timeout = config.getint("spamassassin", "timeout", fallback=DEFAULT_SPAMASSASSIN_TIMEOUT)
    max_bytes = config.getint("spamassassin", "max_bytes", fallback=DEFAULT_SPAMASSASSIN_MAX_BYTES)
    scan_bytes = raw_email[:max_bytes] if max_bytes > 0 else raw_email
    truncated = max_bytes > 0 and len(raw_email) > max_bytes
    spamc_max_size = max_bytes if max_bytes > 0 else len(scan_bytes)
    spamc_args = [spamc_bin, "-x", "-c"]
    if spamc_max_size > 0:
        spamc_args.extend(["-s", str(min(spamc_max_size, 268435456))])

    if spamc_bin:
        try:
            result = subprocess.run(
                spamc_args,
                input=scan_bytes,
                capture_output=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            log.warning(f"SpamAssassin Timeout nach {timeout}s")
        except Exception as e:
            log.warning(f"SpamAssassin Fehler: {e}")
        else:
            output = (result.stdout or b"").decode("utf-8", errors="replace").strip()
            if result.returncode in (0, 1):
                spamc_result = build_spamassassin_result(output, truncated, "spamc")
                if spamc_result:
                    return spamc_result
            else:
                stderr = (result.stderr or b"").decode("utf-8", errors="replace").strip()
                log.warning(f"spamc Fehler (exit {result.returncode}): {(stderr or output)[:200]}")

    return check_spamassassin_fallback(scan_bytes, truncated, timeout, config)


def format_spamassassin_detail(spam_result):
    if not spam_result:
        return ""
    suffix = ",truncated" if spam_result.get("truncated") else ""
    return f"spamassassin={spam_result['score']:.1f}/{spam_result['threshold']:.1f}{suffix}"


def is_spamassassin_spam(spam_result, threshold_spam):
    return bool(spam_result and spam_result["score"] >= threshold_spam)


def _get_legit_domains(brand):
    """Gibt bekannte legitime Domains für eine Marke zurück."""
    mapping = {
        "telekom": {"telekom.de", "t-online.de", "t-systems.de"},
        "paypal": {"paypal.com", "paypal.de"},
        "amazon": {"amazon.de", "amazon.com", "amazonaws.com"},
        "dhl": {"dhl.de", "dhl.com", "deutschepost.de"},
        "microsoft": {"microsoft.com", "outlook.com", "hotmail.com"},
        "google": {"google.com", "gmail.com"},
        "apple": {"apple.com", "icloud.com"},
    }
    return mapping.get(brand, set())


def calculate_score(msg):
    """Berechnet den Phishing-Score einer Mail."""
    body = get_body(msg)
    subject = decode_mime_header(msg.get("Subject", ""))
    details = []

    checks = [
        ("auth_results", check_auth_results(msg)),
        ("from_reply_mismatch", check_from_reply_mismatch(msg)),
        ("suspicious_urls", check_urls(body)),
        ("link_text_href_mismatch", get_link_text_href_mismatch_score(body)),
        ("urgency_keywords", check_urgency_keywords(body, subject)),
        ("html_forms", check_html_forms(body)),
        ("suspicious_attachments", check_attachments(msg)),
        ("encoding_tricks", check_encoding_tricks(msg)),
        ("freemail_institution", check_freemail_institution(msg)),
        ("domain_spoofing", check_from_domain_spoofing(msg)),
        ("brand_spoofing", get_brand_spoofing_score(msg, body)),
        ("bank_brand_mismatch", check_bank_brand_mismatch(msg, body)),
    ]

    total = 0
    for name, points in checks:
        if points > 0:
            details.append(f"{name}={points}")
            total += points

    return min(total, 100), details


def ask_claude(msg, config, details=None):
    """Fragt Claude ob eine E-Mail Phishing ist."""
    claude_bin = config.get("claude", "binary", fallback="/root/.local/bin/claude")
    claude_model = config.get("claude", "model", fallback="sonnet")
    subject = decode_mime_header(msg.get("Subject", ""))
    from_addr = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    auth_results = msg.get("Authentication-Results", "")
    body = get_body(msg)[:3000]

    prompt = (
        f"Du bist ein E-Mail-Sicherheitsanalyst für ein deutsches Betriebsarztzentrum (BAZ West / Werksarzt Online). "
        f"Das Postfach empfängt regulär Geschäftsmails von Kunden, Lieferanten, Apotheken, Krankenhäusern, "
        f"Firmenkontakten und internen Systemen (Terminplaner, BAZ-Systeme).\n\n"
        f"Analysiere diese E-Mail und entscheide: ist sie PHISHING oder SAFE?\n\n"
        f"Beachte:\n"
        f"- Kleine Firmen haben oft kein DKIM/DMARC → dkim=none/dmarc=none ist KEIN Phishing-Indikator\n"
        f"- Sekretärinnen schreiben oft im Namen anderer → Absender ≠ Signatur ist normal\n"
        f"- Anhang-Erwähnungen ohne Anhang können bedeuten, dass der Anhang als Bild/PDF inline ist\n"
        f"- Teams/Zoom-Links, HubSpot-Signaturen, Google-CDN-Bilder sind normal\n"
        f"- Patienten schreiben von Freemail-Adressen (gmx, gmail, t-online), oft mit kyrillischen Namen → normal\n"
        f"- Banken, Behörden (ELSTER, Finanzamt), Paketdienste oder Hoster schreiben NIE von Freemail-Adressen\n"
        f"- Unsichtbare Zeichen (Zero-Width, Soft-Hyphen) in Absendername/Betreff sind ein sicheres Phishing-Zeichen\n"
        f"- Aufforderungen zu Verifizierung/Freigabe/Datenabgleich mit Link sind klassisches Credential-Phishing\n\n"
        f"Heuristik-Signale des Vorfilters: {', '.join(details) if details else 'keine'}\n"
        f"Von: {from_addr}\n"
        f"Reply-To: {reply_to or '(nicht gesetzt)'}\n"
        f"Betreff: {subject}\n"
        f"Auth-Results: {auth_results[:300] if auth_results else '(nicht vorhanden)'}\n"
        f"Body:\n{body}\n\n"
        f"Antworte EXAKT in diesem Format (nichts anderes):\n"
        f"PHISHING — [kurze Begründung]\n"
        f"oder\n"
        f"SAFE — [kurze Begründung]"
    )

    try:
        result = subprocess.run(
            [claude_bin, "-p", prompt, "--model", claude_model],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout.strip()
        if not output and result.returncode != 0:
            log.warning(f"Claude Fehler (exit {result.returncode}): {result.stderr[:200]}")
            return None
        log.info(f"Claude Antwort: {output[:200]}")
        if output.upper().startswith("PHISHING"):
            return True
        if output.upper().startswith("SAFE"):
            return False
        log.warning(f"Claude Antwort nicht eindeutig: {output[:200]}")
        return None
    except subprocess.TimeoutExpired:
        log.warning("Claude Timeout nach 60s")
        return None
    except Exception as e:
        log.error(f"Claude Fehler: {e}")
        return None


def get_last_uid():
    """Liest die letzte verarbeitete UID aus der State-Datei."""
    if not os.path.exists(STATE_FILE):
        return 0
    try:
        with open(STATE_FILE, "r") as f:
            return int(f.read().strip())
    except (ValueError, IOError):
        return 0


def save_last_uid(uid):
    """Speichert die letzte verarbeitete UID in die State-Datei."""
    try:
        with open(STATE_FILE, "w") as f:
            f.write(str(uid))
    except IOError as e:
        log.warning(f"Konnte State-Datei nicht schreiben: {e}")


def check_uidvalidity(conn, last_uid):
    """Setzt den UID-Zeiger neu, wenn der Server die UIDs neu vergeben hat.

    Sonst wuerde ein alter last_uid entweder alles erneut pruefen (tausende
    Mails) oder, wenn er groesser als alle neuen UIDs ist, nie wieder etwas.
    """
    status, data = conn.response("UIDVALIDITY")
    current = (data[0] or b"").decode() if data and data[0] else ""
    if not current:
        return last_uid
    stored = ""
    if os.path.exists(UIDVALIDITY_FILE):
        with open(UIDVALIDITY_FILE) as f:
            stored = f.read().strip()
    if stored and stored != current:
        status, search = conn.uid("SEARCH", None, "ALL")
        uids = search[0].split() if status == "OK" and search[0] else []
        new_last = max((int(u) for u in uids), default=0)
        log.warning(f"UIDVALIDITY geaendert ({stored} -> {current}); setze last_uid {last_uid} -> {new_last}, Backlog wird uebersprungen")
        notify_failure(RuntimeError(f"UIDVALIDITY geaendert ({stored} -> {current}), Backlog bis UID {new_last} uebersprungen"))
        save_last_uid(new_last)
        last_uid = new_last
    if stored != current:
        with open(UIDVALIDITY_FILE, "w") as f:
            f.write(current)
    return last_uid


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


def move_to_folder(imap_conn, uid, folder_name):
    """Verschiebt eine Mail in den angegebenen IMAP-Ordner."""
    result = imap_conn.uid("COPY", uid, folder_name)
    if result[0] == "OK":
        imap_conn.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
        imap_conn.expunge()
        return True
    return False


def move_to_fish(imap_conn, uid, folder_fish):
    """Verschiebt eine Mail in den Fish-Ordner."""
    return move_to_folder(imap_conn, uid, folder_fish)


def process_mailbox(config):
    """Hauptlogik: Verbindet sich mit IMAP und prüft neue Mails per UID."""
    server = config.get("imap", "server")
    port = config.getint("imap", "port")
    user = config.get("imap", "user")
    password = config.get("imap", "password")
    folder_inbox = config.get("imap", "folder_inbox")
    folder_fish = config.get("imap", "folder_fish")
    folder_spam = config.get("imap", "folder_spam", fallback=DEFAULT_SPAM_FOLDER)
    threshold_auto = config.getint("thresholds", "auto_fish")
    threshold_claude = config.getint("thresholds", "claude_check")
    threshold_spam = config.getfloat("thresholds", "spamassassin_spam", fallback=DEFAULT_SPAMASSASSIN_THRESHOLD)
    spamassassin_enabled = is_spamassassin_configured(config)

    conn = imaplib.IMAP4_SSL(server, port)
    conn.login(user, password)
    log.info(f"IMAP Login erfolgreich: {user}@{server}")

    ensure_fish_folder(conn, folder_fish)
    if spamassassin_enabled and folder_spam != folder_fish:
        ensure_fish_folder(conn, folder_spam)
    conn.select(folder_inbox)
    last_uid = check_uidvalidity(conn, get_last_uid())
    # Scan by UID, not by UNSEEN. BODY.PEEK below preserves unread flags for FreeScout,
    # while already-read-but-new messages are still reviewed.
    search_query = f"UID {last_uid+1}:*" if last_uid > 0 else "ALL"

    status, data = conn.uid("SEARCH", None, search_query)
    if status != "OK" or not data[0]:
        log.info("Keine neuen Mails seit letztem Lauf")
        conn.logout()
        return

    raw_uids = data[0].split()
    uids = [uid for uid in raw_uids if int(uid) > last_uid]
    if not uids:
        log.info("Keine neuen Mails seit letztem Lauf")
        conn.logout()
        return

    log.info(f"{len(uids)} neue Mail(s) gefunden")

    moved_fish = 0
    moved_spam = 0
    for uid in uids:
        # Read the full message without setting \Seen so FreeScout can still import it.
        status, msg_data = conn.uid("FETCH", uid, "(BODY.PEEK[])")
        if status != "OK":
            continue

        raw_email = msg_data[0][1]
        msg = email.message_from_bytes(raw_email)
        subject = decode_mime_header(msg.get("Subject", ""))
        from_addr = msg.get("From", "")
        try:
            body = get_body(msg)
            score, details = calculate_score(msg)
        except Exception as e:
            # Eine einzelne kaputte Mail darf den Lauf nicht stoppen: so blieb der
            # Filter vom 26.05. bis 16.10.2026 an UID 10081 haengen (0 Mails geprueft).
            log.error(f"Mail UID {uid.decode()} '{subject}' von {from_addr}: Scoring fehlgeschlagen, bleibt in INBOX: {e}", exc_info=True)
            continue
        spam_result = check_spamassassin(raw_email, config)
        spam_detail = format_spamassassin_detail(spam_result)
        detail_parts = details[:]
        if spam_detail:
            detail_parts.append(spam_detail)
        detail_str = ", ".join(detail_parts) if detail_parts else "none"
        log.info(f"Mail: '{subject}' von {from_addr} — Score: {score} ({detail_str})")

        needs_claude = requires_claude_review(msg, body)
        is_spam = is_spamassassin_spam(spam_result, threshold_spam)

        if needs_claude:
            log.info("  → Marken-/Finanzsignal erkannt, frage Claude unabhängig vom Score...")
            claude_result = ask_claude(msg, config, details)
            if claude_result is True:
                log.info(f"  → Claude: PHISHING, verschiebe nach {folder_fish}")
                if move_to_fish(conn, uid, folder_fish):
                    moved_fish += 1
            elif claude_result is False:
                if is_spam:
                    log.info(f"  → Claude: SAFE, aber SpamAssassin {spam_result['score']:.1f} >= {threshold_spam:.1f}; verschiebe nach {folder_spam}")
                    if move_to_folder(conn, uid, folder_spam):
                        moved_spam += 1
                else:
                    log.info("  → Claude: SAFE, belasse in INBOX ohne Flags zu ändern")
            else:
                if score >= threshold_auto:
                    log.warning(f"  → Claude ohne eindeutige Entscheidung, aber Score {score} >= {threshold_auto}; verschiebe nach {folder_fish}")
                    if move_to_fish(conn, uid, folder_fish):
                        moved_fish += 1
                elif is_spam:
                    log.warning(f"  → Claude ohne eindeutige Entscheidung, aber SpamAssassin {spam_result['score']:.1f} >= {threshold_spam:.1f}; verschiebe nach {folder_spam}")
                    if move_to_folder(conn, uid, folder_spam):
                        moved_spam += 1
                else:
                    log.warning("  → Claude ohne eindeutige Entscheidung, belasse in INBOX ohne Flags zu ändern")
        elif score >= threshold_auto:
            log.info(f"  → PHISHING (Score {score} >= {threshold_auto}), verschiebe nach {folder_fish}")
            if move_to_fish(conn, uid, folder_fish):
                moved_fish += 1
        elif score >= threshold_claude:
            log.info(f"  → Score {score}, frage Claude...")
            claude_result = ask_claude(msg, config, details)
            if claude_result is True:
                log.info(f"  → Claude: PHISHING, verschiebe nach {folder_fish}")
                if move_to_fish(conn, uid, folder_fish):
                    moved_fish += 1
            elif claude_result is False:
                if is_spam:
                    log.info(f"  → Claude: SAFE, aber SpamAssassin {spam_result['score']:.1f} >= {threshold_spam:.1f}; verschiebe nach {folder_spam}")
                    if move_to_folder(conn, uid, folder_spam):
                        moved_spam += 1
                else:
                    log.info("  → Claude: SAFE, belasse in INBOX ungelesen fuer FreeScout")
            else:
                if is_spam:
                    log.warning(f"  → Claude ohne eindeutige Entscheidung, aber SpamAssassin {spam_result['score']:.1f} >= {threshold_spam:.1f}; verschiebe nach {folder_spam}")
                    if move_to_folder(conn, uid, folder_spam):
                        moved_spam += 1
                else:
                    log.warning("  → Claude ohne eindeutige Entscheidung, belasse in INBOX ohne Flags zu ändern")
        elif is_spam:
            log.info(f"  → SPAM (SpamAssassin {spam_result['score']:.1f} >= {threshold_spam:.1f}), verschiebe nach {folder_spam}")
            if move_to_folder(conn, uid, folder_spam):
                moved_spam += 1
        else:
            log.info(f"  → SAFE (Score {score} < {threshold_claude}), belasse in INBOX ungelesen fuer FreeScout")

    log.info(f"Fertig. {moved_fish} Mail(s) nach {folder_fish}, {moved_spam} Mail(s) nach {folder_spam} verschoben")

    if uids:
        max_uid = int(max(uids))
        save_last_uid(max_uid)

    conn.logout()


ALERT_MARKER = "/tmp/fishcatcher.alerted"
ALERT_INTERVAL_SECONDS = 6 * 3600


def notify_failure(error):
    """Telegram-Alarm bei Lauf-Abbruch, gedrosselt auf einmal pro 6 h."""
    try:
        if os.path.exists(ALERT_MARKER) and time.time() - os.path.getmtime(ALERT_MARKER) < ALERT_INTERVAL_SECONDS:
            return
        open(ALERT_MARKER, "w").close()
        subprocess.run(
            ["/usr/local/bin/send-telegram-alert.sh", "Fishcatcher abgebrochen",
             f"{type(error).__name__}: {str(error)[:300]}\nSiehe {LOG_FILE}"],
            timeout=30, capture_output=True,
        )
    except Exception as alert_error:
        log.warning(f"Telegram-Alarm fehlgeschlagen: {alert_error}")


def main():
    lock_fd = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit(0)

    try:
        config = configparser.RawConfigParser()
        config.read(CONFIG_PATH)
        process_mailbox(config)
    except Exception as e:
        log.error(f"Fehler: {e}", exc_info=True)
        notify_failure(e)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()
        try:
            os.unlink(LOCK_FILE)
        except OSError:
            pass


if __name__ == "__main__":
    main()
