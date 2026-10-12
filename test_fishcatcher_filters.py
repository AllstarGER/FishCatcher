import configparser
import importlib.util
import logging
import pathlib
import unittest
from unittest.mock import patch
from email.message import EmailMessage


def load_fishcatcher():
    original_basic_config = logging.basicConfig
    logging.basicConfig = lambda *args, **kwargs: None
    try:
        path = pathlib.Path(__file__).with_name("fishcatcher.py")
        spec = importlib.util.spec_from_file_location("fishcatcher", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        logging.basicConfig = original_basic_config


fc = load_fishcatcher()


def make_msg(from_header, subject, body="Bitte aktualisieren Sie Ihr Online-Banking Profil."):
    msg = EmailMessage()
    msg["From"] = from_header
    msg["Subject"] = subject
    msg.set_content(body)
    return msg


def make_html_msg(html):
    msg = EmailMessage()
    msg["From"] = "Sender <sender@example.com>"
    msg["Subject"] = "Test"
    msg.add_alternative(html, subtype="html")
    return msg


def make_spamassassin_config():
    config = configparser.ConfigParser()
    config["spamassassin"] = {
        "enabled": "true",
        "spamc_binary": "/usr/bin/spamc",
        "spamassassin_binary": "/usr/bin/spamassassin",
        "timeout": "3",
        "max_bytes": "100000",
    }
    return config


class FishcatcherFilterTests(unittest.TestCase):
    def assert_review(self, msg, expected_review, expected_bank_score=None, expected_brand_score=None):
        body = fc.get_body(msg)
        self.assertEqual(fc.requires_claude_review(msg, body), expected_review)
        if expected_bank_score is not None:
            self.assertEqual(fc.check_bank_brand_mismatch(msg, body), expected_bank_score)
        if expected_brand_score is not None:
            self.assertEqual(fc.get_brand_spoofing_score(msg, body), expected_brand_score)

    def test_apobank_claim_from_foreign_domain_forces_review(self):
        self.assert_review(
            make_msg("apoBank <info@yamanashi-seimitsu.co.jp>", "Service-Mitteilung: Aktion erforderlich"),
            True,
            expected_bank_score=30,
        )

    def test_zero_width_apobank_subject_forces_review(self):
        self.assert_review(
            make_msg("Kontakt <kontakt@example.org>", "AP\u200fOBA\u200fNK - Statusmeldung zu Ihrem Online-Ba\u200fnking"),
            True,
            expected_bank_score=30,
        )

    def test_generic_bank_display_name_is_compared_to_sender_domain(self):
        self.assert_review(
            make_msg("Muster Bank Kundenservice <info@unrelated.example>", "Bitte Zugang pruefen"),
            True,
            expected_bank_score=30,
        )
        self.assert_review(
            make_msg("Muster Bank <service@muster-bank.de>", "Terminbestaetigung"),
            False,
            expected_bank_score=0,
        )
        self.assert_review(
            make_msg("Muster Bank <info@musterbank.xyz>", "Aktion erforderlich", "Konto gesperrt, bitte Login pruefen"),
            True,
            expected_bank_score=30,
        )

    def test_body_only_bankverbindung_without_abuse_context_stays_safe(self):
        self.assert_review(
            make_msg(
                "Michelle Spier <masterdata@stockmeier.com>",
                "Kreditor 76369 - Bankverbindung",
                "Bitte beachten Sie unsere Bankverbindung in der Signatur.",
            ),
            False,
            expected_bank_score=0,
        )
        self.assert_review(
            make_msg("Blood Bank <info@klinikum.example>", "Termin", "Hallo"),
            False,
            expected_bank_score=0,
        )
        self.assert_review(
            make_msg("Datenbank Team <it@example.com>", "Wartung", "Hallo"),
            False,
            expected_bank_score=0,
        )

    def test_bank_brand_in_spoofed_domain_or_abuse_body_forces_review(self):
        self.assert_review(
            make_msg("security@sparkasse-login.de", "Neue Nachricht", "Hallo"),
            True,
            expected_bank_score=30,
        )
        self.assert_review(
            make_msg("Info <info@example.com>", "Ihre Sparkasse Nachricht", "Guten Tag, bitte lesen Sie die Nachricht."),
            True,
            expected_bank_score=30,
        )
        self.assert_review(
            make_msg("foo@example.com", "Ihre Nachricht", "Ihre Sparkasse: Konto gesperrt"),
            True,
            expected_bank_score=30,
        )

    def test_brand_body_and_local_part_need_abuse_context(self):
        self.assert_review(
            make_msg("service@example.net", "Benachrichtigung", "PayPal Konto gesperrt, bitte Login"),
            True,
            expected_brand_score=30,
        )
        self.assert_review(
            make_msg("support-paypal@example.net", "Benachrichtigung", "Konto gesperrt login erforderlich"),
            True,
            expected_brand_score=30,
        )
        self.assert_review(
            make_msg("service@example.net", "Benachrichtigung", "Wir nutzen PayPal gelegentlich."),
            False,
            expected_brand_score=0,
        )

    def test_consumer_google_microsoft_domains_do_not_flag_subject_only_brand_context(self):
        self.assert_review(
            make_msg("Person <person@gmail.com>", "Google Ads Report", "Hier ist der Report ohne Login-Aufforderung."),
            False,
            expected_brand_score=0,
        )
        self.assert_review(
            make_msg("Outlook User <user@outlook.com>", "Microsoft Teams Termin", "Normaler Teams-Link ohne Konto-Aktion."),
            False,
            expected_brand_score=0,
        )
        self.assert_review(
            make_msg("Google <security@gmail.com>", "Sicherheitswarnung", "Login erforderlich"),
            True,
            expected_brand_score=40,
        )
        self.assert_review(
            make_msg("Microsoft <account@outlook.com>", "Sicherheitswarnung", "Konto gesperrt"),
            True,
            expected_brand_score=40,
        )

    def test_s_web_is_not_web_de_spoofing(self):
        msg = make_msg("Info <info@s-web.de>", "Sparkasse", "Hallo")
        body = fc.get_body(msg)
        self.assertEqual(fc.get_brand_spoofing_score(msg, body), 0)
        self.assertEqual(fc.check_bank_brand_mismatch(msg, body), 0)

    def test_safelinks_rewrite_target_is_compared_before_wrapper_domain(self):
        msg = make_html_msg(
            '<a href="https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Flogin">'
            "https://outlook.com/login</a>"
        )
        body = fc.get_body(msg)
        self.assertEqual(fc.get_link_text_href_mismatch_score(body), 35)
        self.assertTrue(fc.requires_claude_review(msg, body))

        safe_msg = make_html_msg(
            '<a href="https://safelinks.protection.outlook.com/?url=https%3A%2F%2Foutlook.com%2Flogin">'
            "https://outlook.com/login</a>"
        )
        safe_body = fc.get_body(safe_msg)
        self.assertEqual(fc.get_link_text_href_mismatch_score(safe_body), 0)

    def test_spamassassin_falls_back_when_spamc_safe_fallback_returns_zero_zero(self):
        spamc_zero_zero = fc.subprocess.CompletedProcess(
            ["/usr/bin/spamc", "-x", "-c"],
            70,
            stdout=b"0/0\n",
            stderr=b"spamd unavailable",
        )
        local_spamassassin_hit = fc.subprocess.CompletedProcess(
            ["/usr/bin/spamassassin", "-t"],
            0,
            stdout=b"X-Spam-Status: Yes, score=1003.7 required=5.0 tests=GTUBE\n",
            stderr=b"",
        )

        with patch.object(fc.subprocess, "run", side_effect=[spamc_zero_zero, local_spamassassin_hit]) as run:
            result = fc.check_spamassassin(b"Subject: spam\n\nGTUBE\n", make_spamassassin_config())

        self.assertEqual(result["score"], 1003.7)
        self.assertEqual(result["threshold"], 5.0)
        self.assertIn("-x", run.call_args_list[0].args[0])
        self.assertEqual(run.call_args_list[1].args[0], ["/usr/bin/spamassassin", "-t"])

    def test_spamassassin_parser_accepts_spamc_and_x_spam_status_formats(self):
        self.assertEqual(fc.parse_spamassassin_score("9.2/5.0"), (9.2, 5.0))
        self.assertEqual(
            fc.parse_spamassassin_score("X-Spam-Status: Yes, score=1003.7 required=5.0 tests=GTUBE"),
            (1003.7, 5.0),
        )


if __name__ == "__main__":
    unittest.main()
