"""Tes aturan dengan email buatan, tanpa jaringan atau email sungguhan."""

from pathlib import Path
import sys
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from analyze_email import MAX_EMAIL_BYTES, analyze_file  # noqa: E402


class AnalyzeEmailTests(unittest.TestCase):
    def test_synthetic_risky_sample_explains_four_indicators(self):
        result = analyze_file(PROJECT / "samples" / "contoh-perlu-ditinjau.eml")
        self.assertEqual(result["status"], "perlu ditinjau")
        reasons = " ".join(result["indicators"])
        for fragment in ("Reply-To", "bahasa mendesak", ".exe", "Teks tautan"):
            self.assertIn(fragment, reasons)

    def test_synthetic_neutral_sample_does_not_claim_safe(self):
        result = analyze_file(PROJECT / "samples" / "contoh-tanpa-indikator.eml")
        self.assertEqual(result["status"], "tidak ada indikator dari aturan terbatas")
        self.assertEqual(result["indicators"], [])

    def test_different_reply_to_subdomain_is_only_an_indicator(self):
        raw = (b"From: a@contoh.test\nReply-To: b@balas.contoh.test\n"
               b"Content-Type: text/plain\n\nPesan biasa.\n")
        with tempfile.TemporaryDirectory(dir=PROJECT / "tests") as folder:
            path = Path(folder) / "sample.eml"
            path.write_bytes(raw)
            result = analyze_file(path)
        self.assertEqual(result["status"], "perlu ditinjau")
        self.assertIn("Reply-To", " ".join(result["indicators"]))

    def test_script_never_follows_link(self):
        raw = (b"From: a@contoh.test\nContent-Type: text/html\n\n"
               b'<a href="http://127.0.0.1:65534/private">https://contoh.test</a>')
        with tempfile.TemporaryDirectory(dir=PROJECT / "tests") as folder:
            path = Path(folder) / "sample.eml"
            path.write_bytes(raw)
            result = analyze_file(path)
        self.assertEqual(result["status"], "perlu ditinjau")
        self.assertIn("127.0.0.1", " ".join(result["indicators"]))

    def test_oversized_file_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=PROJECT / "tests") as folder:
            path = Path(folder) / "large.eml"
            path.write_bytes(b"A" * (MAX_EMAIL_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "batas"):
                analyze_file(path)


if __name__ == "__main__":
    unittest.main()
