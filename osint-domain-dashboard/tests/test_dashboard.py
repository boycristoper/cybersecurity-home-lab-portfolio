import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.error import HTTPError


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build_dashboard as dashboard  # noqa: E402


class DomainInputTests(unittest.TestCase):
    def test_accepts_public_domain_and_normalizes_case(self):
        self.assertEqual(dashboard.validate_domain("Example.COM"), "example.com")

    def test_rejects_urls_ips_local_names_and_malformed_names(self):
        bad_inputs = (
            "https://example.com",
            "127.0.0.1",
            "user@example.com",
            "site.local",
            "localhost",
            "name.test",
            "foo..com",
            "example.com/path",
            "example.com:443",
            "example.com..",
            "-bad.com",
        )
        for value in bad_inputs:
            with self.subTest(value=value), self.assertRaises(ValueError):
                dashboard.validate_domain(value)


class SourceHandlingTests(unittest.TestCase):
    def test_http_429_halts_following_queries(self):
        calls = []

        def fetcher(domain, record_type):
            calls.append(record_type)
            return dashboard.LookupResult(record_type, "https://dns.google/resolve", "rate_limited", "HTTP 429")

        results = dashboard.collect_dns("example.com", fetcher)
        self.assertEqual(calls, ["A"])
        self.assertEqual([result.state for result in results], ["rate_limited"] + ["skipped"] * 4)

    def test_google_http_error_becomes_visible_state(self):
        error = HTTPError("https://dns.google/resolve", 429, "Too Many Requests", None, None)
        with patch.object(dashboard, "urlopen", side_effect=error):
            result = dashboard.fetch_dns("example.com", "A")
        self.assertEqual(result.state, "rate_limited")
        self.assertIn("429", result.message)

    def test_http_success_with_dns_error_is_not_reported_as_data(self):
        body = io.BytesIO(b'{"Status":3,"Question":[{"name":"bad.example.","type":1}]}')
        with patch.object(dashboard, "urlopen", return_value=body):
            result = dashboard.fetch_dns("example.com", "A")
        self.assertEqual(result.state, "dns_error")
        self.assertIn("NXDOMAIN", result.message)
        self.assertEqual(result.answers, ())

    def test_malformed_answer_record_type_becomes_visible_error(self):
        for record_type in ([], {}, "A", None, True):
            with self.subTest(record_type=record_type):
                raw = json.dumps({"Status": 0, "Answer": [{"type": record_type, "data": "192.0.2.1"}]}).encode("utf-8")
                with patch.object(dashboard, "urlopen", return_value=io.BytesIO(raw)):
                    result = dashboard.fetch_dns("example.com", "A")
                self.assertEqual(result.state, "invalid_response")
                self.assertEqual(result.answers, ())

    def test_deeply_nested_json_becomes_visible_error(self):
        raw = b"[" * 5000 + b"]" * 5000
        with patch.object(dashboard, "urlopen", return_value=io.BytesIO(raw)):
            result = dashboard.fetch_dns("example.com", "A")
        self.assertEqual(result.state, "invalid_response")
        self.assertEqual(result.answers, ())


class HtmlSafetyTests(unittest.TestCase):
    def test_summary_distinguishes_answers_empty_results_and_errors(self):
        results = (
            dashboard.LookupResult("A", "source-a", "ok", "ada", ({"name": "example.com.", "type": "A", "ttl": "60", "data": "192.0.2.1"},)),
            dashboard.LookupResult("AAAA", "source-aaaa", "empty", "kosong"),
            dashboard.LookupResult("MX", "source-mx", "dns_error", "gagal"),
        )
        page = dashboard.render_html("example.com", results, "2026-10-23 00:00:00")
        self.assertIn("<strong>1</strong><span>Tipe berjawab</span>", page)
        self.assertIn("<strong>1</strong><span>Tipe tanpa jawaban</span>", page)
        self.assertIn("<strong>1</strong><span>Tipe gagal/dilewati</span>", page)

    def test_untrusted_dns_text_is_escaped_in_html(self):
        malicious = '<script>alert("x")</script>'
        result = dashboard.LookupResult(
            "TXT",
            dashboard.query_url("example.com", "TXT"),
            "ok",
            "one record",
            ({"name": "example.com.", "type": "TXT", "ttl": "300", "data": malicious},),
        )
        page = dashboard.render_html("example.com", (result,), "2026-10-23 00:00:00")
        self.assertNotIn(malicious, page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("dns.google/resolve?name=example.com&amp;type=TXT", page)

    def test_demo_is_conspicuously_labeled_and_has_no_source_query(self):
        page = dashboard.render_html("contoh.test", dashboard.demo_results(), "2026-10-23 00:00:00", demo=True)
        self.assertIn("DEMO OFFLINE — DATA BUATAN", page)
        self.assertNotIn("href='https://dns.google/resolve", page)


if __name__ == "__main__":
    unittest.main()
