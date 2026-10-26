"""Pengujian data dummy, aturan lokal, CLI, dan batas HTTP loopback."""

from contextlib import redirect_stderr, redirect_stdout
from http.client import HTTPConnection
import io
import json
from pathlib import Path
import sys
import tempfile
from threading import Thread
import unicodedata
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))
import app
import checker


def checks_by_id(result):
    return {item["id"]: item for item in result["checks"]}


class PasswordRuleTests(unittest.TestCase):
    def test_length_boundary_counts_nfc_codepoints(self):
        for size, passed in ((14, False), (15, True)):
            example = "kabut lentera x"[:size]
            self.assertEqual(len(example), size)
            result = checker.check_password(example)
            self.assertEqual(checks_by_id(result)["length"]["passed"], passed)
        max_example = ("kabut lentera sungai biru " * 11)[:256]
        self.assertEqual(checker.check_password(max_example)["length"], 256)
        with self.assertRaises(ValueError):
            checker.check_password(max_example + "x")

    def test_invalid_empty_whitespace_and_type(self):
        for example in ("", "   \t\n", None, 12, "\ud800"):
            with self.subTest(kind=type(example).__name__):
                with self.assertRaises(ValueError):
                    checker.check_password(example)

    def test_unicode_nfc_and_spaces_are_supported(self):
        decomposed = "cafe\u0301 biru 🌿 bulan"
        composed = unicodedata.normalize("NFC", decomposed)
        self.assertEqual(checker.check_password(decomposed), checker.check_password(composed))
        padded = "  kabut lentera  "
        self.assertEqual(checker.check_password(padded)["length"], len(padded))

    def test_long_lowercase_passphrase_needs_no_composition(self):
        result = checker.check_password("kabut sepeda lentera sungai")
        self.assertEqual(result["status"], "limited_pass")
        self.assertTrue(all(item["passed"] for item in result["checks"]))

    def test_blocklist_is_casefolded_full_input_match(self):
        result = checker.check_password("PASSWORD")
        self.assertEqual(result["status"], "needs_improvement")
        self.assertFalse(checks_by_id(result)["blocklist"]["passed"])
        result = checker.check_password("pastel password lentera bulan")
        self.assertTrue(checks_by_id(result)["blocklist"]["passed"])
        self.assertEqual(result["status"], "limited_pass")

    def test_full_repetition_is_detected_but_varied_input_is_not(self):
        for example in ("a" * 20, "abc" * 6, "password" * 3, "Ab" * 12):
            with self.subTest(length=len(example)):
                result = checker.check_password(example)
                self.assertEqual(result["status"], "needs_improvement")
                self.assertFalse(checks_by_id(result)["repetition"]["passed"])
        result = checker.check_password("kabut lentera kabut sungai")
        self.assertTrue(checks_by_id(result)["repetition"]["passed"])

    def test_sequence_warns_without_fabricating_crack_time(self):
        for example in ("abcd kabut lentera bulan", "kabut 9876 lentera",
                        "kabut qwerty lentera"):
            result = checker.check_password(example)
            self.assertEqual(result["status"], "review")
            self.assertFalse(checks_by_id(result)["sequence"]["passed"])
            self.assertNotIn("score", result)
            self.assertNotIn("entropy", result)
            self.assertNotIn("crack_time", result)

    def test_result_contract_does_not_echo_secret(self):
        example = "DUMMY<unique-marker>42_lentera"
        result = checker.check_password(example)
        self.assertNotIn(example, json.dumps(result, ensure_ascii=False))
        self.assertNotIn("unique-marker", json.dumps(result))
        self.assertEqual(set(result), {"status", "label", "length", "min_length",
                                     "max_length", "checks", "reasons", "suggestions",
                                     "notice", "blocklist_size", "normalization"})
        self.assertEqual(set(checks_by_id(result)),
                         {"length", "blocklist", "repetition", "sequence"})
        self.assertEqual(result["normalization"], "NFC")
        self.assertEqual(result["blocklist_size"], len(checker.BLOCKLIST))


class LocalHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        root = Path(cls.temp.name)
        (root / "index.html").write_text("<main>Local fixture</main>", encoding="utf-8")
        (root / "app.css").write_text("body { color: black; }", encoding="utf-8")
        (root / "app.js").write_text("const localFixture = true;", encoding="utf-8")
        cls.server = app.LocalServer(("127.0.0.1", 0), app.make_handler(root))
        cls.port = cls.server.server_port
        cls.origin = f"http://127.0.0.1:{cls.port}"
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            data = response.read()
            return response.status, dict(response.getheaders()), data
        finally:
            connection.close()

    def post(self, value, extra_headers=None, path="/api/check"):
        headers = {"Origin": self.origin, "Content-Type": "application/json"}
        if extra_headers:
            headers.update(extra_headers)
        return self.request("POST", path, json.dumps(value).encode("utf-8"), headers)

    def test_valid_post_and_public_info(self):
        example = "kabut sepeda lentera sungai"
        status, headers, body = self.post({"password": example})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), checker.check_password(example))
        self.assertNotIn(example.encode(), body)
        status, _, body = self.request("GET", "/api/info")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), checker.policy_info())

    def test_rejects_missing_external_null_and_mismatched_origin(self):
        body = json.dumps({"password": "DUMMY-origin-lentera-bulan"})
        for origin in (None, "https://example.test", "null", "http://localhost:1"):
            headers = {"Content-Type": "application/json"}
            if origin is not None:
                headers["Origin"] = origin
            status, _, data = self.request("POST", "/api/check", body, headers)
            self.assertEqual(status, 403)
            self.assertNotIn(b"DUMMY-origin", data)

    def test_rejects_host_header_rebinding(self):
        status, _, _ = self.request("GET", "/api/info", headers={"Host": "evil.test"})
        self.assertEqual(status, 403)
        status, _, _ = self.post({"password": "DUMMY-localhost-lentera"},
                                 {"Host": f"localhost:{self.port}",
                                  "Origin": f"http://localhost:{self.port}"})
        self.assertEqual(status, 200)

    def test_rejects_content_type_and_oversized_body(self):
        status, _, _ = self.post({"password": "DUMMY-lentera-bulan"},
                                 {"Content-Type": "text/plain"})
        self.assertEqual(status, 415)
        headers = {"Origin": self.origin, "Content-Type": "application/json",
                   "Content-Length": str(app.MAX_BODY_BYTES + 1)}
        status, _, _ = self.request("POST", "/api/check", b"{}", headers)
        self.assertEqual(status, 413)

    def test_rejects_malformed_schema_unicode_and_overlength(self):
        for value in ({}, {"password": []}, {"password": "x", "extra": 1},
                      [], {"password": "x" * 257}, {"password": "\ud800"}):
            status, _, _ = self.post(value)
            self.assertEqual(status, 400)
        status, _, body = self.request("POST", "/api/check", b"{bad json DUMMY-marker",
                                      {"Origin": self.origin, "Content-Type": "application/json"})
        self.assertEqual(status, 400)
        self.assertNotIn(b"DUMMY-marker", body)
        status, _, _ = self.request("POST", "/api/check", b"\xff",
                                    {"Origin": self.origin, "Content-Type": "application/json"})
        self.assertEqual(status, 400)

    def test_whitelist_no_query_and_unsupported_method(self):
        for path in ("/checker.py", "/app.py", "/../checker.py", "/missing"):
            self.assertEqual(self.request("GET", path)[0], 404)
        status, _, body = self.request("GET", "/?password=DUMMY-url-marker")
        self.assertEqual(status, 400)
        self.assertNotIn(b"DUMMY-url-marker", body)
        self.assertEqual(self.request("PUT", "/api/check", b"{}")[0], 405)
        self.assertEqual(self.post({"password": "DUMMY-lentera-bulan"}, path="/missing")[0], 404)

    def test_rejects_deep_json_duplicate_keys_and_oversized_integer(self):
        headers = {"Origin": self.origin, "Content-Type": "application/json"}
        for body in (b"[" * 1500 + b"0" + b"]" * 1500,
                     b'{"password":"DUMMY-first","password":"DUMMY-second"}',
                     b'{"password":' + b"1" * 5000 + b"}"):
            self.assertLess(len(body), app.MAX_BODY_BYTES)
            status, _, output = self.request("POST", "/api/check", body, headers)
            self.assertEqual(status, 400)
            self.assertNotIn(b"DUMMY-first", output)
            self.assertNotIn(b"DUMMY-second", output)

    def test_static_assets_security_headers_and_no_cors(self):
        for path, content_type in (("/", "text/html"), ("/static/app.css", "text/css"),
                                    ("/static/app.js", "text/javascript"),
                                    ("/api/info", "application/json")):
            status, headers, body = self.request("GET", path)
            self.assertEqual(status, 200)
            self.assertTrue(body)
            self.assertIn(content_type, headers["Content-Type"])
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(headers["Referrer-Policy"], "no-referrer")
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
            self.assertIn("form-action 'none'", headers["Content-Security-Policy"])
            self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_no_request_logging_for_valid_or_invalid_secret(self):
        stream = io.StringIO()
        example = "DUMMY-log-marker-lentera"
        with redirect_stderr(stream):
            self.post({"password": example})
            self.request("GET", "/?password=" + example)
        self.assertEqual(stream.getvalue(), "")


class CLITests(unittest.TestCase):
    def test_cli_uses_getpass_and_does_not_echo(self):
        example = "DUMMY-cli-marker-lentera"
        output = io.StringIO()
        with mock.patch.object(app.getpass, "getpass", return_value=example) as getpass_mock:
            with redirect_stdout(output):
                code = app.run_cli()
        self.assertEqual(code, 0)
        getpass_mock.assert_called_once()
        self.assertNotIn(example, output.getvalue())
        self.assertIn("Status:", output.getvalue())

    def test_cli_stops_if_hidden_input_not_supported(self):
        output, error = io.StringIO(), io.StringIO()
        with mock.patch.object(app.getpass, "getpass", side_effect=app.getpass.GetPassWarning):
            with redirect_stdout(output), redirect_stderr(error):
                code = app.run_cli()
        self.assertEqual(code, 1)
        self.assertIn("tidak mendukung input tersembunyi", error.getvalue())


if __name__ == "__main__":
    unittest.main()
