"""Local fixture tests. They are development checks, not Boy's Kali results."""

from __future__ import annotations

import contextlib
import http.client
import io
import json
import socket
import ssl
import threading
import unittest
from unittest.mock import patch

import app
import scanner
from demo_lab import DemoLab


def by_id(checks):
    return {check["id"]: check for check in checks}


class FakeSocket:
    def __init__(self, response=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n", error=None):
        self.response = response
        self.error = error
        self.sent = b""
        self.closed = False
        self.recv_calls = 0

    def settimeout(self, value):
        self.timeout = value

    def connect(self, target):
        self.target = target
        if self.error:
            raise self.error

    def sendall(self, data):
        self.sent += data

    def recv(self, size):
        self.recv_calls += 1
        chunk = self.response[:size]
        self.response = self.response[size:]
        return chunk

    def close(self):
        self.closed = True


class RuleTests(unittest.TestCase):
    def test_target_accepts_only_literal_loopback_or_rfc1918(self):
        for value in ("127.0.0.1", "127.1.2.3", "10.2.3.4", "172.16.1.2", "172.31.255.254", "192.168.1.2"):
            self.assertEqual(scanner.validate_target(value), value)
        for value in ("example.com", "127.0.0.1/8", "127.1", "2130706433", "127.0.0.01", "0.0.0.0", "169.254.169.254", "100.64.0.1", "8.8.8.8", "172.15.1.1", "172.32.0.1", "::1", " 127.0.0.1", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                scanner.validate_target(value)

    def test_request_rejects_coercion_and_unbounded_ports(self):
        self.assertEqual(scanner.validate_request(443, "https"), (443, "https"))
        for port in (True, False, 0, -1, 65536, "80", 80.0, None):
            with self.subTest(port=port), self.assertRaises(ValueError):
                scanner.validate_request(port, "http")
        for scheme in (None, "HTTP", "file", "ftp", []):
            with self.subTest(scheme=scheme), self.assertRaises(ValueError):
                scanner.validate_request(80, scheme)

    def test_header_additions_reduce_reviews_without_a_safe_verdict(self):
        before = by_id(scanner.analyse_headers({"set-cookie": ["session=SECRET; Path=/"]}, "http", 200))
        after = by_id(scanner.analyse_headers({
            "content-security-policy": ["default-src 'none'; frame-ancestors 'none'"],
            "x-frame-options": ["DENY"], "x-content-type-options": ["nosniff"],
            "referrer-policy": ["no-referrer"],
            "set-cookie": ["session=SECRET; Path=/; HttpOnly; SameSite=Lax"],
        }, "http", 200))
        for key in ("csp", "frame", "nosniff", "referrer"):
            self.assertEqual(before[key]["status"], "review")
            self.assertEqual(after[key]["status"], "observed")
        self.assertEqual(after["cookies"]["status"], "review")
        self.assertEqual(after["hsts"]["status"], "not_checked")
        self.assertNotIn("SECRET", json.dumps(after))

    def test_csp_presence_is_not_policy_effectiveness(self):
        checks = by_id(scanner.analyse_headers({"content-security-policy": ["default-src * 'unsafe-inline'"]}, "http", 200))
        self.assertEqual(checks["csp"]["status"], "observed")
        self.assertIn("belum", checks["csp"]["evidence"])
        self.assertEqual(checks["frame"]["status"], "review")

    def test_duplicate_or_invalid_security_values_need_review(self):
        checks = by_id(scanner.analyse_headers({"x-content-type-options": ["nosniff", "anything"], "x-frame-options": ["ALLOW-FROM example.test"], "referrer-policy": ["unsafe-url"]}, "https", 200))
        for key in ("nosniff", "frame", "referrer"):
            self.assertEqual(checks[key]["status"], "review")
        self.assertEqual(checks["hsts"]["status"], "info")

    def test_hsts_is_not_evaluated_on_http_and_zero_is_not_positive(self):
        for scheme, value, expected in (("http", "max-age=31536000", "not_checked"), ("https", "max-age=0", "info"), ("https", "max-age=001", "observed"), ("https", "max-age=abc", "info")):
            checks = by_id(scanner.analyse_headers({"strict-transport-security": [value]}, scheme, 200))
            self.assertEqual(checks["hsts"]["status"], expected)

    def test_cookies_are_aggregated_and_values_and_names_never_echo(self):
        headers = {"set-cookie": ["SECRET_NAME=SECRET_VALUE; Secure; HttpOnly; SameSite=Strict", "ANOTHER_SECRET=OTHER_VALUE; HttpOnly; SameSite=None"]}
        row = by_id(scanner.analyse_headers(headers, "https", 200))["cookies"]
        encoded = json.dumps(row)
        for secret in ("SECRET_NAME", "SECRET_VALUE", "ANOTHER_SECRET", "OTHER_VALUE"):
            self.assertNotIn(secret, encoded)
        self.assertIn("tanpa Secure: 1", row["evidence"])
        self.assertEqual(row["status"], "review")
        headers["set-cookie"] = ["demo=public; Secure; HttpOnly; SameSite=Lax"]
        self.assertEqual(by_id(scanner.analyse_headers(headers, "https", 200))["cookies"]["status"], "observed")
        self.assertEqual(by_id(scanner.analyse_headers({}, "https", 200))["cookies"]["status"], "not_checked")

    def test_redirect_and_banner_are_information_only_and_redacted(self):
        checks = by_id(scanner.analyse_headers({"location": ["https://external.test/?token=SECRET"], "server": ["SECRET_SERVER_VERSION"]}, "http", 302))
        self.assertIn("tidak diikuti", checks["http"]["evidence"])
        self.assertEqual(checks["banner"]["status"], "info")
        self.assertNotIn("SECRET", json.dumps(checks))

    def test_parser_preserves_set_cookie_lines_without_joining_them(self):
        status, headers = scanner.parse_header_block(b"HTTP/1.1 200 OK\r\nSet-Cookie: a=x; Secure\r\nSet-Cookie: b=y; HttpOnly\r\n\r\n")
        self.assertEqual(status, 200)
        self.assertEqual(len(headers["set-cookie"]), 2)

    def test_parser_rejects_oversize_obsfold_controls_and_invalid_headers(self):
        cases = [b"HTTP/1.1 200 OK\r\n a: b\r\n\r\n", b"HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n", b"HTTP/1.1 200 OK\r\nX: x\x00y\r\n\r\n", b"SSH-2.0-test\r\n\r\n", b"HTTP/1.1 100 Continue\r\n\r\n", b"HTTP/1.1 200 OK\r\n" + b"X: x\r\n" * 101 + b"\r\n", b"HTTP/1.1 200 OK\r\nX: " + b"x" * scanner.MAX_HEADER_BYTES + b"\r\n\r\n"]
        for block in cases:
            with self.subTest(size=len(block)), self.assertRaises(ValueError):
                scanner.parse_header_block(block)


class ScannerNetworkTests(unittest.TestCase):
    def test_one_fixed_get_with_no_auth_cookie_proxy_or_redirect_following(self):
        fake = FakeSocket(b"HTTP/1.1 302 Found\r\nLocation: http://8.8.8.8/SECRET\r\nSet-Cookie: name=SECRET\r\n\r\nSECRET_BODY")
        with patch.object(scanner.socket, "socket", return_value=fake) as sockets, patch.dict("os.environ", {"HTTP_PROXY": "http://8.8.8.8:9999"}):
            result = scanner.scan_service("127.0.0.1", 8771)
        sockets.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        self.assertEqual(fake.target, ("127.0.0.1", 8771))
        self.assertTrue(fake.sent.startswith(b"GET / HTTP/1.1\r\n"))
        self.assertNotIn(b"Authorization:", fake.sent)
        self.assertNotIn(b"Cookie:", fake.sent)
        self.assertNotIn(b"8.8.8.8", fake.sent)
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertEqual(result["transport"]["http_status"], 302)
        self.assertTrue(fake.closed)
        self.assertEqual(set(result["summary"]), {"review", "observed", "info", "not_checked"})
        self.assertEqual(sum(result["summary"].values()), 10)

    def test_refused_and_timeout_connections_are_distinct_and_not_clean(self):
        for error, expected in ((ConnectionRefusedError(), "closed"), (TimeoutError(), "timeout"), (OSError(), "error")):
            fake = FakeSocket(error=error)
            with patch.object(scanner.socket, "socket", return_value=fake):
                result = scanner.scan_service("127.0.0.1", 8771)
            self.assertEqual(result["transport"]["tcp"], expected)
            self.assertEqual(result["summary"]["not_checked"], 9)
            self.assertEqual(fake.sent, b"")
            self.assertTrue(fake.closed)

    def test_tls_failure_never_sends_http_or_falls_back(self):
        fake = FakeSocket()
        class Context:
            keylog_filename = "old-keylog-path"
            def wrap_socket(self, raw, server_hostname):
                self.name = server_hostname
                raise ssl.SSLCertVerificationError("SECRET CERT ERROR")
        context = Context()
        with patch.object(scanner.socket, "socket", return_value=fake) as sockets, patch.object(scanner.ssl, "create_default_context", return_value=context):
            result = scanner.scan_service("127.0.0.1", 8771, "https")
        self.assertIsNone(context.keylog_filename)
        self.assertEqual(context.name, "127.0.0.1")
        self.assertEqual(sockets.call_count, 1)
        self.assertEqual(fake.sent, b"")
        self.assertEqual(result["transport"]["tls"], "failed")
        self.assertEqual(result["summary"]["not_checked"], 8)
        self.assertNotIn("SECRET", json.dumps(result))

    def test_verified_tls_uses_selected_host_and_assesses_hsts(self):
        raw = FakeSocket()
        wrapped = FakeSocket(b"HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=3600\r\n\r\n")
        class Context:
            def wrap_socket(self, connection, server_hostname):
                self.name = server_hostname
                return wrapped
        context = Context()
        with patch.object(scanner.socket, "socket", return_value=raw), patch.object(scanner.ssl, "create_default_context", return_value=context):
            result = scanner.scan_service("192.168.1.2", 443, "https")
        self.assertEqual(context.name, "192.168.1.2")
        self.assertEqual(result["transport"]["tls"], "valid")
        self.assertEqual(by_id(result["checks"])["hsts"]["status"], "observed")
        self.assertTrue(wrapped.closed)

    def test_remote_http_is_review_and_failed_http_skips_header_claims(self):
        fake = FakeSocket(b"SSH-2.0-SECRET\r\n\r\n")
        with patch.object(scanner.socket, "socket", return_value=fake):
            result = scanner.scan_service("10.0.0.2", 22)
        checks = by_id(result["checks"])
        self.assertEqual(checks["transport"]["status"], "review")
        self.assertEqual(checks["csp"]["status"], "not_checked")
        self.assertIsNone(result["transport"]["http_status"])
        self.assertNotIn("SECRET", json.dumps(result))

    def test_header_read_is_bounded_and_does_not_need_body(self):
        fake = FakeSocket(b"HTTP/1.1 200 OK\r\nX: " + b"x" * (scanner.MAX_HEADER_BYTES + 100))
        with self.assertRaises(scanner.ResponseLimitError):
            scanner.read_response_headers(fake, scanner.time.monotonic() + 1)
        self.assertLessEqual(fake.recv_calls, 9)
        fake = FakeSocket(b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 100000)
        status, _ = scanner.read_response_headers(fake, scanner.time.monotonic() + 1)
        self.assertEqual(status, 200)
        self.assertEqual(fake.recv_calls, 1)
        self.assertGreater(len(fake.response), 90000)


class LocalHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output = io.StringIO()
        cls.server = app.make_server(0, demo_enabled=True)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        final_headers = {"Host": f"127.0.0.1:{self.port}", **(headers or {})}
        with contextlib.redirect_stderr(self.output), contextlib.redirect_stdout(self.output):
            connection.request(method, path, body=body, headers=final_headers)
            response = connection.getresponse()
            status, data, response_headers = response.status, response.read(), dict(response.getheaders())
        connection.close()
        return status, data, response_headers

    def post(self, body, **headers):
        return self.request("POST", "/api/scan", body, {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{self.port}", **headers})

    def test_info_and_static_security_headers(self):
        status, data, headers = self.request("GET", "/api/info")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["target"], "127.0.0.1")
        self.assertTrue(json.loads(data)["demo_enabled"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        for path in ("/", "/static/app.css", "/static/app.js"):
            with self.subTest(path=path):
                self.assertEqual(self.request("GET", path)[0], 200)

    def test_no_path_traversal_or_query_routes(self):
        for path in ("/scanner.py", "/../app.py", "/static/../app.py", "/static/%2e%2e/app.py", "/api/info?target=8.8.8.8", "/?x=1"):
            with self.subTest(path=path):
                self.assertEqual(self.request("GET", path)[0], 404)

    def test_cross_site_and_rebinding_hosts_rejected_before_scan(self):
        body = '{"port":8771,"scheme":"http"}'
        with patch.object(app, "scan_service") as scan:
            for origin in ("null", "https://attacker.test", f"http://localhost:{self.port}", ""):
                self.assertEqual(self.post(body, Origin=origin)[0], 403)
            self.assertEqual(self.post(body, Host=f"attacker.test:{self.port}")[0], 403)
            self.assertEqual(self.request("POST", "/api/scan", body, {"Content-Type": "application/json"})[0], 403)
            self.assertEqual(self.request("GET", "/api/info", headers={"Host": f"attacker.test:{self.port}"})[0], 403)
        scan.assert_not_called()

    def test_invalid_json_schema_limits_and_no_error_reflection(self):
        invalid = [b"", b"not-json SECRET", b"\xff", b"[]", b"null", b'{"port":true,"scheme":"http"}', b'{"port":0,"scheme":"http"}', b'{"port":8771,"scheme":"ftp"}', b'{"port":8771,"scheme":"http","target":"SECRET"}', b'{"port":8771,"port":8772,"scheme":"http"}', b'{"port":NaN,"scheme":"http"}', b"[" * 500 + b"]" * 500]
        with patch.object(app, "scan_service") as scan:
            for body in invalid:
                with self.subTest(body=body[:40]):
                    status, data, _ = self.post(body)
                    self.assertEqual(status, 400)
                    self.assertNotIn(b"SECRET", data)
            self.assertEqual(self.post(b"x" * 1025)[0], 413)
            self.assertEqual(self.post(b"{}", **{"Content-Type": "text/plain"})[0], 415)
            self.assertEqual(self.post(b"{}", **{"Transfer-Encoding": "chunked"})[0], 400)
        scan.assert_not_called()

    def test_single_scan_lock_fixed_target_and_failure_redaction(self):
        body = '{"port":8771,"scheme":"http"}'
        self.server.scan_lock.acquire()
        try:
            self.assertEqual(self.post(body)[0], 429)
        finally:
            self.server.scan_lock.release()
        with patch.object(app, "scan_service", return_value={"ok": True}) as scan:
            self.assertEqual(self.post(body)[0], 200)
            scan.assert_called_once_with("127.0.0.1", 8771, "http")
        with patch.object(app, "scan_service", side_effect=RuntimeError("SECRET")):
            status, data, _ = self.post(body)
            self.assertEqual(status, 500)
            self.assertNotIn(b"SECRET", data)
        self.assertFalse(self.server.scan_lock.locked())
        self.assertEqual(self.output.getvalue(), "")

    def test_real_loopback_demos_compare_without_cookie_disclosure(self):
        with DemoLab((0, 0)) as demo:
            reports = []
            for server in demo.servers:
                status, data, _ = self.post(json.dumps({"port": server.server_port, "scheme": "http"}))
                self.assertEqual(status, 200)
                report = json.loads(data)
                self.assertEqual(report["transport"]["tcp"], "open")
                self.assertEqual(report["transport"]["http_status"], 200)
                self.assertNotIn("lab_demo", data.decode())
                self.assertNotIn("DEMO_COOKIE_NOT_A_SECRET", data.decode())
                reports.append(report)
            self.assertEqual(reports[0]["summary"]["review"], 5)
            self.assertEqual(reports[1]["summary"]["review"], 1)
            self.assertEqual(by_id(reports[1]["checks"])["cookies"]["status"], "review")


if __name__ == "__main__":
    unittest.main()
