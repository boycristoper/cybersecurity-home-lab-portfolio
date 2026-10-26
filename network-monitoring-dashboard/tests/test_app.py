"""Tes parser dan perhitungan dashboard tanpa akses jaringan atau paket tambahan."""

import importlib.util
from http.client import HTTPConnection
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest


APP_PATH = Path(__file__).resolve().parents[1] / "app.py"
SPEC = importlib.util.spec_from_file_location("network_dashboard_app", APP_PATH)
app = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(app)


def dev_line(name, rx_bytes, rx_packets, tx_bytes, tx_packets):
    return (
        f"{name}: {rx_bytes} {rx_packets} 0 0 0 0 0 0 "
        f"{tx_bytes} {tx_packets} 0 0 0 0 0 0\n"
    )


class NetworkDashboardTests(unittest.TestCase):
    def test_parse_interface_counters(self):
        contents = (
            "Inter-| Receive | Transmit\n"
            " face |bytes packets errs drop fifo frame compressed multicast"
            "|bytes packets errs drop fifo colls carrier compressed\n"
            + dev_line("  lo", 120, 2, 120, 2)
            + dev_line("eth0", 900, 9, 400, 4)
        )
        result = app.parse_net_dev(contents)
        self.assertEqual(result["lo"]["rx_bytes"], 120)
        self.assertEqual(result["eth0"]["tx_packets"], 4)
        self.assertEqual(result["eth0"]["rx_errors"], 0)
        self.assertEqual(app.choose_default_interface(result), "eth0")

    def test_rates_need_baseline_and_handle_counter_reset(self):
        old = {"rx_bytes": 100, "tx_bytes": 30, "rx_packets": 10, "tx_packets": 3}
        new = {"rx_bytes": 300, "tx_bytes": 110, "rx_packets": 14, "tx_packets": 7}
        self.assertIsNone(app.calculate_rates(new, None, None)["rx_bytes_per_sec"])
        self.assertEqual(app.calculate_rates(new, old, 2)["rx_bytes_per_sec"], 100)
        self.assertEqual(app.calculate_rates(new, old, 2)["tx_packets_per_sec"], 2)
        self.assertIsNone(app.calculate_rates(new, old, 0)["rx_bytes_per_sec"])
        reset = {**new, "rx_bytes": 1}
        self.assertTrue(all(value is None for value in app.calculate_rates(reset, old, 2).values()))

    def test_socket_rows_are_aggregated_without_endpoints(self):
        table = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
            "   0: 0100007F:1F90 00000000:0000 0A 0:0 00:0 0 0 0 0\n"
            "   1: 0100007F:1F90 0200007F:A010 01 0:0 00:0 0 0 0 0\n"
        )
        counts = app.parse_socket_table(table, "TCP4")
        self.assertEqual(counts[("TCP4", "LISTEN")], 1)
        self.assertEqual(counts[("TCP4", "ESTABLISHED")], 1)
        self.assertNotIn("0100007F", repr(counts))

    def test_monitor_samples_both_protocol_families(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as temp:
            root = Path(temp)
            (root / "dev").write_text(dev_line("lo", 100, 1, 100, 1), encoding="ascii")
            tcp_header = "sl local_address rem_address st\n"
            (root / "tcp").write_text(
                tcp_header + "0: A:B C:D 01\n" + "1: A:B C:D 0A\n", encoding="ascii"
            )
            (root / "tcp6").write_text(tcp_header + "0: A:B C:D 01\n", encoding="ascii")
            (root / "udp").write_text(tcp_header + "0: A:B C:D 07\n", encoding="ascii")
            # udp6 sengaja tidak dibuat: file IPv6 boleh tidak tersedia.
            monitor = app.Monitor(proc_root=root)
            first = monitor.sample(now=10)
            self.assertIsNone(first["interfaces"]["lo"]["rx_bytes_per_sec"])
            self.assertEqual(first["sockets"]["tcp_established"], 2)
            self.assertEqual(first["sockets"]["tcp_listening"], 1)
            self.assertEqual(first["sockets"]["udp_sockets"], 1)
            self.assertNotIn("local", first["connections"][0])
            (root / "dev").write_text(dev_line("lo", 300, 3, 220, 2), encoding="ascii")
            second = monitor.sample(now=12)
            self.assertEqual(second["interfaces"]["lo"]["rx_bytes_per_sec"], 100)
            self.assertEqual(second["interfaces"]["lo"]["tx_bytes_per_sec"], 60)
            self.assertEqual(len(second["history"]["lo"]), 2)

    def test_local_http_api_and_static_assets(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as temp:
            root = Path(temp)
            (root / "dev").write_text(dev_line("lo", 100, 1, 100, 1), encoding="ascii")
            monitor = app.Monitor(proc_root=root)
            monitor.sample(now=10)
            server = app.ThreadingHTTPServer(("127.0.0.1", 0), app.make_handler(monitor))
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                self.assertEqual(server.server_address[0], "127.0.0.1")
                connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
                for path, expected_type in (
                    ("/api/snapshot", "application/json"),
                    ("/", "text/html"),
                    ("/static/app.css", "text/css"),
                    ("/static/app.js", "text/javascript"),
                ):
                    connection.request("GET", path)
                    response = connection.getresponse()
                    body = response.read()
                    self.assertEqual(response.status, 200, path)
                    self.assertIn(expected_type, response.getheader("Content-Type"))
                    self.assertGreater(len(body), 0)
                    if path == "/api/snapshot":
                        payload = json.loads(body)
                        self.assertIn("lo", payload["interfaces"])
                        self.assertNotIn("remote", repr(payload["connections"]))
                connection.close()
                for path in ("/api/snapshot", "/"):
                    with self.subTest(path=path, host="external"):
                        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                        connection.request("GET", path, headers={"Host": f"attacker.test:{server.server_port}"})
                        response = connection.getresponse()
                        body = response.read()
                        self.assertEqual(response.status, 403)
                        self.assertNotIn(b"interfaces", body)
                        connection.close()
                for host_values in ((), (f"127.0.0.1:{server.server_port}", f"localhost:{server.server_port}")):
                    with self.subTest(host_values=host_values):
                        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                        connection.putrequest("GET", "/api/snapshot", skip_host=True)
                        for value in host_values:
                            connection.putheader("Host", value)
                        connection.endheaders()
                        response = connection.getresponse()
                        response.read()
                        self.assertEqual(response.status, 403)
                        connection.close()
                connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                connection.request("GET", "/api/snapshot", headers={"Host": f"localhost:{server.server_port}"})
                response = connection.getresponse()
                response.read()
                self.assertEqual(response.status, 200)
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
