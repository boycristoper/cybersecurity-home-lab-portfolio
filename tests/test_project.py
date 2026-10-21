"""Regression checks for file integrity, protocol checksums, and exercise conclusions."""

import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


generator = module("generate_reference")
analyzer = module("analyze_pcap")


def independently_sum_words(raw):
    """Independent one's-complement validation, without generator/analyzer helper."""
    if len(raw) % 2:
        raw += b"\x00"
    result = 0
    for index in range(0, len(raw), 2):
        result += int.from_bytes(raw[index:index + 2], "big")
    while result > 0xffff:
        result = (result & 0xffff) + (result >> 16)
    return result


class ReferenceTests(unittest.TestCase):
    def setUp(self):
        self.data, self.notes = generator.make_capture()

    def test_deterministic_and_expected_analysis(self):
        self.assertEqual(self.data, generator.make_capture()[0])
        rows = analyzer.parse_pcap(self.data)
        result = analyzer.summarize(rows, self.data, "synthetic", "exercise.pcap")
        self.assertEqual(result["frame_count"], 38)
        self.assertEqual(result["protocol_counts_exclusive"], {"ARP": 2, "ICMP": 4, "TCP": 32})
        self.assertEqual(result["initial_syn_count"], 6)
        self.assertEqual(result["distinct_syn_destination_ports"], [21, 22, 80, 445, 3306, 9999])
        self.assertEqual(result["checksum_failures"], [])
        self.assertEqual([r["frame"] for r in result["http_message_starts"]], [10, 12])
        resets = [r["destination_port"] for r in result["tcp_connection_observations"] if r["reset_frames"]]
        self.assertEqual(resets, [445, 9999])
        self.assertAlmostEqual(result["duration_seconds"], 4.01)

    def test_wire_format_and_checksums_independently(self):
        self.assertEqual(self.data[:4], bytes.fromhex("d4c3b2a1"))
        self.assertEqual(struct.unpack("<I", self.data[20:24])[0], 1)
        cursor, frames = 24, 0
        last_stamp = -1
        while cursor < len(self.data):
            sec, micros, included, original = struct.unpack("<IIII", self.data[cursor:cursor + 16])
            self.assertEqual(included, original)
            self.assertLess(micros, 1000000)
            self.assertGreaterEqual(sec * 1000000 + micros, last_stamp)
            last_stamp = sec * 1000000 + micros
            frame = self.data[cursor + 16:cursor + 16 + included]
            self.assertGreaterEqual(len(frame), 60)
            if frame[12:14] == b"\x08\x00":
                ip = frame[14:]
                ihl = (ip[0] & 15) * 4
                total = int.from_bytes(ip[2:4], "big")
                self.assertEqual(independently_sum_words(ip[:ihl]), 0xffff)
                transport = ip[ihl:total]
                if ip[9] == 6:
                    pseudo = ip[12:20] + b"\x00\x06" + len(transport).to_bytes(2, "big")
                    self.assertEqual(independently_sum_words(pseudo + transport), 0xffff)
                elif ip[9] == 1:
                    self.assertEqual(independently_sum_words(transport), 0xffff)
            cursor += 16 + included
            frames += 1
        self.assertEqual(cursor, len(self.data))
        self.assertEqual(frames, 38)

    def test_corruption_is_reported(self):
        data = bytearray(self.data)
        cursor = 24
        for _ in range(2):
            size = int.from_bytes(data[cursor + 8:cursor + 12], "little")
            cursor += 16 + size
        data[cursor + 16 + 14 + 8] ^= 1  # Corrupt frame 3 IPv4 TTL, keeping original checksum.
        records = analyzer.parse_pcap(bytes(data))
        self.assertFalse(records[2]["ipv4_checksum_ok"])

    def test_response_requires_correct_ack_and_ports(self):
        rows = analyzer.parse_pcap(self.data)
        result = analyzer.summarize(rows, self.data, "synthetic", "exercise.pcap")
        self.assertEqual(sum(bool(r["syn_ack_frames"]) for r in result["tcp_connection_observations"]), 4)
        for key in ("ack", "sport"):
            with self.subTest(changed=key):
                changed = [dict(row) for row in rows]
                changed[7][key] += 1  # Frame 8: HTTP SYN/ACK no longer matches frame 7.
                summary = analyzer.summarize(changed, self.data, "synthetic", "exercise.pcap")
                self.assertEqual(summary["tcp_connection_observations"][0]["syn_ack_frames"], [])
                self.assertEqual(summary["tcp_connection_observations"][0]["observation"], "No matching response observed")

    def test_truncated_and_unsupported_files_fail(self):
        for invalid in (b"\x0a\x0d\x0d\x0a" + b"\x00" * 24, self.data[:-1], self.data + b"\x01"):
            with self.subTest(length=len(invalid)):
                with self.assertRaises(analyzer.CaptureError):
                    analyzer.parse_pcap(invalid)
        unsupported = bytearray(self.data)
        unsupported[20:24] = (101).to_bytes(4, "little")
        with self.assertRaises(analyzer.CaptureError):
            analyzer.parse_pcap(bytes(unsupported))

    def test_big_endian_and_nanosecond_headers(self):
        # Repackage one generated frame using each supported PCAP header variant.
        sec, micros, included, original = struct.unpack("<IIII", self.data[24:40])
        frame = self.data[40:40 + included]
        for endian, magic, scale in ((">", 0xa1b2c3d4, 1000000),
                                      ("<", 0xa1b23c4d, 1000000000),
                                      (">", 0xa1b23c4d, 1000000000)):
            header = struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1)
            packed = header + struct.pack(endian + "IIII", sec, scale // 2, included, original) + frame
            rows = analyzer.parse_pcap(packed)
            self.assertEqual(rows[0]["protocol"], "ARP")
            self.assertEqual(rows[0]["timestamp"], sec + 0.5)


if __name__ == "__main__":
    unittest.main()
