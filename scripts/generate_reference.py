"""Build a deterministic, synthetic Ethernet PCAP. No network access is made."""

import hashlib
import ipaddress
import json
import struct
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIENT, TARGET = "192.168.77.10", "192.168.77.20"
CLIENT_MAC = bytes.fromhex("020000000010")
TARGET_MAC = bytes.fromhex("020000000020")
EPOCH = int(datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp())
REQUEST = b"GET / HTTP/1.1\r\nHost: 192.168.77.20\r\nUser-Agent: portfolio-synthetic/1.0\r\nConnection: close\r\n\r\n"
BODY = b"Synthetic home-lab training page. No real service was contacted.\n"
RESPONSE = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(BODY)).encode() + b"\r\nConnection: close\r\n\r\n" + BODY)


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def ipv4(src, dst, proto, payload, ident):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident,
                         0x4000, 64, proto, 0,
                         ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed)
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


def ethernet(src_mac, dst_mac, eth_type, payload):
    frame = dst_mac + src_mac + struct.pack("!H", eth_type) + payload
    return frame.ljust(60, b"\x00")  # No FCS; minimum Ethernet frame without FCS.


def make_capture():
    packets, notes = [], []

    def add(at_us, raw, description):
        packets.append((at_us, raw))
        notes.append({"frame": len(packets), "relative_us": at_us, "description": description})

    def arp(opcode, at_us):
        request = opcode == 1
        sm, dm = (CLIENT_MAC, TARGET_MAC) if request else (TARGET_MAC, CLIENT_MAC)
        sip, dip = (CLIENT, TARGET) if request else (TARGET, CLIENT)
        arp_payload = struct.pack("!HHBBH", 1, 0x0800, 6, 4, opcode)
        arp_payload += sm + ipaddress.ip_address(sip).packed
        arp_payload += (b"\x00" * 6 if request else dm) + ipaddress.ip_address(dip).packed
        add(at_us, ethernet(sm, b"\xff" * 6 if request else dm, 0x0806, arp_payload),
            "ARP request" if request else "ARP reply")

    def icmp(kind, seq, at_us):
        outbound = kind == 8
        src, dst = (CLIENT, TARGET) if outbound else (TARGET, CLIENT)
        sm, dm = (CLIENT_MAC, TARGET_MAC) if outbound else (TARGET_MAC, CLIENT_MAC)
        raw = struct.pack("!BBHHH", kind, 0, 0, 77, seq) + b"portfolio-lab"
        raw = raw[:2] + struct.pack("!H", checksum(raw)) + raw[4:]
        add(at_us, ethernet(sm, dm, 0x0800, ipv4(src, dst, 1, raw, len(packets) + 1)),
            "ICMP echo request" if outbound else "ICMP echo reply")

    def tcp(at_us, sport, dport, seq, ack, flags, payload=b"", outbound=True, note="TCP"):
        src, dst = (CLIENT, TARGET) if outbound else (TARGET, CLIENT)
        sm, dm = (CLIENT_MAC, TARGET_MAC) if outbound else (TARGET_MAC, CLIENT_MAC)
        header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 64240, 0, 0)
        segment = header + payload
        pseudo = ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed
        pseudo += struct.pack("!BBH", 0, 6, len(segment))
        segment = segment[:16] + struct.pack("!H", checksum(pseudo + segment)) + segment[18:]
        add(at_us, ethernet(sm, dm, 0x0800, ipv4(src, dst, 6, segment, len(packets) + 1)), note)

    arp(1, 0)
    arp(2, 20000)
    icmp(8, 1, 100000)
    icmp(0, 1, 110000)
    icmp(8, 2, 200000)
    icmp(0, 2, 210000)
    # A complete HTTP/1.1 conversation, each message contained in one segment.
    tcp(500000, 51000, 80, 1000, 0, 0x02, note="HTTP connection SYN")
    tcp(510000, 80, 51000, 7000, 1001, 0x12, outbound=False, note="HTTP connection SYN/ACK")
    tcp(520000, 51000, 80, 1001, 7001, 0x10, note="HTTP connection ACK")
    tcp(530000, 51000, 80, 1001, 7001, 0x18, REQUEST, note="Synthetic HTTP GET /")
    tcp(540000, 80, 51000, 7001, 1001 + len(REQUEST), 0x10, outbound=False)
    tcp(550000, 80, 51000, 7001, 1001 + len(REQUEST), 0x18, RESPONSE,
        outbound=False, note="Synthetic HTTP 200 OK")
    tcp(560000, 51000, 80, 1001 + len(REQUEST), 7001 + len(RESPONSE), 0x10)
    tcp(570000, 80, 51000, 7001 + len(RESPONSE), 1001 + len(REQUEST), 0x11,
        outbound=False, note="HTTP server FIN/ACK")
    tcp(580000, 51000, 80, 1001 + len(REQUEST), 7002 + len(RESPONSE), 0x11,
        note="HTTP client FIN/ACK")
    tcp(590000, 80, 51000, 7002 + len(RESPONSE), 1002 + len(REQUEST), 0x10, outbound=False)
    # Constructed connection probes: five distinct destination ports.
    for index, port in enumerate((21, 22, 445, 3306, 9999)):
        at, sport, seq, server_seq = 2000000 + index * 500000, 52000 + index, 2000 + index * 100, 9000 + index * 100
        tcp(at, sport, port, seq, 0, 0x02, note=f"Probe port {port}: SYN")
        if port in (445, 9999):
            tcp(at + 10000, port, sport, 0, seq + 1, 0x14, outbound=False,
                note=f"Probe port {port}: RST/ACK response")
            continue
        tcp(at + 10000, port, sport, server_seq, seq + 1, 0x12, outbound=False,
            note=f"Probe port {port}: SYN/ACK response")
        tcp(at + 20000, sport, port, seq + 1, server_seq + 1, 0x10)
        tcp(at + 30000, sport, port, seq + 1, server_seq + 1, 0x11)
        tcp(at + 40000, port, sport, server_seq + 1, seq + 2, 0x11, outbound=False)
        tcp(at + 50000, sport, port, seq + 2, server_seq + 2, 0x10)
    output = bytearray(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for at_us, raw in packets:
        seconds, micros = divmod(at_us, 1000000)
        output.extend(struct.pack("<IIII", EPOCH + seconds, micros, len(raw), len(raw)))
        output.extend(raw)
    return bytes(output), notes


def main():
    out = ROOT / "samples"
    out.mkdir(exist_ok=True)
    data, frames = make_capture()
    path = out / "synthetic-reference.pcap"
    path.write_bytes(data)
    manifest = {
        "provenance": "SYNTHETIC: generated locally; not a capture from running VMs",
        "generator": "scripts/generate_reference.py, scenario version 1",
        "scenario_time_note": "Fixed UTC scenario timestamps; not the author's execution time",
        "sha256": hashlib.sha256(data).hexdigest(),
        "file": path.name, "frame_count": len(frames), "frames": frames,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Generated {path.name}: {len(frames)} synthetic frames; SHA256 {manifest['sha256']}")


if __name__ == "__main__":
    main()
