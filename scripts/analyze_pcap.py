"""Small, offline classic-PCAP reader for this exercise, not a Wireshark replacement."""

import argparse
import csv
import hashlib
import ipaddress
import json
import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


class CaptureError(ValueError):
    pass


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def parse_pcap(data):
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1000000), b"\xa1\xb2\xc3\xd4": (">", 1000000),
               b"\x4d\x3c\xb2\xa1": ("<", 1000000000), b"\xa1\xb2\x3c\x4d": (">", 1000000000)}
    if len(data) < 24 or data[:4] not in formats:
        raise CaptureError("Expected classic PCAP; convert PCAPNG using editcap -F pcap input.pcapng output.pcap")
    endian, scale = formats[data[:4]]
    major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", data[4:24])
    if (major, minor) != (2, 4) or linktype != 1:
        raise CaptureError("Only PCAP v2.4 with Ethernet link type 1 is supported")
    records, offset = [], 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise CaptureError("Truncated PCAP record header")
        seconds, fraction, captured, original = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        if fraction >= scale or captured > original or captured > snaplen or offset + captured > len(data):
            raise CaptureError("Invalid timestamp, length, or truncated PCAP record")
        packet = data[offset:offset + captured]
        offset += captured
        if len(packet) < 14:
            raise CaptureError("Truncated Ethernet header")
        row = {"frame": len(records) + 1, "timestamp": seconds + fraction / scale,
               "length": captured, "protocol": "Other Ethernet"}
        ethertype = struct.unpack("!H", packet[12:14])[0]
        raw = packet[14:]
        if ethertype == 0x0806:
            if len(raw) < 28:
                raise CaptureError("Truncated ARP packet")
            htype, ptype, hlen, plen, opcode = struct.unpack("!HHBBH", raw[:8])
            if (htype, ptype, hlen, plen) == (1, 0x0800, 6, 4):
                row.update(protocol="ARP", arp_opcode=opcode,
                           src=str(ipaddress.ip_address(raw[14:18])), dst=str(ipaddress.ip_address(raw[24:28])))
        elif ethertype == 0x0800:
            if len(raw) < 20 or raw[0] >> 4 != 4:
                raise CaptureError("Invalid IPv4 header")
            ihl, total = (raw[0] & 15) * 4, struct.unpack("!H", raw[2:4])[0]
            if ihl < 20 or total < ihl or len(raw) < total:
                raise CaptureError("Invalid or truncated IPv4 packet")
            src_raw, dst_raw = raw[12:16], raw[16:20]
            row.update(protocol="IPv4 other", src=str(ipaddress.ip_address(src_raw)),
                       dst=str(ipaddress.ip_address(dst_raw)), ipv4_checksum_ok=checksum(raw[:ihl]) == 0)
            segment = raw[ihl:total]
            fragments = struct.unpack("!H", raw[6:8])[0] & 0x3fff
            if fragments:
                row["protocol"] = "IPv4 fragment (not reassembled)"
            elif raw[9] == 1:
                if len(segment) < 8:
                    raise CaptureError("Truncated ICMP packet")
                row.update(protocol="ICMP", icmp_type=segment[0],
                           transport_checksum_ok=checksum(segment) == 0)
            elif raw[9] == 6:
                if len(segment) < 20:
                    raise CaptureError("Truncated TCP header")
                sport, dport, seq, ack = struct.unpack("!HHII", segment[:12])
                tcp_header_length = (segment[12] >> 4) * 4
                if tcp_header_length < 20 or tcp_header_length > len(segment):
                    raise CaptureError("Invalid TCP data offset")
                flags = segment[13]
                pseudo = src_raw + dst_raw + struct.pack("!BBH", 0, 6, len(segment))
                row.update(protocol="TCP", sport=sport, dport=dport, seq=seq, ack=ack, flags=flags,
                           payload_length=len(segment) - tcp_header_length,
                           transport_checksum_ok=checksum(pseudo + segment) == 0)
                payload = segment[tcp_header_length:]
                # Deliberately not stream reassembly; only complete message starts in a segment.
                if payload.startswith((b"GET ", b"POST ", b"HEAD ", b"HTTP/1.")):
                    row["http_start_line"] = payload.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        records.append(row)
    return records


def summarize(records, data, label, file_name):
    syns = [r for r in records if r.get("protocol") == "TCP" and r["flags"] & 2 and not r["flags"] & 16]
    observations = []
    for syn in syns:
        responses = [r for r in records if r["frame"] > syn["frame"] and r.get("protocol") == "TCP"
                     and r.get("src") == syn["dst"] and r.get("dst") == syn["src"]
                     and r["sport"] == syn["dport"] and r["dport"] == syn["sport"]
                     and r["ack"] == (syn["seq"] + 1) % (2 ** 32) and r["flags"] & 16]
        synack = [r["frame"] for r in responses if (r["flags"] & 0x12) == 0x12]
        reset = [r["frame"] for r in responses if r["flags"] & 4]
        observations.append({"source": syn["src"], "destination": syn["dst"], "source_port": syn["sport"],
                             "destination_port": syn["dport"], "syn_frame": syn["frame"],
                             "syn_ack_frames": synack, "reset_frames": reset,
                             "observation": "SYN/ACK observed" if synack else "RST/ACK observed" if reset else "No matching response observed"})
    stamps = [r["timestamp"] for r in records]
    utc = lambda value: datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    return {
        "file": file_name, "provenance_label": label, "sha256": hashlib.sha256(data).hexdigest(),
        "frame_count": len(records), "duration_seconds": round(max(stamps) - min(stamps), 6) if stamps else 0,
        "first_packet_utc": utc(min(stamps)) if stamps else None,
        "last_packet_utc": utc(max(stamps)) if stamps else None,
        "protocol_counts_exclusive": dict(sorted(Counter(r["protocol"] for r in records).items())),
        "ip_addresses": sorted({r[key] for r in records for key in ("src", "dst") if key in r}),
        "initial_syn_count": len(syns),
        "distinct_syn_destination_ports": sorted({r["dport"] for r in syns}),
        "tcp_connection_observations": observations,
        "http_message_starts": [{"frame": r["frame"], "source": r["src"], "destination": r["dst"],
                                 "start_line": r["http_start_line"]} for r in records if "http_start_line" in r],
        "checksum_failures": [r["frame"] for r in records if r.get("ipv4_checksum_ok") is False or r.get("transport_checksum_ok") is False],
        "limitations": ["Provenance label is supplied by the caller, not independently verified.",
                        "Classic PCAP/Ethernet/IPv4 only; no VLAN, IPv6, UDP/DNS decoding or stream/fragment reassembly.",
                        "SYN entries count packets, not deduplicated attempts; reused tuples can be ambiguous.",
                        "Port numbers do not identify applications; SYN/ACK is an observed response, not proof of a service version.",
                        "A scan-like pattern is not proof of an attacker. Check context and authorization.",
                        "Checksum offload can affect checksums in real captures; errors alone do not establish malicious traffic."]
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--label", default="User-supplied capture; provenance not verified")
    parser.add_argument("--json", type=Path)
    parser.add_argument("--csv", type=Path)
    args = parser.parse_args()
    try:
        data = args.capture.read_bytes()
        records = parse_pcap(data)
        summary = summarize(records, data, args.label, args.capture.name)
    except (CaptureError, OSError) as error:
        parser.exit(2, f"Error: {error}\n")
    rendered = json.dumps(summary, indent=2) + "\n"
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    if args.csv:
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        keys = ["frame", "relative_seconds", "protocol", "src", "dst", "sport", "dport", "flags",
                "seq", "ack", "arp_opcode", "icmp_type", "payload_length", "http_start_line",
                "ipv4_checksum_ok", "transport_checksum_ok", "length"]
        first = records[0]["timestamp"] if records else 0
        with args.csv.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=keys, extrasaction="ignore")
            writer.writeheader()
            for record in records:
                writer.writerow({**record, "relative_seconds": round(record["timestamp"] - first, 6)})
    if args.json:
        print(f"Analyzed {len(records)} frames offline.")


if __name__ == "__main__":
    main()
