#!/usr/bin/env python3
import argparse
import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, Raw, conf


def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def describe_packet(packet, log_file=None):
    """Parse and print the key fields of a captured packet."""
    lines = []
    lines.append(f"\n[{timestamp()}] New packet captured")
    lines.append("-" * 60)

    # --- Layer 2: Ethernet ---
    if Ether in packet:
        eth = packet[Ether]
        lines.append(f"Ethernet | Src MAC: {eth.src}  Dst MAC: {eth.dst}")

    # --- Layer 3: IP ---
    if IP in packet:
        ip = packet[IP]
        lines.append(
            f"IP       | Src: {ip.src} -> Dst: {ip.dst} | "
            f"TTL: {ip.ttl} | Proto: {ip.proto} | Len: {ip.len}"
        )

        # --- Layer 4: Transport ---
        if TCP in packet:
            tcp = packet[TCP]
            flags = tcp.sprintf("%TCP.flags%")
            lines.append(
                f"TCP      | Sport: {tcp.sport} -> Dport: {tcp.dport} | "
                f"Seq: {tcp.seq} | Ack: {tcp.ack} | Flags: {flags}"
            )
        elif UDP in packet:
            udp = packet[UDP]
            lines.append(
                f"UDP      | Sport: {udp.sport} -> Dport: {udp.dport} | "
                f"Len: {udp.len}"
            )
        elif ICMP in packet:
            icmp = packet[ICMP]
            lines.append(f"ICMP     | Type: {icmp.type} | Code: {icmp.code}")

        # --- Payload preview ---
        if Raw in packet:
            payload = bytes(packet[Raw].load)
            preview = payload[:64]
            try:
                decoded = preview.decode("utf-8", errors="replace")
            except Exception:
                decoded = repr(preview)
            lines.append(f"Payload  | ({len(payload)} bytes) {decoded!r}")

    else:
        # Non-IP traffic (ARP, etc.)
        lines.append(f"Summary  | {packet.summary()}")

    output = "\n".join(lines)
    print(output)

    if log_file:
        with open(log_file, "a") as f:
            f.write(output + "\n")


def main():
    parser = argparse.ArgumentParser(description="Basic Python network sniffer")
    parser.add_argument("-i", "--interface", default=conf.iface,
                         help="Network interface to sniff on (e.g. eth0, wlan0)")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Number of packets to capture (0 = infinite, Ctrl+C to stop)")
    parser.add_argument("-f", "--filter", default="",
                         help="BPF filter string, e.g. 'tcp port 80' or 'udp'")
    parser.add_argument("-o", "--output", default=None,
                         help="Optional file to log packet details to")
    args = parser.parse_args()

    print(f"[*] Starting sniffer on interface: {args.interface}")
    print(f"[*] Filter: {args.filter if args.filter else 'none'}")
    print(f"[*] Packet count: {'unlimited' if args.count == 0 else args.count}")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter if args.filter else None,
            prn=lambda pkt: describe_packet(pkt, args.output),
            count=args.count,
            store=False,
        )
    except PermissionError:
        print("[!] Permission denied. Try running with sudo.")
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped by user.")


if __name__ == "__main__":
    main()
