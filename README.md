# Basic Network Sniffer

A lightweight Python network sniffer built with [Scapy](https://scapy.net/) that captures live traffic on a network interface and breaks down each packet layer by layer — Ethernet, IP, TCP/UDP/ICMP, and payload preview. Built as part of the Cyber Security Internship (Month 1) at Arch Technologies.

## Features

- Live packet capture on any network interface
- Parses Ethernet, IP, TCP, UDP, and ICMP headers
- Displays TCP flags, sequence/ack numbers, and payload previews
- Optional BPF filtering (e.g. `tcp port 80`)
- Optional logging of captured packet details to a file
- Configurable packet count (capture N packets or run indefinitely)

## Requirements

- Linux (tested on Kali Linux)
- Python 3
- [Scapy](https://scapy.net/) — preinstalled on Kali, otherwise install with:
  ```bash
  sudo apt install python3-scapy
  ```
- Root privileges (required for raw socket access)

## Usage

```bash
sudo python3 network_sniffer.py -i <interface> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i`, `--interface` | Network interface to sniff on (e.g. `eth0`, `wlan0`) | system default |
| `-c`, `--count` | Number of packets to capture (`0` = unlimited) | `0` |
| `-f`, `--filter` | BPF filter string (e.g. `"tcp port 80"`, `"udp"`) | none |
| `-o`, `--output` | File to log packet details to | none |

### Examples

Capture traffic indefinitely on `eth0`:
```bash
sudo python3 network_sniffer.py -i eth0
```

Capture 20 TCP packets on port 80 and log them to a file:
```bash
sudo python3 network_sniffer.py -i eth0 -f "tcp port 80" -c 20 -o capture_log.txt
```

Find your interface name first with:
```bash
ip a
```

Stop capture anytime with `Ctrl+C`.

## Sample Output

```
[2026-10-17 11:04:22] New packet captured
------------------------------------------------------------
Ethernet | Src MAC: 08:00:27:aa:bb:cc  Dst MAC: 52:54:00:12:35:02
IP       | Src: 192.168.1.15 -> Dst: 142.250.183.14 | TTL: 64 | Proto: 6 | Len: 60
TCP      | Sport: 51322 -> Dport: 443 | Seq: 123456789 | Ack: 0 | Flags: S
```

## How It Works

The script uses Scapy's `sniff()` function to open a live capture on the chosen interface. Each captured packet is passed to a handler that inspects it layer by layer:

1. **Ethernet layer** — source/destination MAC addresses
2. **IP layer** — source/destination IPs, TTL, protocol number, packet length
3. **Transport layer** — TCP (ports, seq/ack, flags), UDP (ports, length), or ICMP (type, code)
4. **Payload** — a preview of up to 64 bytes, decoded as text where possible

## Disclaimer

This tool is intended for educational use and for analyzing traffic on networks you own or have explicit permission to monitor. Capturing traffic on networks without authorization may be illegal in your jurisdiction.

## Author

**Muhammad Taimoor Afzal**
