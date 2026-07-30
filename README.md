# ARP Spoof Detector

A lightweight Python tool that detects ARP spoofing attacks by monitoring ARP packets on the network. It alerts when a MAC address is observed claiming multiple IP addresses, which is a key indicator of ARP spoofing.

## Requirements

- Python 3
- scapy

## Installation

```bash
git clone https://github.com/s4wbvnny/arpspoof-detector
cd arpspoof-detector
pip3 install -r requirements.txt
```

## Usage

Requires root privileges to sniff network packets:

```bash
sudo python3 spoofdetector.py
```

The tool will continuously monitor ARP traffic and display alerts when suspicious activity is detected. Press `Ctrl+C` to stop.

## How It Works

1. Captures all ARP packets on the network interface.
2. Maintains a mapping of MAC addresses to IP addresses.
3. Detects when a previously-seen MAC address starts claiming a different IP address.
4. Displays an alert with details of the suspected spoofing attempt.

## License

MIT
