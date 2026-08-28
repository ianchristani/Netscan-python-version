# Netscan-python

A Python TCP/UDP port scanner, built on Scapy (https://scapy.net/), that allows you to manually assemble scan packets (custom TCP flags, fragmentation, wait times, and interval between sends) through an interactive menu in the terminal.

> ⚠️ **Legal Notice:** This tool manipulates network packets at a low level and may be interpreted as malicious activity. Use **only** on networks and systems for which you have explicit authorization to perform tests. The author is not responsible for misuse.

## Features

- **Customizable TCP Scan**

- Free choice of flags (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR) — including classic scans like NULL, SYN, and custom combinations.

- Packet fragmentation support.

- Definition of a single port, port list (`80,443,8080`) or ranges (`1-1024`).

- Control of timeout per packet, interval between transmissions, and number of packets per port.

- Automatic classification of results (`open`, `closed`, `filtered`) based on received TCP/ICMP responses.

- **UDP Scan with specific payloads**

- Sends real payloads (DNS, NTP, SNMP, DHCP, TFTP, RPC, NetBIOS, ISAKMP, RIP, SSDP, mDNS, SIP) to increase the chance of a response on commonly filtered ports.

- If there is no response with a payload, automatically tries an empty packet.

- Scans a predefined set of ~20 most relevant UDP ports.

- Classifies the result as `open`, `closed`, `open|filtered`, or `filtered`.

- **Interactive menu in Portuguese**, guiding the user through all the steps of the scan setup.

## Requirements

- Python 3.7+
- [Scapy](https://scapy.net/) 2.7.0
- Administrator/root privileges (required for creating and sending raw packages)
- Linux/Unix system recommended (using raw sockets on Windows may require additional configuration, such as Npcap)

## Installation

```bash
# Clone the repository
git clone https://github.com/ianchristani/Netscan-python-version

# (Optional) create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

```

## How to use

Since Scapy needs to create raw sockets, run the script with elevated privileges:

```bash
sudo python3 main.py
or
./main.py
```

You will see the menu Initial:

```
========== Home Menu - Scan Type ==========
Connect (very invasive) and Discover (use ICMP) scan types are not supported.

Choose the protocol type:

[1] TCP
[2] UDP
[0] Exit


### TCP Scan

When choosing TCP, you will be prompted for:

1. Target IP/domain (or network range, e.g., `192.168.0.0/24`)
2. Response timeout per packet (seconds)
3. Interval between transmissions (seconds)
4. Number of packets per port
5. Port(s) to scan (single, comma-separated list, or `start-end` range; default: `1-1024`)
6. Whether packets should be fragmented (`True`/`False`)
7. TCP flag(s) to use (e.g., `S` for SYN scan, empty for NULL scan)

Finally, the result is displayed port by port and also as a Python dictionary.

### UDP Scan

When choosing UDP, you are only asked for:

1. Target IP/domain
2. Response timeout (seconds)
3. Interval between sends (seconds)

The scan is automatically executed against the most common UDP port set, first attempting a service-specific payload and, if there is no response, an empty packet.

## Known limitations

- *Connect* and *Discover* (ICMP) type scans are not supported.

- The `closed` port classification is only reliable in pure SYN scans.

- In UDP, the absence of a response is reported as `open|filtered`, the expected behavior of this protocol.
