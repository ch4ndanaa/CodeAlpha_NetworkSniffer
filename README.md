# CodeAlpha Network Sniffer

A Python-based network packet sniffer developed as part of the CodeAlpha Cyber Security Internship.

The tool captures live network traffic through the configured Wi-Fi network interface and analyzes IPv4 packets to display useful information such as source IP, destination IP, protocol, port numbers, packet payload size, and a limited hexadecimal payload preview.

## Features

- Live network packet capture
- IPv4 packet analysis
- TCP, UDP, and ICMP protocol detection
- Source and destination IP address identification
- Source and destination port identification
- Payload size analysis
- Limited hexadecimal payload preview
- Protocol statistics
- TCP/UDP/ICMP protocol filtering
- Capture duration tracking
- Live packet monitoring dashboard
- Colour-coded protocol display
- Compact live packet table
- Lightweight packet processing using Scapy
- Captured packets are not stored by Scapy after processing

## Technologies Used

- Python 3
- Scapy
- Rich
- Npcap
- Windows
- Visual Studio Code

## Project Structure

```text
CodeAlpha_NetworkSniffer/
│
├── network_sniffer.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Requirements

Before running the project, install:

1. Python 3
2. Npcap
3. Scapy
4. Rich

Npcap is required on Windows to allow Scapy to capture network packets.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/CodeAlpha_NetworkSniffer.git
cd CodeAlpha_NetworkSniffer
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

### 3. Activate the virtual environment

Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

## Usage

Run the network sniffer:

```bash
python network_sniffer.py
```

The program will begin capturing packets from the configured Wi-Fi interface.

Press:

```text
CTRL+C
```

to stop packet capture.

## Protocol Filtering

The program supports protocol-specific filtering.

### TCP

```bash
python network_sniffer.py --protocol TCP
```

### UDP

```bash
python network_sniffer.py --protocol UDP
```

### ICMP

```bash
python network_sniffer.py --protocol ICMP
```

## Example Output

```text
╭──────────────────────────────────────────────────────────────╮
│                 CODEALPHA NETWORK SNIFFER                    │
│                    LIVE PACKET MONITOR                       │
╰──────────────────────────────────────────────────────────────╯

Interface: Wi-Fi    Filter: ALL

              CAPTURE STATISTICS

┏━━━━━━━┳━━━━━━┳━━━━━━┳━━━━━━┳━━━━━━━━━━┳━━━━━━━┓
┃ TOTAL ┃ TCP  ┃ UDP  ┃ ICMP ┃ DURATION ┃ FILTER┃
┡━━━━━━━╇━━━━━━╇━━━━━━╇━━━━━━╇━━━━━━━━━━╇━━━━━━━┩
│   103 │   95 │    8 │    0 │ 00:13    │ ALL   │
└───────┴──────┴──────┴──────┴──────────┴───────┘

                         LIVE PACKETS

┏━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┓
┃ #  ┃ TIME   ┃ SOURCE             ┃ DESTINATION        ┃ PROTOCOL┃ PAYLOAD ┃
┡━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━┩
│ 1  │ 18:15  │ 192.168.1.10:53461 │ 203.0.113.10:443   │ TCP     │ 118 B   │
│ 2  │ 18:15  │ 203.0.113.10:443   │ 192.168.1.10:53461 │ TCP     │ 25 B    │
└────┴────────┴────────────────────┴────────────────────┴─────────┴─────────┘

Latest Payload Preview
17 03 03 00 71 fd 93 f3 ...

CTRL+C  Stop capture  |  ● CAPTURING
```

The example uses documentation IP addresses and does not represent actual captured traffic.

## How It Works

The program uses Scapy to capture packets from the configured Wi-Fi network interface.

For each captured IPv4 packet, the program:

1. Checks whether the packet contains an IP layer.
2. Identifies the transport protocol.
3. Extracts source and destination IP addresses.
4. Extracts source and destination ports for TCP and UDP packets.
5. Checks whether a raw payload is present.
6. Displays the payload size.
7. Displays only the first 32 bytes of the payload in hexadecimal format.
8. Updates protocol statistics.
9. Displays recent packets in the live monitoring dashboard.

## Payload Handling

The program intentionally displays only a small hexadecimal preview of packet payloads.

Encrypted network traffic may appear as binary or hexadecimal data. The tool does not attempt to decrypt HTTPS/TLS traffic or reconstruct application-level content.

This keeps the project focused on packet-level network analysis.

## Security and Privacy Considerations

Network packet capture can expose sensitive information.

This tool should only be used on networks and devices where the user has explicit permission to perform packet analysis.

Do not use the tool to intercept traffic belonging to other people or unauthorized systems.

Captured traffic should be handled responsibly and should not be published if it contains sensitive information.

## Limitations

- The current version focuses on IPv4 packets.
- The tool does not decrypt encrypted traffic.
- It does not reconstruct complete application-level conversations.
- Packet payload previews are limited to the first 32 bytes.
- The configured network interface is currently `Wi-Fi`.
- The live dashboard is designed for terminal environments.
- The tool is intended for educational and authorized security analysis.

## Learning Outcomes

Through this project, the following cybersecurity concepts are demonstrated:

- Network packet analysis
- TCP/IP fundamentals
- Protocol identification
- Port analysis
- Packet payload inspection
- Python network programming
- Scapy usage
- Basic network monitoring
- Terminal-based security tool development
- Security and privacy considerations

## Ethical Use

This project is intended for educational and authorized cybersecurity purposes only.

Always obtain appropriate permission before capturing or analyzing network traffic.

## Internship

Developed as part of the **CodeAlpha Cyber Security Internship**.

**Project:** Network Sniffer

**Developer:** Chandana T