# CODSOFT Task 1 - Network Packet Analyzer

## Objective

To develop a Python-based Network Packet Analyzer that captures and analyzes network packets in real time and provides useful information such as protocols, IP addresses, ports, packet details, and network statistics through a graphical interface.

## Project Description

This project is a Python-based educational network packet analysis tool developed using Scapy and Tkinter.

The application provides a graphical interface for capturing and analyzing network traffic. It can identify common protocols, display packet information, provide traffic statistics, and export captured packets for further analysis.

## Technologies Used

- Python 3
- Scapy
- Tkinter
- CSV
- PCAP
- Threading
- Queue

## Features

- Live packet capture
- Network interface selection
- BPF capture filters
- TCP packet analysis
- UDP packet analysis
- ICMP packet analysis
- ARP packet analysis
- DNS packet analysis
- IPv4 and IPv6 support
- Source and destination IP addresses
- Source and destination ports
- TCP flags
- DNS query extraction
- Packet details
- Packet search/filtering
- Packet statistics
- Basic traffic indicators
- CSV export
- PCAP export
- Graphical user interface
- Threaded packet capture for responsive GUI operation

## How It Works

1. The user selects a network interface.
2. An optional BPF filter can be entered.
3. The application starts packet capture using Scapy.
4. Captured packets are processed and analyzed.
5. Packet information is displayed in the GUI.
6. Statistics and basic traffic indicators are updated.
7. Captured packets can be exported as CSV or PCAP files.

## Main Protocols

### TCP
Displays TCP communication information including source/destination ports and TCP flags.

### UDP
Displays UDP traffic and port information.

### ICMP
Identifies ICMP packets commonly used for network diagnostics.

### ARP
Analyzes ARP packets and provides basic ARP-related traffic indicators.

### DNS
Extracts DNS query information when available.

### IPv4 / IPv6
Supports analysis of both IPv4 and IPv6 network traffic.

## Security / Forensics Relevance

The tool can be used for educational network forensics and packet analysis. It helps in understanding network protocols, identifying traffic patterns, inspecting packet information, and observing basic suspicious traffic indicators.

The project can support beginner-level learning in:

- Network Forensics
- Packet Analysis
- Network Security
- Incident Response
- Protocol Analysis
- Cybersecurity Monitoring

## Project Structure

```text
Network-Packet-Analyzer/
├── packet_analyzer.py
└── README.md
