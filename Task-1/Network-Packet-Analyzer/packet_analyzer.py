#!/usr/bin/env python3

"""
=============================================================
 PYTHON NETWORK PACKET ANALYZER - VERSION 2
=============================================================

Educational Network Forensics / Packet Analysis Tool

Features:
    - Live packet capture
    - Interface selection
    - BPF capture filters
    - TCP / UDP / ICMP / ARP / DNS detection
    - IPv4 / IPv6
    - Packet statistics
    - Search
    - Packet details
    - Basic traffic indicators
    - CSV export
    - PCAP export

AUTHORIZED USE ONLY
Use this application only on systems/networks you own,
administer, or have explicit permission to monitor.
=============================================================
"""

import csv
import os
import queue
import threading
from collections import defaultdict
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

try:
    from scapy.all import (
        sniff,
        get_if_list,
        wrpcap,
        Ether,
        IP,
        IPv6,
        TCP,
        UDP,
        ICMP,
        ARP,
        Raw,
        DNS,
        DNSQR,
    )
except ImportError:
    raise SystemExit(
        "\nScapy is not installed.\n\n"
        "Install it with:\n"
        "sudo apt install python3-scapy\n"
    )


class PacketAnalyzer:

    def __init__(self, root):

        self.root = root

        self.root.title(
            "Network Packet Analyzer - DFIR Lab"
        )

        self.root.geometry(
            "1450x900"
        )

        self.root.minsize(
            1150,
            700
        )

        # -----------------------------------------------------
        # Capture state
        # -----------------------------------------------------

        self.capturing = False

        self.capture_thread = None

        self.packet_queue = queue.Queue()

        # -----------------------------------------------------
        # Packet storage
        # -----------------------------------------------------

        self.packets = []

        self.packet_rows = []

        self.packet_counter = 0

        # -----------------------------------------------------
        # Statistics
        # -----------------------------------------------------

        self.stats = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "ARP": 0,
            "DNS": 0,
            "OTHER": 0,
            "IPv4": 0,
            "IPv6": 0,
        }

        # -----------------------------------------------------
        # Security indicators
        # -----------------------------------------------------

        self.syn_count = 0

        self.port_activity = defaultdict(int)

        self.arp_ips = {}

        self.alerts = []

        # -----------------------------------------------------
        # GUI
        # -----------------------------------------------------

        self.setup_style()

        self.build_gui()

        self.refresh_interfaces()

        self.root.after(
            100,
            self.process_packet_queue
        )

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close_application
        )

    # =========================================================
    # STYLE
    # =========================================================

    def setup_style(self):

        style = ttk.Style()

        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "Title.TLabel",
            font=("Arial", 20, "bold"),
        )

        style.configure(
            "Header.TLabel",
            font=("Arial", 11, "bold"),
        )

        style.configure(
            "Card.TLabel",
            font=("Arial", 12, "bold"),
            padding=8,
        )

        style.configure(
            "Treeview",
            rowheight=28,
            font=("Arial", 9),
        )

        style.configure(
            "Treeview.Heading",
            font=("Arial", 9, "bold"),
        )

    # =========================================================
    # MAIN GUI
    # =========================================================

    def build_gui(self):

        # -----------------------------------------------------
        # Title
        # -----------------------------------------------------

        title = ttk.Label(
            self.root,
            text="NETWORK PACKET ANALYZER",
            style="Title.TLabel",
        )

        title.pack(
            pady=(12, 2)
        )

        subtitle = ttk.Label(
            self.root,
            text="Python + Scapy | Network Forensics Lab",
        )

        subtitle.pack(
            pady=(0, 10)
        )

        # -----------------------------------------------------
        # Statistics dashboard
        # -----------------------------------------------------

        stats_frame = ttk.Frame(
            self.root
        )

        stats_frame.pack(
            fill="x",
            padx=15,
            pady=5
        )

        self.total_card = self.create_stat_card(
            stats_frame,
            "PACKETS",
            "0"
        )

        self.tcp_card = self.create_stat_card(
            stats_frame,
            "TCP",
            "0"
        )

        self.udp_card = self.create_stat_card(
            stats_frame,
            "UDP",
            "0"
        )

        self.dns_card = self.create_stat_card(
            stats_frame,
            "DNS",
            "0"
        )

        self.arp_card = self.create_stat_card(
            stats_frame,
            "ARP",
            "0"
        )

        self.icmp_card = self.create_stat_card(
            stats_frame,
            "ICMP",
            "0"
        )

        self.syn_card = self.create_stat_card(
            stats_frame,
            "SYN",
            "0"
        )

        for i in range(7):
            stats_frame.columnconfigure(
                i,
                weight=1
            )

        # -----------------------------------------------------
        # Interface controls
        # -----------------------------------------------------

        control_frame = ttk.LabelFrame(
            self.root,
            text="Capture Configuration"
        )

        control_frame.pack(
            fill="x",
            padx=15,
            pady=8
        )

        ttk.Label(
            control_frame,
            text="Interface:"
        ).grid(
            row=0,
            column=0,
            padx=8,
            pady=8
        )

        self.interface_var = tk.StringVar()

        self.interface_combo = ttk.Combobox(
            control_frame,
            textvariable=self.interface_var,
            state="readonly",
            width=20,
        )

        self.interface_combo.grid(
            row=0,
            column=1,
            padx=5
        )

        ttk.Button(
            control_frame,
            text="Refresh",
            command=self.refresh_interfaces,
        ).grid(
            row=0,
            column=2,
            padx=5
        )

        ttk.Label(
            control_frame,
            text="BPF Filter:"
        ).grid(
            row=0,
            column=3,
            padx=(20, 5)
        )

        self.filter_var = tk.StringVar()

        self.filter_entry = ttk.Entry(
            control_frame,
            textvariable=self.filter_var,
            width=35,
        )

        self.filter_entry.grid(
            row=0,
            column=4,
            padx=5
        )

        ttk.Label(
            control_frame,
            text="e.g. tcp | udp | icmp | arp | port 53"
        ).grid(
            row=0,
            column=5,
            padx=5
        )

        # -----------------------------------------------------
        # Buttons
        # -----------------------------------------------------

        button_frame = ttk.Frame(
            self.root
        )

        button_frame.pack(
            fill="x",
            padx=15,
            pady=5
        )

        self.start_button = ttk.Button(
            button_frame,
            text="▶ START CAPTURE",
            command=self.start_capture,
        )

        self.start_button.pack(
            side="left",
            padx=4
        )

        self.stop_button = ttk.Button(
            button_frame,
            text="■ STOP",
            command=self.stop_capture,
            state="disabled",
        )

        self.stop_button.pack(
            side="left",
            padx=4
        )

        ttk.Button(
            button_frame,
            text="CLEAR",
            command=self.clear_packets,
        ).pack(
            side="left",
            padx=4
        )

        ttk.Button(
            button_frame,
            text="SAVE CSV",
            command=self.save_csv,
        ).pack(
            side="left",
            padx=4
        )

        ttk.Button(
            button_frame,
            text="SAVE PCAP",
            command=self.save_pcap,
        ).pack(
            side="left",
            padx=4
        )

        # -----------------------------------------------------
        # Search
        # -----------------------------------------------------

        ttk.Label(
            button_frame,
            text="Search:"
        ).pack(
            side="left",
            padx=(30, 5)
        )

        self.search_var = tk.StringVar()

        self.search_var.trace_add(
            "write",
            lambda *_: self.refresh_table()
        )

        ttk.Entry(
            button_frame,
            textvariable=self.search_var,
            width=30,
        ).pack(
            side="left"
        )

        # -----------------------------------------------------
        # Main packet table
        # -----------------------------------------------------

        table_frame = ttk.LabelFrame(
            self.root,
            text="Live Packet Capture"
        )

        table_frame.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=8
        )

        columns = (
            "no",
            "time",
            "source",
            "destination",
            "protocol",
            "sport",
            "dport",
            "length",
            "info",
        )

        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
        )

        headings = {
            "no": "No.",
            "time": "Time",
            "source": "Source",
            "destination": "Destination",
            "protocol": "Protocol",
            "sport": "Src Port",
            "dport": "Dst Port",
            "length": "Length",
            "info": "Information",
        }

        widths = {
            "no": 55,
            "time": 100,
            "source": 180,
            "destination": 180,
            "protocol": 90,
            "sport": 80,
            "dport": 80,
            "length": 70,
            "info": 360,
        }

        for column in columns:

            self.tree.heading(
                column,
                text=headings[column]
            )

            self.tree.column(
                column,
                width=widths[column],
                anchor="w"
            )

        self.tree.tag_configure(
            "TCP",
            foreground="#1f5f99"
        )

        self.tree.tag_configure(
            "UDP",
            foreground="#6a3d9a"
        )

        self.tree.tag_configure(
            "DNS",
            foreground="#008060"
        )

        self.tree.tag_configure(
            "ARP",
            foreground="#996600"
        )

        self.tree.tag_configure(
            "ICMP",
            foreground="#8b0000"
        )

        yscroll = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.tree.yview
        )

        xscroll = ttk.Scrollbar(
            table_frame,
            orient="horizontal",
            command=self.tree.xview
        )

        self.tree.configure(
            yscrollcommand=yscroll.set,
            xscrollcommand=xscroll.set
        )

        self.tree.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        yscroll.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        xscroll.grid(
            row=1,
            column=0,
            sticky="ew"
        )

        table_frame.rowconfigure(
            0,
            weight=1
        )

        table_frame.columnconfigure(
            0,
            weight=1
        )

        self.tree.bind(
            "<<TreeviewSelect>>",
            self.show_details
        )

        # -----------------------------------------------------
        # Bottom section
        # -----------------------------------------------------

        bottom = ttk.Frame(
            self.root
        )

        bottom.pack(
            fill="both",
            padx=15,
            pady=(0, 10)
        )

        bottom.columnconfigure(
            0,
            weight=3
        )

        bottom.columnconfigure(
            1,
            weight=1
        )

        # -----------------------------------------------------
        # Packet details
        # -----------------------------------------------------

        details_frame = ttk.LabelFrame(
            bottom,
            text="Packet Details"
        )

        details_frame.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=(0, 8)
        )

        self.details_text = tk.Text(
            details_frame,
            height=12,
            wrap="word",
            font=("Courier New", 9),
        )

        details_scroll = ttk.Scrollbar(
            details_frame,
            orient="vertical",
            command=self.details_text.yview
        )

        self.details_text.configure(
            yscrollcommand=details_scroll.set
        )

        self.details_text.pack(
            side="left",
            fill="both",
            expand=True
        )

        details_scroll.pack(
            side="right",
            fill="y"
        )

        # -----------------------------------------------------
        # Alerts
        # -----------------------------------------------------

        alert_frame = ttk.LabelFrame(
            bottom,
            text="Traffic Indicators"
        )

        alert_frame.grid(
            row=0,
            column=1,
            sticky="nsew"
        )

        self.alert_text = tk.Text(
            alert_frame,
            height=12,
            wrap="word",
            font=("Arial", 9),
        )

        self.alert_text.pack(
            fill="both",
            expand=True
        )

        # -----------------------------------------------------
        # Status
        # -----------------------------------------------------

        self.status_var = tk.StringVar(
            value="Ready - Select an interface and start capture"
        )

        ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief="sunken",
            anchor="w"
        ).pack(
            fill="x",
            side="bottom"
        )

    # =========================================================
    # STAT CARD
    # =========================================================

    def create_stat_card(
        self,
        parent,
        title,
        value
    ):

        frame = ttk.LabelFrame(
            parent,
            text=title
        )

        frame.grid(
            row=0,
            column=len(
                parent.winfo_children()
            ),
            sticky="ew",
            padx=3
        )

        label = ttk.Label(
            frame,
            text=value,
            style="Card.TLabel",
            anchor="center"
        )

        label.pack(
            fill="both",
            expand=True
        )

        return label

    # =========================================================
    # INTERFACES
    # =========================================================

    def refresh_interfaces(self):

        try:

            interfaces = get_if_list()

            self.interface_combo["values"] = interfaces

            if interfaces:

                current = self.interface_var.get()

                if current not in interfaces:

                    preferred = None

                    for iface in interfaces:

                        if iface not in (
                            "lo",
                            "Loopback"
                        ):
                            preferred = iface
                            break

                    self.interface_var.set(
                        preferred or interfaces[0]
                    )

            self.status_var.set(
                f"{len(interfaces)} interface(s) detected"
            )

        except Exception as exc:

            messagebox.showerror(
                "Interface Error",
                str(exc)
            )

    # =========================================================
    # START
    # =========================================================

    def start_capture(self):

        if self.capturing:
            return

        interface = self.interface_var.get().strip()

        if not interface:

            messagebox.showwarning(
                "Interface Required",
                "Select a network interface first."
            )

            return

        capture_filter = (
            self.filter_var.get().strip()
        )

        self.capturing = True

        self.start_button.configure(
            state="disabled"
        )

        self.stop_button.configure(
            state="normal"
        )

        self.status_var.set(
            f"CAPTURING on {interface}"
        )

        self.capture_thread = threading.Thread(
            target=self.capture_worker,
            args=(
                interface,
                capture_filter
            ),
            daemon=True
        )

        self.capture_thread.start()

    # =========================================================
    # CAPTURE WORKER
    # =========================================================

    def capture_worker(
        self,
        interface,
        capture_filter
    ):

        try:

            sniff(
                iface=interface,
                filter=(
                    capture_filter
                    if capture_filter
                    else None
                ),
                prn=self.packet_callback,
                store=False,
                stop_filter=lambda pkt:
                    not self.capturing
            )

        except Exception as exc:

            self.packet_queue.put(
                (
                    "error",
                    str(exc)
                )
            )

        finally:

            self.packet_queue.put(
                (
                    "status",
                    "Capture stopped"
                )
            )

    # =========================================================
    # CALLBACK
    # =========================================================

    def packet_callback(
        self,
        packet
    ):

        if not self.capturing:
            return

        self.packet_queue.put(
            (
                "packet",
                packet
            )
        )

    # =========================================================
    # QUEUE
    # =========================================================

    def process_packet_queue(self):

        try:

            while True:

                event_type, data = (
                    self.packet_queue.get_nowait()
                )

                if event_type == "packet":

                    self.handle_packet(data)

                elif event_type == "error":

                    self.capturing = False

                    self.start_button.configure(
                        state="normal"
                    )

                    self.stop_button.configure(
                        state="disabled"
                    )

                    messagebox.showerror(
                        "Capture Error",
                        data
                    )

                elif event_type == "status":

                    self.status_var.set(
                        data
                    )

        except queue.Empty:
            pass

        self.root.after(
            100,
            self.process_packet_queue
        )

    # =========================================================
    # PACKET HANDLING
    # =========================================================

    def handle_packet(
        self,
        packet
    ):

        self.packet_counter += 1

        self.packets.append(
            packet
        )

        row = self.parse_packet(
            packet,
            self.packet_counter
        )

        self.packet_rows.append(
            row
        )

        self.update_statistics(
            packet,
            row
        )

        self.insert_table_row(
            row
        )

        self.update_dashboard()

        self.update_indicators(
            packet,
            row
        )

    # =========================================================
    # PARSER
    # =========================================================

    def parse_packet(
        self,
        packet,
        number
    ):

        timestamp = datetime.fromtimestamp(
            float(packet.time)
        ).strftime(
            "%H:%M:%S.%f"
        )[:-3]

        source = "-"
        destination = "-"

        sport = "-"
        dport = "-"

        protocol = "OTHER"

        info = "-"

        # -----------------------------------------------------
        # Network addresses
        # -----------------------------------------------------

        if packet.haslayer(ARP):

            source = packet[ARP].psrc

            destination = packet[ARP].pdst

            protocol = "ARP"

            info = (
                f"ARP operation={packet[ARP].op}"
            )

        elif packet.haslayer(IP):

            source = packet[IP].src

            destination = packet[IP].dst

        elif packet.haslayer(IPv6):

            source = packet[IPv6].src

            destination = packet[IPv6].dst

        elif packet.haslayer(Ether):

            source = packet[Ether].src

            destination = packet[Ether].dst

        # -----------------------------------------------------
        # TCP
        # -----------------------------------------------------

        if packet.haslayer(TCP):

            protocol = "TCP"

            sport = packet[TCP].sport

            dport = packet[TCP].dport

            info = (
                f"TCP Flags={packet[TCP].flags}"
            )

        # -----------------------------------------------------
        # UDP
        # -----------------------------------------------------

        elif packet.haslayer(UDP):

            protocol = "UDP"

            sport = packet[UDP].sport

            dport = packet[UDP].dport

            info = "UDP packet"

        # -----------------------------------------------------
        # ICMP
        # -----------------------------------------------------

        elif packet.haslayer(ICMP):

            protocol = "ICMP"

            info = (
                f"ICMP Type={packet[ICMP].type} "
                f"Code={packet[ICMP].code}"
            )

        # -----------------------------------------------------
        # DNS
        # -----------------------------------------------------

        if packet.haslayer(DNS):

            protocol = "DNS"

            dns = packet[DNS]

            if dns.qr == 0:

                info = "DNS Query"

                try:

                    if packet.haslayer(DNSQR):

                        qname = packet[
                            DNSQR
                        ].qname

                        if isinstance(
                            qname,
                            bytes
                        ):

                            qname = qname.decode(
                                errors="replace"
                            )

                        info = (
                            f"DNS Query: {qname}"
                        )

                except Exception:
                    pass

            else:

                info = "DNS Response"

        payload = self.safe_payload(
            packet
        )

        return {
            "no": number,
            "time": timestamp,
            "source": source,
            "destination": destination,
            "protocol": protocol,
            "sport": sport,
            "dport": dport,
            "length": len(packet),
            "info": info,
            "payload": payload,
        }

    # =========================================================
    # SAFE PAYLOAD
    # =========================================================

    @staticmethod
    def safe_payload(
        packet,
        max_bytes=64
    ):

        if not packet.haslayer(Raw):
            return "-"

        try:

            raw = bytes(
                packet[Raw].load
            )

            original_length = len(raw)

            raw = raw[:max_bytes]

            output = ""

            for byte in raw:

                if 32 <= byte <= 126:

                    output += chr(byte)

                else:

                    output += "."

            if original_length > max_bytes:

                output += "..."

            return output

        except Exception:

            return "[binary data]"

    # =========================================================
    # STATISTICS
    # =========================================================

    def update_statistics(
        self,
        packet,
        row
    ):

        protocol = row["protocol"]

        if protocol in self.stats:

            self.stats[protocol] += 1

        else:

            self.stats["OTHER"] += 1

        if packet.haslayer(IP):

            self.stats["IPv4"] += 1

        if packet.haslayer(IPv6):

            self.stats["IPv6"] += 1

        # TCP SYN detection

        if packet.haslayer(TCP):

            flags = packet[TCP].flags

            if flags & 0x02:

                self.syn_count += 1

        # Port activity

        if row["dport"] != "-":

            try:

                port = int(
                    row["dport"]
                )

                self.port_activity[
                    port
                ] += 1

            except Exception:
                pass

    # =========================================================
    # TABLE
    # =========================================================

    def insert_table_row(
        self,
        row
    ):

        tag = row["protocol"]

        self.tree.insert(
            "",
            "end",
            iid=str(row["no"]),
            values=(
                row["no"],
                row["time"],
                row["source"],
                row["destination"],
                row["protocol"],
                row["sport"],
                row["dport"],
                row["length"],
                row["info"],
            ),
            tags=(tag,)
        )

    # =========================================================
    # DASHBOARD
    # =========================================================

    def update_dashboard(self):

        self.total_card.configure(
            text=str(
                self.packet_counter
            )
        )

        self.tcp_card.configure(
            text=str(
                self.stats["TCP"]
            )
        )

        self.udp_card.configure(
            text=str(
                self.stats["UDP"]
            )
        )

        self.dns_card.configure(
            text=str(
                self.stats["DNS"]
            )
        )

        self.arp_card.configure(
            text=str(
                self.stats["ARP"]
            )
        )

        self.icmp_card.configure(
            text=str(
                self.stats["ICMP"]
            )
        )

        self.syn_card.configure(
            text=str(
                self.syn_count
            )
        )

    # =========================================================
    # SEARCH
    # =========================================================

    def refresh_table(self):

        search = (
            self.search_var.get()
            .lower()
            .strip()
        )

        for item in self.tree.get_children():

            self.tree.delete(
                item
            )

        for row in self.packet_rows:

            searchable = " ".join(
                str(value)
                for value in row.values()
            ).lower()

            if search and search not in searchable:

                continue

            self.insert_table_row(
                row
            )

    # =========================================================
    # PACKET DETAILS
    # =========================================================

    def show_details(
        self,
        event=None
    ):

        selection = self.tree.selection()

        if not selection:
            return

        try:

            number = int(
                selection[0]
            )

        except ValueError:

            return

        if number <= 0:
            return

        packet = self.packets[
            number - 1
        ]

        row = self.packet_rows[
            number - 1
        ]

        self.details_text.delete(
            "1.0",
            tk.END
        )

        details = []

        details.append(
            "============================================\n"
        )

        details.append(
            "PACKET ANALYSIS\n"
        )

        details.append(
            "============================================\n\n"
        )

        details.append(
            f"Packet Number : {row['no']}\n"
        )

        details.append(
            f"Time          : {row['time']}\n"
        )

        details.append(
            f"Length        : {row['length']} bytes\n"
        )

        # -----------------------------------------------------
        # Ethernet
        # -----------------------------------------------------

        if packet.haslayer(Ether):

            ether = packet[Ether]

            details.append(
                "\n[ ETHERNET ]\n"
            )

            details.append(
                f"Source MAC      : {ether.src}\n"
            )

            details.append(
                f"Destination MAC : {ether.dst}\n"
            )

            details.append(
                f"EtherType       : 0x{ether.type:04x}\n"
            )

        # -----------------------------------------------------
        # IPv4
        # -----------------------------------------------------

        if packet.haslayer(IP):

            ip = packet[IP]

            details.append(
                "\n[ IPv4 ]\n"
            )

            details.append(
                f"Source IP       : {ip.src}\n"
            )

            details.append(
                f"Destination IP  : {ip.dst}\n"
            )

            details.append(
                f"TTL             : {ip.ttl}\n"
            )

            details.append(
                f"Protocol        : {ip.proto}\n"
            )

            details.append(
                f"Packet ID       : {ip.id}\n"
            )

        # -----------------------------------------------------
        # IPv6
        # -----------------------------------------------------

        if packet.haslayer(IPv6):

            ipv6 = packet[IPv6]

            details.append(
                "\n[ IPv6 ]\n"
            )

            details.append(
                f"Source IP       : {ipv6.src}\n"
            )

            details.append(
                f"Destination IP  : {ipv6.dst}\n"
            )

            details.append(
                f"Hop Limit       : {ipv6.hlim}\n"
            )

        # -----------------------------------------------------
        # TCP
        # -----------------------------------------------------

        if packet.haslayer(TCP):

            tcp = packet[TCP]

            details.append(
                "\n[ TCP ]\n"
            )

            details.append(
                f"Source Port     : {tcp.sport}\n"
            )

            details.append(
                f"Destination Port: {tcp.dport}\n"
            )

            details.append(
                f"Flags           : {tcp.flags}\n"
            )

            details.append(
                f"Sequence        : {tcp.seq}\n"
            )

            details.append(
                f"Acknowledgment   : {tcp.ack}\n"
            )

            details.append(
                f"Window          : {tcp.window}\n"
            )

        # -----------------------------------------------------
        # UDP
        # -----------------------------------------------------

        if packet.haslayer(UDP):

            udp = packet[UDP]

            details.append(
                "\n[ UDP ]\n"
            )

            details.append(
                f"Source Port     : {udp.sport}\n"
            )

            details.append(
                f"Destination Port: {udp.dport}\n"
            )

            details.append(
                f"Length          : {udp.len}\n"
            )

        # -----------------------------------------------------
        # ICMP
        # -----------------------------------------------------

        if packet.haslayer(ICMP):

            icmp = packet[ICMP]

            details.append(
                "\n[ ICMP ]\n"
            )

            details.append(
                f"Type            : {icmp.type}\n"
            )

            details.append(
                f"Code            : {icmp.code}\n"
            )

        # -----------------------------------------------------
        # ARP
        # -----------------------------------------------------

        if packet.haslayer(ARP):

            arp = packet[ARP]

            details.append(
                "\n[ ARP ]\n"
            )

            details.append(
                f"Operation       : {arp.op}\n"
            )

            details.append(
                f"Sender MAC      : {arp.hwsrc}\n"
            )

            details.append(
                f"Sender IP       : {arp.psrc}\n"
            )

            details.append(
                f"Target MAC      : {arp.hwdst}\n"
            )

            details.append(
                f"Target IP       : {arp.pdst}\n"
            )

        # -----------------------------------------------------
        # DNS
        # -----------------------------------------------------

        if packet.haslayer(DNS):

            dns = packet[DNS]

            details.append(
                "\n[ DNS ]\n"
            )

            details.append(
                "Type            : "
                + (
                    "Response"
                    if dns.qr
                    else "Query"
                )
                + "\n"
            )

            if packet.haslayer(DNSQR):

                try:

                    qname = packet[
                        DNSQR
                    ].qname

                    if isinstance(
                        qname,
                        bytes
                    ):

                        qname = qname.decode(
                            errors="replace"
                        )

                    details.append(
                        f"Query Name      : {qname}\n"
                    )

                except Exception:
                    pass

        # -----------------------------------------------------
        # Payload
        # -----------------------------------------------------

        details.append(
            "\n[ SAFE PAYLOAD SUMMARY ]\n"
        )

        details.append(
            row["payload"]
            + "\n"
        )

        details.append(
            "\n============================================\n"
        )

        self.details_text.insert(
            tk.END,
            "".join(details)
        )

    # =========================================================
    # TRAFFIC INDICATORS
    # =========================================================

    def update_indicators(
        self,
        packet,
        row
    ):

        indicator = None

        # -----------------------------------------------------
        # SYN indicator
        # -----------------------------------------------------

        if packet.haslayer(TCP):

            flags = packet[TCP].flags

            syn = bool(
                flags & 0x02
            )

            ack = bool(
                flags & 0x10
            )

            if syn and not ack:

                indicator = (
                    f"SYN activity: "
                    f"{row['source']} → "
                    f"{row['destination']} "
                    f"port {row['dport']}"
                )

        # -----------------------------------------------------
        # High destination port indicator
        # -----------------------------------------------------

        if indicator is None:

            try:

                port = int(
                    row["dport"]
                )

                if port >= 1024:

                    indicator = (
                        f"High destination port activity: "
                        f"{port}"
                    )

            except Exception:
                pass

        # -----------------------------------------------------
        # ARP indicator
        # -----------------------------------------------------

        if (
            indicator is None
            and packet.haslayer(ARP)
        ):

            arp = packet[ARP]

            source_ip = arp.psrc

            source_mac = arp.hwsrc

            previous = self.arp_ips.get(
                source_ip
            )

            if (
                previous
                and previous != source_mac
            ):

                indicator = (
                    "ARP mapping changed: "
                    f"{source_ip}"
                )

            self.arp_ips[
                source_ip
            ] = source_mac

        if indicator:

            timestamp = datetime.now().strftime(
                "%H:%M:%S"
            )

            message = (
                f"[{timestamp}] {indicator}\n"
            )

            self.alert_text.insert(
                "end",
                message
            )

            self.alert_text.see(
                "end"
            )

            self.alerts.append(
                message
            )

    # =========================================================
    # STOP
    # =========================================================

    def stop_capture(self):

        self.capturing = False

        self.start_button.configure(
            state="normal"
        )

        self.stop_button.configure(
            state="disabled"
        )

        self.status_var.set(
            "Stopping capture..."
        )

    # =========================================================
    # CLEAR
    # =========================================================

    def clear_packets(self):

        if self.capturing:

            messagebox.showwarning(
                "Capture Running",
                "Stop capture before clearing."
            )

            return

        self.packets.clear()

        self.packet_rows.clear()

        self.packet_counter = 0

        for key in self.stats:

            self.stats[key] = 0

        self.syn_count = 0

        self.port_activity.clear()

        self.arp_ips.clear()

        self.alerts.clear()

        for item in self.tree.get_children():

            self.tree.delete(
                item
            )

        self.details_text.delete(
            "1.0",
            tk.END
        )

        self.alert_text.delete(
            "1.0",
            tk.END
        )

        self.update_dashboard()

        self.status_var.set(
            "All captured data cleared"
        )

    # =========================================================
    # CSV EXPORT
    # =========================================================

    def save_csv(self):

        if not self.packet_rows:

            messagebox.showwarning(
                "No Data",
                "No packets available."
            )

            return

        filename = filedialog.asksaveasfilename(
            title="Save Packet CSV",
            initialdir=os.path.join(
                os.getcwd(),
                "exports"
            ),
            defaultextension=".csv",
            filetypes=[
                ("CSV files", "*.csv"),
                ("All files", "*.*")
            ]
        )

        if not filename:
            return

        fields = [
            "no",
            "time",
            "source",
            "destination",
            "protocol",
            "sport",
            "dport",
            "length",
            "info",
            "payload",
        ]

        try:

            with open(
                filename,
                "w",
                newline="",
                encoding="utf-8"
            ) as file:

                writer = csv.DictWriter(
                    file,
                    fieldnames=fields
                )

                writer.writeheader()

                for row in self.packet_rows:

                    writer.writerow(
                        {
                            field: row[field]
                            for field in fields
                        }
                    )

            messagebox.showinfo(
                "CSV Export",
                f"CSV saved successfully:\n\n{filename}"
            )

        except Exception as exc:

            messagebox.showerror(
                "CSV Error",
                str(exc)
            )

    # =========================================================
    # PCAP EXPORT
    # =========================================================

    def save_pcap(self):

        if not self.packets:

            messagebox.showwarning(
                "No Packets",
                "No packets available."
            )

            return

        filename = filedialog.asksaveasfilename(
            title="Save PCAP",
            initialdir=os.path.join(
                os.getcwd(),
                "captures"
            ),
            defaultextension=".pcap",
            filetypes=[
                ("PCAP files", "*.pcap"),
                ("All files", "*.*")
            ]
        )

        if not filename:
            return

        try:

            wrpcap(
                filename,
                self.packets
            )

            messagebox.showinfo(
                "PCAP Export",
                f"PCAP saved successfully:\n\n{filename}"
            )

        except Exception as exc:

            messagebox.showerror(
                "PCAP Error",
                str(exc)
            )

    # =========================================================
    # CLOSE
    # =========================================================

    def close_application(self):

        if self.capturing:

            answer = messagebox.askyesno(
                "Capture Running",
                "Capture is still running.\n\n"
                "Stop capture and exit?"
            )

            if not answer:
                return

            self.capturing = False

        self.root.destroy()


# =============================================================
# MAIN
# =============================================================

def main():

    root = tk.Tk()

    PacketAnalyzer(
        root
    )

    root.mainloop()


if __name__ == "__main__":

    main()
