# detector.py

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
from collections import defaultdict
import threading
import time

from database import add_alert
from rules import (
    SUSPICIOUS_PORTS,
    BLACKLISTED_IPS,
    SUSPICIOUS_DOMAINS,
    PORT_SCAN_THRESHOLD,
    SYN_FLOOD_THRESHOLD,
    ICMP_FLOOD_THRESHOLD,
    CONNECTION_THRESHOLD,
    LARGE_PACKET_SIZE,
    TIME_WINDOW
)

port_scan_tracker = defaultdict(set)
syn_tracker = defaultdict(list)
icmp_tracker = defaultdict(list)
connection_tracker = defaultdict(list)

monitoring_status = False
sniffer_thread = None

recent_alerts = {}
alert_cooldown = 8


def should_create_alert(alert_type, source_ip, destination_ip):
    key = f"{alert_type}:{source_ip}:{destination_ip}"
    current_time = time.time()

    if key in recent_alerts:
        if current_time - recent_alerts[key] < alert_cooldown:
            return False

    recent_alerts[key] = current_time
    return True


def create_alert(alert_type, source_ip, destination_ip, message, severity="Medium"):
    if not should_create_alert(alert_type, source_ip, destination_ip):
        return

    alert_id = add_alert(
        alert_type,
        source_ip,
        destination_ip,
        message,
        severity
    )

    print("\n================ ALERT DETECTED ================")
    print(f"ID: {alert_id}")
    print(f"Type: {alert_type}")
    print(f"Source IP: {source_ip}")
    print(f"Destination IP: {destination_ip}")
    print(f"Message: {message}")
    print(f"Severity: {severity}")
    print("================================================")


def clean_old_entries(tracker, key):
    current_time = time.time()

    if key in tracker:
        tracker[key] = [
            timestamp
            for timestamp in tracker[key]
            if current_time - timestamp < TIME_WINDOW
        ]


def detect_blacklisted_ip(source_ip, destination_ip):
    if source_ip in BLACKLISTED_IPS:
        create_alert(
            "Blacklisted IP",
            source_ip,
            destination_ip,
            "Traffic detected from a blacklisted source IP address.",
            "High"
        )


def detect_suspicious_port(source_ip, destination_ip, destination_port):
    if destination_port in SUSPICIOUS_PORTS:
        create_alert(
            "Suspicious Port Access",
            source_ip,
            destination_ip,
            f"{SUSPICIOUS_PORTS[destination_port]} Port: {destination_port}",
            "Medium"
        )


def detect_port_scan(source_ip, destination_ip, destination_port):
    port_scan_tracker[source_ip].add(destination_port)

    if len(port_scan_tracker[source_ip]) >= PORT_SCAN_THRESHOLD:
        create_alert(
            "Port Scan Detected",
            source_ip,
            destination_ip,
            f"Possible port scan: {len(port_scan_tracker[source_ip])} unique ports accessed in a short period.",
            "High"
        )

        port_scan_tracker[source_ip].clear()


def detect_syn_flood(source_ip, destination_ip):
    current_time = time.time()

    syn_tracker[source_ip].append(current_time)
    clean_old_entries(syn_tracker, source_ip)

    if len(syn_tracker[source_ip]) >= SYN_FLOOD_THRESHOLD:
        create_alert(
            "SYN Flood Detected",
            source_ip,
            destination_ip,
            f"Possible SYN flood: {len(syn_tracker[source_ip])} SYN packets in {TIME_WINDOW} seconds.",
            "Critical"
        )

        syn_tracker[source_ip].clear()


def detect_icmp_flood(source_ip, destination_ip):
    current_time = time.time()

    icmp_tracker[source_ip].append(current_time)
    clean_old_entries(icmp_tracker, source_ip)

    if len(icmp_tracker[source_ip]) >= ICMP_FLOOD_THRESHOLD:
        create_alert(
            "ICMP Flood Detected",
            source_ip,
            destination_ip,
            f"Possible ICMP flood: {len(icmp_tracker[source_ip])} ICMP packets in {TIME_WINDOW} seconds.",
            "High"
        )

        icmp_tracker[source_ip].clear()


def detect_multiple_connections(source_ip, destination_ip, destination_port):
    current_time = time.time()
    key = f"{source_ip}:{destination_ip}:{destination_port}"

    connection_tracker[key].append(current_time)
    clean_old_entries(connection_tracker, key)

    if len(connection_tracker[key]) >= CONNECTION_THRESHOLD:
        create_alert(
            "Repeated Connection Attempts",
            source_ip,
            destination_ip,
            f"{len(connection_tracker[key])} connection attempts to port {destination_port} in {TIME_WINDOW} seconds.",
            "High"
        )

        connection_tracker[key].clear()


def detect_large_packet(packet, source_ip, destination_ip):
    packet_size = len(packet)

    if packet_size >= LARGE_PACKET_SIZE:
        create_alert(
            "Large Packet Detected",
            source_ip,
            destination_ip,
            f"Large packet observed: {packet_size} bytes.",
            "Medium"
        )


def detect_suspicious_dns(packet, source_ip, destination_ip):
    if not packet.haslayer(DNS):
        return

    if not packet[DNS].qd:
        return

    try:
        domain = packet[DNS].qd.qname.decode(errors="ignore").rstrip(".")

        for suspicious_domain in SUSPICIOUS_DOMAINS:
            if suspicious_domain.lower() in domain.lower():
                create_alert(
                    "Suspicious DNS Request",
                    source_ip,
                    destination_ip,
                    f"Suspicious domain requested: {domain}",
                    "High"
                )
                break

    except Exception:
        pass


def process_packet(packet):
    try:
        if not packet.haslayer(IP):
            return

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        detect_blacklisted_ip(source_ip, destination_ip)
        detect_large_packet(packet, source_ip, destination_ip)
        detect_suspicious_dns(packet, source_ip, destination_ip)

        if packet.haslayer(TCP):
            destination_port = packet[TCP].dport
            flags = packet[TCP].flags

            detect_suspicious_port(
                source_ip,
                destination_ip,
                destination_port
            )

            detect_port_scan(
                source_ip,
                destination_ip,
                destination_port
            )

            detect_multiple_connections(
                source_ip,
                destination_ip,
                destination_port
            )

            if flags == "S":
                detect_syn_flood(source_ip, destination_ip)

        if packet.haslayer(UDP):
            destination_port = packet[UDP].dport

            detect_multiple_connections(
                source_ip,
                destination_ip,
                destination_port
            )

        if packet.haslayer(ICMP):
            detect_icmp_flood(source_ip, destination_ip)

    except Exception as error:
        print("Packet processing error:", error)


def start_sniffer():
    global monitoring_status

    monitoring_status = True
    print("Network monitoring started...")

    try:
        sniff(
            prn=process_packet,
            store=False,
            stop_filter=lambda packet: not monitoring_status
        )

    except Exception as error:
        monitoring_status = False
        print("Sniffer error:", error)


def start_monitoring():
    global sniffer_thread, monitoring_status

    if monitoring_status:
        return "Monitoring is already running."

    sniffer_thread = threading.Thread(
        target=start_sniffer,
        daemon=True
    )

    sniffer_thread.start()

    return "Network monitoring started."


def stop_monitoring():
    global monitoring_status

    monitoring_status = False

    return "Monitoring stopped."