# rules.py

SUSPICIOUS_PORTS = {
    21: "FTP service access detected",
    23: "Telnet service access detected",
    22: "SSH service access detected",
    445: "SMB service access detected",
    3389: "Remote Desktop Protocol access detected",
    3306: "MySQL service access detected",
    1433: "MSSQL service access detected",
    5900: "VNC service access detected"
}

# For a safe demo, you can temporarily add your own test IP here.
BLACKLISTED_IPS = [
    "10.10.10.10",
    "192.168.1.250"
]

# For safe demonstration, temporarily add "google.com" and run nslookup google.com.
SUSPICIOUS_DOMAINS = [
    "malware-test.com",
    "phishing-test.com",
    "suspicious-site.com",
    "evil.com"
]

PORT_SCAN_THRESHOLD = 8
SYN_FLOOD_THRESHOLD = 15
ICMP_FLOOD_THRESHOLD = 4
CONNECTION_THRESHOLD = 10

LARGE_PACKET_SIZE = 1200
TIME_WINDOW = 20