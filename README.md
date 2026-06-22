# CodeAlpha_NetworkIDS
A real-time Network Intrusion Detection System (NIDS) built with Python, Flask, and Scapy. It monitors network packets, detects suspicious activity using basic detection rules, and displays alerts on a web dashboard.

Features
Live packet capture using Scapy
Detects suspicious network activity
Web dashboard for viewing alerts
Displays source IP, destination IP, protocol, alert type, and time
Alert severity levels: Low, Medium, High
Mark alerts as resolved from the dashboard
Stores alerts during application runtime
Supports TCP, UDP, ICMP, and ARP packet monitoring
Detection Rules

This project can detect examples of:

Port scanning attempts
SYN flood / high number of TCP SYN packets
ICMP flood / ping flood
Suspicious ports such as Telnet, FTP, SSH, RDP, SMB
ARP spoofing warning
Large or suspicious packets
Multiple connections from the same IP address
Technologies Used
Python
Flask
Scapy
HTML
CSS
JavaScript
Bootstrap
Project Structure
CodeAlpha_NetworkIDS/
│
├── app.py
├── requirements.txt
├── README.md
│
├── templates/
│   └── index.html
│
└── static/
    ├── style.css
    └── script.js
