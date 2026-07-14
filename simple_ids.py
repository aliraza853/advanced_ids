#!/usr/bin/env python3
"""
Advanced Python Intrusion Detection System (IDS)
Features:
- Network packet sniffing and analysis
- Suspicious activity logging to CSV
- Automatic IP blocking after threshold
- GeoIP lookup for source IPs
- Email notifications for blocked IPs
- Firewall integration (iptables)
"""

import pandas as pd
from datetime import datetime
from scapy.all import sniff
from scapy.layers.inet import IP, TCP
import requests
import smtplib
from email.message import EmailMessage
import os
import sys
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ids.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ---------------------------
# CONFIGURATION
# ---------------------------
SUSPICIOUS_PORTS = [22, 23, 3389, 445, 139, 135]  # SSH, Telnet, RDP, SMB, NetBIOS
ALERT_CSV = "alerts.csv"
BLOCK_THRESHOLD = 3
EMAIL_ALERTS = False  # Set to True and configure credentials below
EMAIL_FROM = "your_email@example.com"
EMAIL_TO = "recipient_email@example.com"
SMTP_SERVER = "smtp.gmail.com"  # Change for your email provider
SMTP_PORT = 587
SMTP_PASS = "your_app_password"  # Use app-specific password for Gmail
FIREWALL_BLOCKING = False  # Set to True to enable firewall blocking (requires sudo)

blocked_ips = {}
geoip_cache = {}  # Cache GeoIP lookups to reduce API calls

# ---------------------------
# INITIALIZE CSV
# ---------------------------
def initialize_csv():
    """Create alerts CSV file if it doesn't exist"""
    if not os.path.exists(ALERT_CSV):
        df = pd.DataFrame(columns=[
            "timestamp",
            "src_ip",
            "dst_port",
            "attack_type",
            "severity",
            "location",
            "blocked",
            "attempt_count"
        ])
        df.to_csv(ALERT_CSV, index=False)
        logger.info(f"Created new alerts file: {ALERT_CSV}")

# ---------------------------
# GEOIP LOOKUP
# ---------------------------
def get_geo(ip):
    """
    Get geographical location of IP address
    Uses caching to reduce API calls
    """
    if ip in geoip_cache:
        return geoip_cache[ip]
    
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        if response.status_code == 200:
            data = response.json()
            location = f"{data.get('country', 'Unknown')}, {data.get('city', 'Unknown')}"
            geoip_cache[ip] = location
            return location
    except Exception as e:
        logger.warning(f"GeoIP lookup failed for {ip}: {str(e)}")
    
    return "Unknown"

# ---------------------------
# EMAIL NOTIFICATIONS
# ---------------------------
def send_email_alert(ip, location):
    """Send email notification when IP is blocked"""
    if not EMAIL_ALERTS:
        return
    
    try:
        msg = EmailMessage()
        msg.set_content(
            f"Alert: Suspicious IP has been blocked!\n\n"
            f"IP Address: {ip}\n"
            f"Location: {location}\n"
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Reason: Multiple suspicious connection attempts detected"
        )
        msg['Subject'] = f"IDS Alert - Blocked IP: {ip}"
        msg['From'] = EMAIL_FROM
        msg['To'] = EMAIL_TO
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_FROM, SMTP_PASS)
            server.send_message(msg)
        
        logger.info(f"Email alert sent for blocked IP: {ip}")
    except Exception as e:
        logger.error(f"Failed to send email alert for {ip}: {str(e)}")

# ---------------------------
# FIREWALL BLOCKING
# ---------------------------
def block_ip_firewall(ip):
    """Block IP at OS level using iptables (Linux only)"""
    if not FIREWALL_BLOCKING:
        return
    
    try:
        # Check if running as root
        if os.geteuid() != 0:
            logger.warning(f"Cannot block {ip} - requires root privileges")
            return
        
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        logger.info(f"Firewall rule added to block: {ip}")
    except Exception as e:
        logger.error(f"Firewall blocking failed for {ip}: {str(e)}")

# ---------------------------
# ATTACK TYPE DETECTION
# ---------------------------

ip_port_history = {}
ip_syn_counter = {}

def detect_attack_type(ip, port, packet):
    """Detect attack type and severity"""

    if ip not in ip_port_history:
        ip_port_history[ip] = set()

    ip_port_history[ip].add(port)

    # Port Scan
    if len(ip_port_history[ip]) >= 5:
        return "Port Scan", "High"

    # SSH
    if port == 22:
        attempts = blocked_ips.get(ip, {}).get("count", 0)

        if attempts >= BLOCK_THRESHOLD:
            return "SSH Brute Force", "Critical"

        return "SSH Login Attempt", "Medium"

    # Telnet
    if port == 23:
        return "Telnet Login Attempt", "High"

    # SMB
    if port in [139, 445]:
        return "SMB Enumeration", "High"

    # RPC
    if port == 135:
        return "RPC Enumeration", "Medium"

    # RDP
    if port == 3389:
        return "RDP Brute Force", "Critical"

    # SYN Flood
    if packet.haslayer(TCP):

        flags = packet[TCP].flags

        if flags == "S":

            ip_syn_counter[ip] = ip_syn_counter.get(ip, 0) + 1

            if ip_syn_counter[ip] >= 20:
                return "SYN Flood", "Critical"

    return "Unknown Suspicious Activity", "Low"

# ---------------------------
# PACKET DETECTION
# ---------------------------

def detect_suspicious_packet(packet):
    """Detect suspicious packets and classify attack type"""

    try:

        if not packet.haslayer(TCP):
            return

        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        # Ignore already blocked IPs
        if src_ip in blocked_ips:
            if blocked_ips[src_ip]["status"] == "blocked":
                return

        # Ignore non-suspicious ports
        if dst_port not in SUSPICIOUS_PORTS:
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        location = get_geo(src_ip)

        blocked = False

        # Create entry if first time seen
        if src_ip not in blocked_ips:

            blocked_ips[src_ip] = {
                "count": 0,
                "status": "monitoring",
                "first_seen": timestamp
            }

        # Increase attempt counter
        blocked_ips[src_ip]["count"] += 1

        attempt_count = blocked_ips[src_ip]["count"]

        # Detect attack type
        attack_type, severity = detect_attack_type(
            src_ip,
            dst_port,
            packet
        )

        logger.info(
            f"[ALERT] "
            f"{src_ip} "
            f"-> Port {dst_port} "
            f"| {attack_type} "
            f"| Severity: {severity} "
            f"| Attempt #{attempt_count}"
        )

        # Save alert
        alert = pd.DataFrame([[
            timestamp,
            src_ip,
            dst_port,
            attack_type,
            severity,
            location,
            blocked,
            attempt_count
        ]],
        columns=[
            "timestamp",
            "src_ip",
            "dst_port",
            "attack_type",
            "severity",
            "location",
            "blocked",
            "attempt_count"
        ])

        alert.to_csv(
            ALERT_CSV,
            mode="a",
            header=False,
            index=False
        )

        # Block attacker
        if attempt_count >= BLOCK_THRESHOLD:

            blocked = True

            blocked_ips[src_ip]["status"] = "blocked"

            logger.warning(
                f"[BLOCK] "
                f"{src_ip} "
                f"blocked after "
                f"{attempt_count} attempts"
            )

            block_ip_firewall(src_ip)

            send_email_alert(
                src_ip,
                location
            )

            blocked_alert = pd.DataFrame([[
                timestamp,
                src_ip,
                dst_port,
                attack_type,
                severity,
                location,
                blocked,
                attempt_count
            ]],
            columns=[
                "timestamp",
                "src_ip",
                "dst_port",
                "attack_type",
                "severity",
                "location",
                "blocked",
                "attempt_count"
            ])

            blocked_alert.to_csv(
                ALERT_CSV,
                mode="a",
                header=False,
                index=False
            )

    except Exception as e:

        logger.error(
            f"Error processing packet: {str(e)}"
        )

# ---------------------------
# STATISTICS
# ---------------------------
def print_statistics():
    """Print current IDS statistics"""
    try:
        if os.path.exists(ALERT_CSV):
            df = pd.read_csv(ALERT_CSV)
            total_alerts = len(df)
            blocked_count = df[df["blocked"] == True]["src_ip"].nunique()
            unique_ips = df['src_ip'].nunique() if 'src_ip' in df.columns else 0
            
            logger.info(f"\n=== IDS Statistics ===")
            logger.info(f"Total Alerts: {total_alerts}")
            logger.info(f"Blocked IPs: {blocked_count}")
            logger.info(f"Unique Source IPs: {unique_ips}")
            logger.info(f"========================\n")
    except Exception as e:
        logger.error(f"Error printing statistics: {str(e)}")

# ---------------------------
# MAIN
# ---------------------------
def main():
    """Start the IDS"""
    initialize_csv()
    
    logger.info("=" * 50)
    logger.info("Advanced Python IDS Starting...")
    logger.info("=" * 50)
    logger.info(f"Monitoring ports: {SUSPICIOUS_PORTS}")
    logger.info(f"Block threshold: {BLOCK_THRESHOLD} attempts")
    logger.info(f"Email alerts: {'Enabled' if EMAIL_ALERTS else 'Disabled'}")
    logger.info(f"Firewall blocking: {'Enabled' if FIREWALL_BLOCKING else 'Disabled'}")
    logger.info("Press Ctrl+C to stop")
    logger.info("=" * 50 + "\n")
    
    try:
        sniff(prn=detect_suspicious_packet, filter="tcp", store=0)
    except KeyboardInterrupt:
        logger.info("\nIDS stopped by user")
        print_statistics()
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
