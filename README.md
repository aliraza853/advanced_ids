# Advanced Python Intrusion Detection System (IDS)

A professional-grade **Intrusion Detection System** built in Python that monitors network traffic, detects suspicious activity, logs alerts, and provides real-time visualization through a web dashboard.

## 🎯 Features

### Core Functionality
- **Real-time Network Monitoring**: Captures and analyzes TCP packets on suspicious ports
- **Suspicious Activity Detection**: Identifies connection attempts to common attack vectors (SSH, Telnet, RDP, SMB)
- **CSV Logging**: Comprehensive logging with timestamp, source IP, port, location, and block status
- **Automatic IP Blocking**: Blocks IPs after configurable threshold of suspicious attempts
- **GeoIP Lookup**: Identifies geographical location of source IPs
- **Email Notifications**: Sends alerts when IPs are blocked
- **Firewall Integration**: Automatic iptables rules for OS-level IP blocking (Linux)

### Dashboard Features
- **Live Alerts Table**: Real-time table of all detected suspicious activity
- **Top Suspicious IPs**: Bar chart showing most active threat sources
- **Port Distribution**: Pie chart of targeted ports
- **Alerts Timeline**: Line chart showing alert frequency over time
- **Location Analysis**: Geographic distribution of threats
- **Statistics Cards**: Quick overview of total alerts, blocked IPs, and unique sources
- **Auto-refresh**: Dashboard updates every 5 seconds
- This project was intentionally designed to be simple to deploy and easy to understand, making it accessible to students, early-career security engineers, and practitioners learning Intrusion Detection concepts.

## 📋 Requirements

- **Python**: 3.9 or higher
- **Operating System**: Linux (for full firewall functionality)
- **Privileges**: Root/sudo access required for packet sniffing and firewall rules
- **Dependencies**: See `requirements.txt`

### System Requirements
```bash
# Ubuntu/Debian
sudo apt-get install python3-pip libpcap-dev

# Fedora/RHEL
sudo dnf install python3-pip libpcap-devel
```

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/hina-saif64/advanced_ids.git
cd advanced_ids
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configuration (Optional)

Edit `simple_ids.py` to customize:

```python
# Suspicious ports to monitor
SUSPICIOUS_PORTS = [22, 23, 3389, 445, 139, 135]

# Block threshold (number of attempts before blocking)
BLOCK_THRESHOLD = 3

# Email notifications (set to True to enable)
EMAIL_ALERTS = False
EMAIL_FROM = "your_email@example.com"
EMAIL_TO = "recipient_email@example.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_PASS = "your_app_password"

# Firewall blocking (set to True to enable)
FIREWALL_BLOCKING = False
```

## 📖 Usage

### Step 1: Start the IDS
```bash
# Run with sudo (required for packet sniffing)
sudo python3 simple_ids.py
```

You should see:
```
==================================================
Advanced Python IDS Starting...
==================================================
Monitoring ports: [22, 23, 3389, 445, 139, 135]
Block threshold: 3 attempts
Email alerts: Disabled
Firewall blocking: Disabled
Press Ctrl+C to stop
==================================================
```

### Step 2: Start the Dashboard (in another terminal)
```bash
python3 dashboard.py
```

You should see:
```
Starting Advanced IDS Dashboard...
Open http://127.0.0.1:8050/ in your browser
```

### Step 3: Access the Dashboard
Open your web browser and navigate to:
```
http://127.0.0.1:8050/
```

### Step 4: Monitor Activity
The dashboard will automatically update every 5 seconds with:
- New alerts
- Updated statistics
- Real-time charts and visualizations

### Stop the IDS
Press `Ctrl+C` in the terminal running `simple_ids.py`

## 📊 Output Files

### alerts.csv
CSV file containing all detected alerts:
```
timestamp,src_ip,dst_port,location,blocked,attempt_count
2024-01-18 10:30:45,192.168.1.100,22,United States New York,False,1
2024-01-18 10:31:12,192.168.1.100,22,United States New York,False,2
2024-01-18 10:31:45,192.168.1.100,22,United States New York,True,3
```

### ids.log
Log file with detailed system information:
```
2024-01-18 10:30:45,123 - INFO - Advanced Python IDS Starting...
2024-01-18 10:30:45,456 - INFO - [ALERT] 2024-01-18 10:30:45 - 192.168.1.100 (United States, New York) -> Port 22 (Attempt #1)
2024-01-18 10:31:45,789 - WARNING - [BLOCK] 192.168.1.100 blocked after 3 suspicious attempts
```

## 🔧 Advanced Configuration

### Enable Email Notifications

1. **For Gmail**:
   - Enable 2-Factor Authentication
   - Generate App Password: https://myaccount.google.com/apppasswords
   - Update `simple_ids.py`:
   ```python
   EMAIL_ALERTS = True
   EMAIL_FROM = "your_email@gmail.com"
   EMAIL_TO = "recipient@example.com"
   SMTP_SERVER = "smtp.gmail.com"
   SMTP_PORT = 587
   SMTP_PASS = "your_16_character_app_password"
   ```

2. **For Other Email Providers**:
   - Update SMTP_SERVER and SMTP_PORT accordingly
   - Use app-specific passwords if available

### Enable Firewall Blocking

```python
FIREWALL_BLOCKING = True
```

Then run with sudo:
```bash
sudo python3 simple_ids.py
```

**Note**: This will add iptables rules to block suspicious IPs at the OS level.

### Add Custom Ports

Edit the `SUSPICIOUS_PORTS` list in `simple_ids.py`:
```python
SUSPICIOUS_PORTS = [22, 23, 3389, 445, 139, 135, 8080, 9000]  # Add your ports
```

## 🛡️ Security Best Practices

1. **Run with appropriate privileges**: Use `sudo` only when necessary
2. **Secure email credentials**: Use environment variables or configuration files with restricted permissions
3. **Monitor logs regularly**: Check `ids.log` for suspicious patterns
4. **Update dependencies**: Regularly run `pip install --upgrade -r requirements.txt`
5. **Firewall rules**: Periodically review and clean up old iptables rules
6. **Network isolation**: Run on a dedicated monitoring interface when possible

## 🐛 Troubleshooting

### "Permission denied" error
```bash
# Solution: Run with sudo
sudo python3 simple_ids.py
```

### "No module named 'scapy'" error
```bash
# Solution: Install dependencies
pip install -r requirements.txt
```

### Dashboard not updating
- Ensure `simple_ids.py` is running
- Check that `alerts.csv` exists and is being written to
- Verify port 8050 is not in use: `lsof -i :8050`

### GeoIP lookups are slow
- GeoIP cache is enabled to reduce API calls
- First lookup for each IP may take 2-3 seconds
- Subsequent lookups are instant

### Email alerts not sending
- Verify SMTP credentials are correct
- Check firewall allows outbound SMTP connections
- Review `ids.log` for error messages
- Test with a simple Python script first

## 📈 Performance Considerations

- **Memory Usage**: Minimal (~50-100 MB)
- **CPU Usage**: Low (~1-5% depending on traffic)
- **Disk Usage**: CSV file grows ~1-2 KB per alert
- **Network Overhead**: Negligible (read-only sniffing)

For high-traffic networks, consider:
- Filtering specific interfaces: `sniff(iface='eth0', ...)`
- Adjusting block threshold
- Archiving old CSV files regularly

## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- Machine learning-based anomaly detection
- Database backend instead of CSV
- Web UI improvements
- Multi-interface monitoring
- Advanced threat intelligence integration

## 📝 License

This project is open-source and available for educational, personal, and voluntary work purposes.

## ⚠️ Disclaimer

This tool is for authorized security monitoring only. Unauthorized access to computer networks is illegal. Always ensure you have proper authorization before deploying this IDS on any network.

## 📞 Support

For issues, questions, or suggestions:
1. Check the Troubleshooting section above
2. Review `ids.log` for error messages
3. Open an issue on GitHub with detailed information

## 🎓 Learning Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Dash Documentation](https://dash.plotly.com/)
- [Network Security Basics](https://www.cisco.com/c/en/us/support/docs/security/)
- [IDS/IPS Concepts](https://www.paloaltonetworks.com/cyberpedia/what-is-ids-ips)

---

**Created with ❤️ for cybersecurity enthusiasts and professionals**

Last Updated: January 2024
