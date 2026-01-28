# RoboWiFi-AP - WiFi Security Assessment Framework

Advanced wireless security toolkit with fake access point creation, password capture, monitoring, and rogue AP detection capabilities.

## ⚠️ LEGAL WARNING

**This tool is for AUTHORIZED security testing and educational purposes ONLY.**

- ✅ Only use on networks you **own** or have **explicit written permission** to test
- ❌ Unauthorized access point creation may be **illegal** in your jurisdiction
- ❌ Password interception without consent is a **criminal offense** in most countries
- ❌ Captive portal credential harvesting must only be used in **authorized penetration tests**
- ⚖️ Check your **local laws** before use

**The authors assume NO LIABILITY for misuse of this software.**

---

## 📋 Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [Advanced Features](#-advanced-features)
- [Monitoring & Logs](#-monitoring-and-logs)
- [Troubleshooting](#️-troubleshooting)
- [FAQ](#-faq)

---

## ✨ Features

### 🎯 Three Operational Modes

#### 1. Basic Fake Access Point (`fake_ap.sh`)
- ✅ Create simple fake WiFi access points
- ✅ WPA2 password capture (with hostapd-wpe)
- ✅ Open network support
- ✅ Internet sharing via uplink interface
- ✅ DHCP server with configurable ranges
- ✅ DNS forwarding
- ✅ Real-time client monitoring

#### 2. Advanced Fake Access Point (`advanced_fake_ap.sh`)
All basic features **PLUS:**
- 🔐 **Captive portal** for credential harvesting
- 📊 **Packet monitoring** with tcpdump
- 🚫 **MAC address filtering** (whitelist/blacklist)
- 📉 **Bandwidth limiting** per client
- 👻 **Hidden SSID** (stealth mode)
- 📱 **Multi-adapter support** with capability detection
- 📈 **Real-time statistics** and monitoring
- 💾 **Comprehensive logging** of all activities

#### 3. Rogue AP Detector (`fake_ap_detector.sh`)
- 🔍 Detect fake/rogue access points
- 🛡️ Monitor for evil twin attacks
- 🚨 Identify deauthentication attacks
- 🔐 ARP spoofing detection
- 🌐 DNS spoofing detection
- ⚡ Real-time threat alerts
- 📊 Client tracking and analysis

---

## 🔧 Requirements

### Hardware
- **Wireless adapter** with AP mode support
- USB or built-in wireless card (check compatibility below)

### Software
- **Linux**: Debian/Ubuntu-based distribution (Kali, Parrot, Ubuntu, etc.)
- **Privileges**: Root/sudo access
- **Kernel**: 4.0+ recommended
- **Python**: 3.6+ (for main interface)

### Required Packages
- `hostapd` - Access point daemon
- `dnsmasq` - DHCP and DNS server
- `iptables` - Firewall and NAT
- `iw` - Wireless configuration
- `iproute2` - Network configuration
- `python3` - Main interface
- `colorama` - Terminal colors (Python)
- `rich` - Terminal UI (Python)

### Optional Packages
- `hostapd-wpe` - For WPA2 password capture
- `tcpdump` - For packet monitoring
- `aircrack-ng` - For advanced monitoring
- `ethtool` - For adapter information

### Recommended Wireless Adapters
**Excellent Compatibility:**
- Atheros chipsets (ath9k, ath10k)
- Intel chipsets (iwlwifi)
- MediaTek chipsets (mt76xx)

**Good Compatibility:**
- Ralink chipsets (rt2800)

**Limited/Poor:**
- Realtek chipsets (rtl8xxx) - often limited AP support
- Broadcom (limited support)

---

## 📦 Installation

### 1. Download the Project

```bash
# Clone repository
git clone https://github.com/yourusername/robowifi-ap.git
cd robowifi-ap

# Or download and extract
wget https://github.com/yourusername/robowifi-ap/archive/main.zip
unzip main.zip
cd robowifi-ap-main
```

### 2. Project Structure

Ensure your project has this structure:

```
robowifi-ap/
├── main.py                    # Main interface
├── setup.sh                   # Setup script
├── requirements.txt           # Python dependencies
├── README.md                  # This file
└── scripts/
    ├── fake_ap.sh            # Basic AP script
    ├── advanced_fake_ap.sh   # Advanced AP script
    └── fake_ap_detector.sh  # Defender script
```

### 3. Install Python Dependencies

```bash
# Install Python packages
pip3 install -r requirements.txt

# Or manually
pip3 install colorama rich
```

### 4. Run Setup (Two Options)

#### Option A: Through Main Interface (Recommended)
```bash
sudo python3 main.py
# Select option [0] Setup & Check Requirements
# Choose setup type (1, 2, or 3)
```

#### Option B: Direct Setup Script
```bash
# Basic installation
sudo ./setup.sh

# With password capture support
sudo ./setup.sh --with-wpe
```

### 5. Verify Installation

```bash
# Through main interface
sudo python3 main.py
# Select option [0] → option [3] Quick check

# Or directly
sudo python3 main.py
```

---

## 🚀 Quick Start

### Using Main Interface (Recommended)

```bash
# Launch main interface
sudo python3 main.py

# Follow the menu:
# 1. Accept disclaimer
# 2. Read tool guide
# 3. Choose your mode:
#    [0] Setup & Check Requirements
#    [1] Basic Fake Access Point
#    [2] Advanced Fake Access Point
#    [3] Rogue AP Detector
#    [4] Exit
```

### Direct Script Usage

#### Check Available Adapters
```bash
sudo ./scripts/fake_ap.sh list-adapters
```

#### Create Basic Open Network
```bash
sudo ./scripts/fake_ap.sh "FreeWiFi" 6 eth0
```

#### Create Network with Password Capture
```bash
sudo ./scripts/fake_ap.sh "CoffeeShop" 6 eth0 wlan0 --capture-auth
```

#### Create Hidden Network with Captive Portal
```bash
sudo ./scripts/advanced_fake_ap.sh "SecureNet" 11 eth0 --hide-ssid --captive-portal
```

#### Run Rogue AP Detector
```bash
sudo ./scripts/fake_ap_detector.sh --scan
sudo ./scripts/fake_ap_detector.sh --monitor wlan0
```

#### Stop Access Point
```bash
sudo ./scripts/fake_ap.sh stop eth0
```

#### Check Status
```bash
sudo ./scripts/fake_ap.sh status
```

---

## 📖 Usage

### Main Interface Options

```
[0] Setup & Check Requirements
    → Install dependencies, verify system, check adapters

[1] Basic Fake Access Point
    → Simple AP with password capture capability

[2] Advanced Fake Access Point
    → Full-featured AP with captive portal, monitoring, filtering

[3] Rogue AP Detector (Defender Mode)
    → Detect and defend against fake access points

[4] Exit
```

### Basic Fake AP - Command Line

**Syntax:**
```bash
sudo ./scripts/fake_ap.sh SSID CHANNEL UPLINK_IF [WLAN_IF] [OPTIONS]
```

**Parameters:**
| Parameter | Description | Example |
|-----------|-------------|---------|
| `SSID` | Network name (max 32 chars) | `"FreeWiFi"` |
| `CHANNEL` | WiFi channel (1-14) | `6` or `11` |
| `UPLINK_IF` | Internet interface or `none` | `eth0`, `enp1s0`, `none` |
| `WLAN_IF` | Wireless interface (auto-detect if omitted) | `wlan0` |

**Options:**
| Option | Description |
|--------|-------------|
| `--capture-auth` | Enable WPA2 password capture (requires hostapd-wpe) |
| `list-adapters` | Show all wireless adapters and capabilities |
| `status` | Show current AP status and statistics |
| `stop [UPLINK_IF]` | Stop the access point |
| `--help` | Display help message |

### Advanced Fake AP - Command Line

**Syntax:**
```bash
sudo ./scripts/advanced_fake_ap.sh SSID CHANNEL UPLINK_IF [WLAN_IF] [OPTIONS]
```

**Additional Options:**
| Option | Description |
|--------|-------------|
| `--monitor` | Enable packet monitoring with tcpdump |
| `--mac-filter` | Enable MAC address filtering |
| `--bandwidth-limit N` | Limit bandwidth to N KB/s per client |
| `--captive-portal` | Enable credential harvesting portal |
| `--hide-ssid` | Hide SSID broadcast (stealth mode) |
| `--adapter-check` | Check adapter capabilities |

### Rogue AP Detector - Command Line

**Syntax:**
```bash
sudo ./scripts/fake_ap_detector.sh [OPTIONS]
```

**Options:**
| Option | Description |
|--------|-------------|
| `--scan` | Quick scan for rogue APs |
| `--monitor [INTERFACE]` | Continuous monitoring mode |
| `--protect SSID BSSID` | Protect specific network |
| `--analyze LOGFILE` | Analyze captured logs |
| `--help` | Display help message |

---

## 🎯 Advanced Features

### 1. WPA2 Password Capture

Captures passwords from connecting clients (requires `hostapd-wpe`):

```bash
# Through main interface
sudo python3 main.py
# Select [1] or [2], then confirm authorization

# Direct usage
sudo ./scripts/fake_ap.sh "TestAP" 6 eth0 --capture-auth
```

**View captured passwords:**
```bash
cat /tmp/fakeap_auth_attempts.log
```

### 2. Captive Portal

Creates a fake login page to harvest credentials:

```bash
sudo ./scripts/advanced_fake_ap.sh "Free WiFi" 6 eth0 --captive-portal
```

**Access portal:** Open browser and navigate to `http://192.168.1.1`

**View captured credentials:**
```bash
cat /tmp/fakeap_portal_credentials.log
```

### 3. Packet Monitoring

Captures all wireless traffic:

```bash
sudo ./scripts/advanced_fake_ap.sh "MonitorAP" 6 eth0 --monitor
```

**View packet captures:**
```bash
ls -lh /tmp/fakeap_pcaps/
wireshark /tmp/fakeap_pcaps/capture_*.pcap
```

### 4. MAC Address Filtering

Control which devices can connect:

```bash
sudo ./scripts/advanced_fake_ap.sh "FilteredAP" 6 eth0 --mac-filter
```

**Add to whitelist:**
```bash
echo "AA:BB:CC:DD:EE:FF" >> /tmp/fakeap_mac_whitelist.txt
```

**Add to blacklist:**
```bash
echo "11:22:33:44:55:66" >> /tmp/fakeap_mac_blacklist.txt
```

### 5. Bandwidth Limiting

Limit speed per client (in KB/s):

```bash
sudo ./scripts/advanced_fake_ap.sh "SlowWiFi" 6 eth0 --bandwidth-limit 512
```

### 6. Hidden SSID

Create stealth access point:

```bash
sudo ./scripts/advanced_fake_ap.sh "HiddenNet" 6 eth0 --hide-ssid
```

### 7. Combined Advanced Features

Use multiple features together:

```bash
sudo ./scripts/advanced_fake_ap.sh "SecureAP" 6 eth0 wlan0 \
  --capture-auth \
  --monitor \
  --captive-portal \
  --bandwidth-limit 1024 \
  --hide-ssid \
  --mac-filter
```

### 8. Rogue AP Detection

Protect your network from fake APs:

```bash
# Quick scan
sudo ./scripts/fake_ap_detector.sh --scan

# Continuous monitoring
sudo ./scripts/fake_ap_detector.sh --monitor wlan0

# Protect specific network
sudo ./scripts/fake_ap_detector.sh --protect "MyNetwork" "AA:BB:CC:DD:EE:FF"
```

---

## 🔍 Monitoring and Logs

### Log File Locations

| File | Description |
|------|-------------|
| `/tmp/fakeap_auth_attempts.log` | WPA2 password captures |
| `/tmp/fakeap_portal_credentials.log` | Captive portal credentials |
| `/tmp/fakeap_monitor.log` | Packet monitoring statistics |
| `/tmp/hostapd_fakeap.log` | hostapd daemon log |
| `/tmp/dnsmasq_fakeap.log` | DHCP/DNS server log |
| `/tmp/fakeap_pcaps/` | Packet capture files (pcap format) |
| `/tmp/robowifi_setup_*.log` | Setup script logs |

### Real-time Monitoring

```bash
# Watch hostapd log
tail -f /tmp/hostapd_fakeap.log

# Watch authentication attempts
tail -f /tmp/fakeap_auth_attempts.log

# Watch captive portal captures
tail -f /tmp/fakeap_portal_credentials.log

# Check connected clients
cat /var/lib/misc/dnsmasq.leases
```

### Status and Statistics

```bash
# Full status report
sudo ./scripts/fake_ap.sh status

# Connected clients with ARP
arp -n | grep 192.168.1

# Traffic statistics
iptables -L -n -v

# Wireless interface info
iw dev wlan0 info
```

### Log Security

**⚠️ IMPORTANT:** Logs contain sensitive information!

```bash
# Secure log permissions (run after testing)
sudo chmod 600 /tmp/fakeap_*.log

# Delete logs after testing
sudo rm -f /tmp/fakeap_*.log
sudo rm -rf /tmp/fakeap_pcaps/

# Or use secure deletion
sudo shred -vfz -n 3 /tmp/fakeap_*.log
```

---

## 🛠️ Troubleshooting

### Common Issues

#### 1. "No wireless interface detected"

**Solution:**
```bash
# Check interfaces
ip link show
iw dev

# List compatible adapters
sudo ./scripts/fake_ap.sh list-adapters

# Check through main interface
sudo python3 main.py
# Select [0] → [3] Quick check
```

#### 2. "Adapter does not support AP mode"

**Problem:** Your wireless card doesn't support AP mode

**Solution:**
- Try a different USB port
- Check adapter compatibility: https://wireless.wiki.kernel.org
- Use recommended chipsets: Atheros, Intel, MediaTek
- Avoid Realtek chipsets (limited support)

#### 3. "hostapd process died unexpectedly"

**Solution:**
```bash
# Check hostapd log
cat /tmp/hostapd_fakeap.log

# Stop conflicting services
sudo systemctl stop NetworkManager
sudo pkill wpa_supplicant

# Check driver
ethtool -i wlan0
```

#### 4. "hostapd-wpe not found"

**Solution:**
```bash
# Install from repositories (Kali/Parrot)
sudo apt-get install hostapd-wpe

# Or through main interface
sudo python3 main.py
# Select [0] → [2] (Full setup + hostapd-wpe)

# Or build from source
git clone https://github.com/OpenSecurityResearch/hostapd-wpe
cd hostapd-wpe/hostapd-wpe
make
sudo make install
```

#### 5. "dnsmasq failed to start"

**Solution:**
```bash
# Check if port 53 is in use
sudo lsof -i :53

# Stop conflicting DNS services
sudo systemctl stop systemd-resolved

# Check dnsmasq log
cat /tmp/dnsmasq_fakeap.log
```

#### 6. "Permission denied" errors

**Solution:**
```bash
# Always run with sudo
sudo python3 main.py

# Or for direct scripts
sudo ./scripts/fake_ap.sh ...
```

#### 7. Clients can't connect / No DHCP lease

**Solution:**
```bash
# Check DHCP log
cat /tmp/dnsmasq_fakeap.log

# Verify interface is up
ip addr show wlan0

# Check iptables rules
iptables -L -n -v

# Verify IP forwarding (if using uplink)
cat /proc/sys/net/ipv4/ip_forward
# Should show: 1
```

#### 8. "Module not found" (Python errors)

**Solution:**
```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Or manually
pip3 install colorama rich
```

### Run System Diagnostics

```bash
# Through main interface (recommended)
sudo python3 main.py
# Select [0] → [3] Quick check

# Or run test script directly (if available)
sudo ./test.sh --quick    # Quick check
sudo ./test.sh --full     # Full diagnostic
```

### Complete Reset

```bash
# 1. Stop all services
sudo ./scripts/fake_ap.sh stop
sudo ./scripts/advanced_fake_ap.sh stop

# 2. Restart network services
sudo systemctl restart NetworkManager
sudo systemctl restart wpa_supplicant

# 3. Reboot if issues persist
sudo reboot
```

---

## ❓ FAQ

### Q: Is this legal?

**A:** **Only** on networks you **own** or have **written permission** to test. Unauthorized use is **illegal** and may result in criminal charges.

### Q: Which wireless adapters work best?

**A:** 
- **Best:** Atheros (ath9k), Intel (iwlwifi), MediaTek (mt76xx)
- **Good:** Ralink (rt2800)
- **Avoid:** Realtek (rtl8xxx) - limited AP mode support

Check compatibility: https://wikidevi.wi-cat.ru/

### Q: Can I capture WPA2 handshakes?

**A:** Yes, with `--capture-auth` and `--monitor` options. Use `aircrack-ng` or `hashcat` to crack captures.

### Q: Does this work in a virtual machine?

**A:** Limited support. USB passthrough works best. Built-in VM wireless adapters often don't support AP mode.

### Q: How do I crack captured password hashes?

**A:** 
```bash
# View captured data
cat /tmp/fakeap_auth_attempts.log

# Extract hash (if available)
grep "Hash:" /tmp/fakeap_auth_attempts.log > hash.txt

# Crack with hashcat
hashcat -m 5500 hash.txt wordlist.txt

# Or with aircrack-ng
aircrack-ng -w wordlist.txt capture.cap
```

### Q: Can clients detect this is a fake AP?

**A:** Possibly. Indicators include:
- Hidden SSID on known network
- Captive portal on familiar network
- Weak signal strength
- Different BSSID (MAC) than expected
- Certificate warnings (for HTTPS sites)

Use realistic configurations to avoid detection.

### Q: How do I make the AP persistent after reboot?

**A:** Not recommended for security reasons. If needed:
```bash
# Create systemd service (advanced users only)
sudo nano /etc/systemd/system/robowifi.service
```

### Q: Why isn't internet sharing working?

**A:** Check:
```bash
# 1. IP forwarding enabled
cat /proc/sys/net/ipv4/ip_forward  # Should be 1

# 2. NAT rules present
iptables -t nat -L -n -v

# 3. Uplink interface has internet
ping -I eth0 8.8.8.8

# 4. DNS is working
nslookup google.com
```

### Q: How do I update RoboWiFi-AP?

**A:**
```bash
# If using git
cd robowifi-ap
git pull

# Re-run setup if needed
sudo ./setup.sh
```

---

## 📚 Additional Resources

### Documentation
- [Hostapd Documentation](https://w1.fi/hostapd/)
- [Linux Wireless Wiki](https://wireless.wiki.kernel.org/)
- [Aircrack-ng Documentation](https://www.aircrack-ng.org/documentation.html)
- [Kali Linux Wireless Tools](https://www.kali.org/tools/)

### Wireless Adapter Databases
- [WikiDevi](https://wikidevi.wi-cat.ru/)
- [Linux Wireless Drivers](https://wireless.wiki.kernel.org/en/users/drivers)

### Security Testing Guides
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)

### Learning Resources
- [WiFi Security Fundamentals](https://www.sans.org/white-papers/)
- [Wireless Penetration Testing](https://www.offensive-security.com/metasploit-unleashed/)

---

## 📝 License

This tool is provided for **educational** and **authorized testing** purposes only.

**Use responsibly and legally.**

---

## 🤝 Contributing

Contributions are welcome! Please ensure:
- ✅ Proper error handling
- ✅ Clear code comments
- ✅ Security warnings included
- ✅ Documentation updated
- ✅ Testing on multiple systems

**Pull requests should:**
1. Follow existing code style
2. Include descriptive commit messages
3. Update documentation as needed
4. Add security warnings for new features

---

## 📧 Support

### Getting Help

1. **Check Documentation**: Read this README thoroughly
2. **Run Diagnostics**: Use setup option [0] → [3]
3. **Review Logs**: Check `/tmp/fakeap_*.log` and `/tmp/robowifi_setup_*.log`
4. **Search Issues**: Check if your issue is already reported
5. **Ask Community**: Open a GitHub issue with details

### Reporting Issues

Include:
- Operating system and version
- Wireless adapter model and chipset
- Full error messages
- Relevant log excerpts
- Steps to reproduce

---

## ⚠️ Final Warning

**This is a powerful security tool. Use it responsibly.**

- ✅ Get **written authorization** before any testing
- ✅ Test only on **networks you own**
- ✅ Comply with **local laws and regulations**
- ✅ **Secure and delete** logs after testing
- ✅ Report **vulnerabilities responsibly**
- ❌ **Never** use for unauthorized access
- ❌ **Never** share captured credentials
- ❌ **Never** target public networks without permission

**Remember: With great power comes great responsibility.**

---

**RoboWiFi-AP** - WiFi Security Assessment Framework  
*For authorized security testing and education only.*

🔐 Stay legal. Stay ethical. Stay secure.