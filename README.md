# WiFi Security Assessment Tool

> **⚠️ LEGAL WARNING**: This tool is for **authorized security testing only**. Unauthorized use may violate federal and state laws including the Computer Fraud and Abuse Act (CFAA). Always obtain written permission before testing.

## 🎯 Purpose

This tool is designed for **authorized security professionals** to:
- Assess WiFi security configurations
- Test wireless network defenses
- Demonstrate attack vectors in controlled environments
- Train security teams on wireless threats

## ⚖️ Legal & Ethical Use

### You MUST Have:
- ✅ **Written authorization** from network owner
- ✅ **Documented scope** with clear boundaries
- ✅ **Legal approval** from organization's counsel
- ✅ **User notification** plan or informed consent

### Prohibited Uses:
- ❌ Testing networks without permission
- ❌ Capturing credentials from unsuspecting users
- ❌ Creating fake versions of public networks
- ❌ Any unauthorized security testing

## 📋 Prerequisites

### System Requirements
- Linux-based OS (Ubuntu 20.04+, Kali, Debian)
- Wireless adapter supporting AP/monitor mode
- Root/sudo access
- Minimum 2GB RAM

### Required Packages
```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y \
  hostapd \
  hostapd-wpe \
  dnsmasq \
  iptables \
  iw \
  wireless-tools \
  net-tools \
  gpg

# Additional for Kali Linux
sudo apt-get install -y aircrack-ng
```

### Compatible Wireless Adapters
Adapters that support AP mode (check with `iw list`):
- Atheros AR9271 (common in penetration testing)
- Ralink RT3070/RT5370
- Realtek RTL8812AU
- Intel wireless cards (some models)

Test with: `iw list | grep -A 10 "Supported interface modes"`

## 🚀 Installation

1. **Clone or download** the script:
```bash
chmod +x fake_ap.sh
```

2. **Verify wireless adapter** supports AP mode:
```bash
iw list | grep "Supported interface modes" -A 10
```

3. **Install dependencies**:
```bash
sudo apt-get install hostapd hostapd-wpe dnsmasq iw iptables
```

4. **IMPORTANT**: Review and implement ethical safeguards from the [Ethical Use Guide](./ETHICAL_USE.md)

## 📖 Usage

### Basic Syntax
```bash
sudo ./fake_ap.sh SSID CHANNEL UPLINK_IF [WLAN_IF] [--capture-auth]
```

### Authorized Testing Example
```bash
# Open test network (recommended for most testing)
sudo ./fake_ap.sh "TEST-SecAudit-2024" 6 eth0

# With password capture (requires written authorization)
sudo ./fake_ap.sh "PENTEST-Demo" 11 eth0 wlan0 --capture-auth
```

### Management Commands
```bash
# Check status
sudo ./fake_ap.sh status

# Stop the AP
sudo ./fake_ap.sh stop

# View help
sudo ./fake_ap.sh --help
```

## 🔒 Security Best Practices

### For Ethical Testing:

1. **Always use identifiable SSIDs**:
   - Prefix with `TEST-`, `PENTEST-`, or `SECURITY-TEST-`
   - Never impersonate legitimate networks

2. **Implement user warnings**:
   - Use captive portals with clear warnings
   - Post physical signs near test area
   - Notify users via email/announcements

3. **Protect captured data**:
   - Encrypt all logs immediately
   - Use access controls (chmod 600)
   - Destroy data after analysis
   - Never share credentials

4. **Limit test duration**:
   - Set automatic shutoff timers
   - Use minimum time needed
   - Document exact testing windows

5. **Maintain audit trails**:
   - Log all actions with timestamps
   - Record authorization details
   - Keep evidence of proper authorization

## 📊 Output Files

- `/tmp/hostapd_fakeap.log` - Access point logs
- `/tmp/dnsmasq_fakeap.log` - DHCP server logs
- `/tmp/fakeap_auth_attempts.log` - Authentication attempts (encrypt this!)
- `/tmp/fakeap_state.txt` - Current configuration

**Always encrypt sensitive logs before storage or transmission.**

## 🛡️ Defensive Recommendations

Based on testing, recommend to clients:

1. **Use WPA3** where possible
2. **Implement 802.1X** for enterprise networks
3. **Enable certificate validation** on client devices
4. **Train users** to recognize suspicious networks
5. **Use VPNs** for sensitive communications
6. **Monitor for rogue APs** regularly
7. **Disable auto-connect** features

## 🐛 Troubleshooting

### "No wireless interface detected"
- Verify adapter is connected: `iwconfig`
- Check driver support: `lsmod | grep wireless`
- Try specifying interface: `sudo ./fake_ap.sh "TEST" 6 eth0 wlan0`

### "Interface does not support AP mode"
- Not all adapters support AP mode
- Check capabilities: `iw list`
- Consider using a compatible USB adapter

### "hostapd-wpe not found"
- Install: `sudo apt-get install hostapd-wpe`
- Or disable capture mode for basic testing

### "iptables rules not working"
- Check forwarding: `cat /proc/sys/net/ipv4/ip_forward`
- Verify uplink is connected and has internet
- Check firewall rules: `sudo iptables -L -n -v`

## 📚 Educational Resources

- [OWASP Wireless Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Wireless Network Security Guidelines](https://www.nist.gov/wireless-security)
- [SANS WiFi Penetration Testing](https://www.sans.org/courses/)
- [Offensive Security OSWP Certification](https://www.offensive-security.com/wireless-professional-oswp/)

## ⚠️ Disclaimer

This tool is provided for **educational and authorized security testing purposes only**. 

**The authors and contributors:**
- Do NOT condone illegal use of this tool
- Are NOT responsible for misuse or damages
- Assume NO liability for unauthorized testing
- Strongly advocate for responsible disclosure

**Users are solely responsible for:**
- Obtaining proper authorization
- Complying with all applicable laws
- Using the tool ethically and legally
- Any consequences of misuse

By using this tool, you agree to use it only in authorized, legal, and ethical ways.

## 📄 License

MIT License

Copyright (c) 2024 [Your Name/Organization]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

**Additional Terms**: This software may not be used for any illegal purpose. Users must comply with all applicable laws and regulations.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## 🤝 Contributing

Contributions that improve security, add ethical safeguards, or enhance educational value are welcome.

**We will NOT accept contributions that:**
- Make the tool stealthier or harder to detect
- Remove authorization checks
- Facilitate misuse
- Violate ethical hacking principles

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/ethical-improvement`)
3. Commit your changes (`git commit -am 'Add ethical safeguard'`)
4. Push to the branch (`git push origin feature/ethical-improvement`)
5. Create a Pull Request

## 📧 Contact

For responsible disclosure of issues or ethical concerns:
- Email: security@yourdomain.com
- PGP Key: [Your PGP key fingerprint]

For general questions:
- Open an issue on GitHub
- Join our security research community

---

**Remember**: The difference between a security professional and a criminal is authorization. Always get it in writing.

## 🙏 Acknowledgments

- Security research community for ethical hacking practices
- Open source contributors to hostapd, dnsmasq, and related tools
- Organizations promoting responsible disclosure

## 📜 Version History

- **v1.0.0** (2024-12) - Initial release with ethical safeguards
  - Authorization checkpoint implementation
  - Audit logging features
  - Data encryption support
  - Automatic shutoff timers

---

*This tool is for educational and authorized security testing only. Use responsibly.*