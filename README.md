# ⬡ PENTRAX v8.0
### **WEB VULNERABILITY ASSESSMENT & SECURITY PLATFORM**

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Version](https://img.shields.io/badge/version-8.0-red.svg)

---

## 🎯 Overview

**PENTRAX** is a production-grade web vulnerability assessment and network security scanner that combines port scanning with automated service fingerprinting, CVE vulnerability matching, safe PoC verification, attack path analysis, and MITRE ATT&CK mapping. Built with an asynchronous engine and a real-time web operations dashboard.

---

## ✨ Key Features

### 🚀 **Performance**
- **Asyncio-powered** — 10,000+ concurrent connections
- **Multi-phase scanning** — Host discovery → Port scan → Version detection → Deep intel → Verification
- **Adaptive rate limiting** — Automatically adjusts to network conditions
- **Checkpoint/Resume** — Resume interrupted scans

### 🔍 **Scanning Capabilities**
- **7 Scan Types**: CONNECT, SYN, ACK, FIN, XMAS, NULL, WINDOW
- **Full port range** — All 65535 TCP ports + UDP scanning
- **500+ service fingerprints** — Accurate service identification
- **Version detection** — Automatic version fingerprinting
- **OS fingerprinting** — TTL/window-based OS detection

### 🛡️ **Security Features**
- **Stealth mode** — Decoy scanning, packet fragmentation, random delays
- **Evasion techniques** — Random delays, packet fragmentation, decoy IPs
- **Authorization gate** — Prevents accidental scanning of unauthorized targets
- **IPv6 support** — Full IPv6 scanning support

### 🎯 **Vulnerability Detection**
- **CVE database** — Automatic CVE matching with CVSS scoring
- **CIS benchmarks** — Compliance mapping with remediation guidance
- **Attack path analysis** — MITRE ATT&CK technique mapping
- **Threat actor attribution** — Real-world campaign mapping (WannaCry, NotPetya, etc.)

### 🔬 **Deep Intel Probes**
- **SSH** — Weak algorithm detection (DH Group1, DSA, 3DES, RC4, MD5)
- **Redis** — Authentication testing, SLAVEOF RCE detection
- **MongoDB** — Authentication testing, version detection
- **SMB** — EternalBlue (MS17-010) detection
- **Memcached** — DDoS amplification testing
- **FTP** — Anonymous login testing
- **Elasticsearch** — Authentication testing
- **Docker API** — Unauthenticated API access testing

### 📊 **Reporting**
- **JSON** — Machine-readable output
- **CSV** — Spreadsheet-compatible
- **HTML** — Professional HTML reports with dark theme
- **Audit logging** — Complete scan audit trail

---

## 🚀 Quick Start

### **Installation**

```bash
# Clone the repository
git clone https://github.com/yourusername/yerscan.git
cd yerscan

# Install dependencies (none required - pure Python!)
# Yerscan uses only Python standard library

# Make executable
chmod +x yerscan.py

# Run self-test
python3 yerscan.py --self-test
```

### **Web Console Quick Start (Graduation Edition)**

Launch the full-featured, real-time web console with a single command:

```bash
# Start the web platform (default: http://127.0.0.1:8080)
python3 run_server.py --host 127.0.0.1 --port 8080

# Or launch with elevated privileges to unlock raw SYN/ACK/FIN scans:
sudo python3 run_server.py --host 127.0.0.1 --port 8080
```
Open **`http://127.0.0.1:8080`** in your browser to access the SOC Security Operations Dashboard with live WebSockets, MITRE ATT&CK attack path topology graphs, and one-click report exports.

### **CLI Basic Usage**

```bash
# Quick scan (top 50 ports)
sudo python3 yerscan.py 192.168.1.0/24 --quick

# Standard scan (top 100 ports)
sudo python3 yerscan.py 192.168.1.0/24 --fast

# Full scan (all 65535 ports)
sudo python3 yerscan.py 192.168.1.0/24 --full

# With vulnerability verification
sudo python3 yerscan.py 192.168.1.0/24 --full --verify
```

---

## 📖 Usage Examples

### **1. Quick Network Reconnaissance**
```bash
# Scan top 50 ports on entire /24 network
sudo python3 yerscan.py 192.168.1.0/24 --quick

# Output: Fast scan with top 50 ports, ~30 seconds
```

### **2. Stealth Scanning with Evasion**
```bash
# Stealth mode with decoys and fragmentation
sudo python3 yerscan.py 192.168.1.0/24 \
  --stealth \
  --decoy RND,RND,RND \
  --mtu 24 \
  --max-delay 2.0
```

### **3. Full Vulnerability Assessment**
```bash
# Complete scan with verification
sudo python3 yerscan.py 192.168.1.0/24 \
  --full \
  --verify \
  -o security_assessment
```

### **4. Targeted Service Scanning**
```bash
# Scan specific ports only
sudo python3 yerscan.py 192.168.1.0/24 \
  -p 22,80,443,3306,3389 \
  --verify
```

### **5. UDP Scanning**
```bash
# Scan UDP ports
sudo python3 yerscan.py 192.168.1.0/24 --udp --verify
```

### **6. Resume Interrupted Scan**
```bash
# Start scan with checkpoint
sudo python3 yerscan.py 192.168.1.0/24 \
  --full \
  --checkpoint scan_checkpoint.json

# Resume later
sudo python3 yerscan.py 192.168.1.0/24 \
  --resume scan_checkpoint.json
```

### **7. Different Scan Types**
```bash
# SYN scan (stealth, requires root)
sudo python3 yerscan.py 192.168.1.0/24 -s syn

# FIN scan (bypasses stateful firewalls)
sudo python3 yerscan.py 192.168.1.0/24 -s fin

# XMAS scan (bypasses stateless firewalls)
sudo python3 yerscan.py 192.168.1.0/24 -s xmas

# NULL scan (bypasses packet filters)
sudo python3 yerscan.py 192.168.1.0/24 -s null

# ACK scan (firewall rule detection)
sudo python3 yerscan.py 192.168.1.0/24 -s ack

# WINDOW scan (window size analysis)
sudo python3 yerscan.py 192.168.1.0/24 -s window
```

### **8. Plugin System**
```python
# Create custom plugin: my_plugin.py
def pre_scan(target, hosts, ports):
    print(f"[PLUGIN] Starting scan of {target}")
    print(f"[PLUGIN] {len(hosts)} hosts, {len(ports)} ports")

def per_host(ip, ports):
    print(f"[PLUGIN] Scanning {ip} with {len(ports)} ports")

def post_scan(results, host_info):
    print(f"[PLUGIN] Found {len(results)} hosts with open ports")
    for ip, ports in results.items():
        print(f"  {ip}: {len(ports)} open ports")

def per_vuln(ip, port, vuln):
    print(f"[PLUGIN] VULN: {ip}:{port} - {vuln}")
```

```bash
# Run with plugin
sudo python3 yerscan.py 192.168.1.0/24 --verify --script my_plugin.py
```

---

## 📊 Output Examples

### **Terminal Output**
```
  ╔══════════════════════════════════════════════════════════════════════╗
  ║                                                                      ║
  ║   ░█░█░█▀▀░█▀▄░█▀▀░█▀▀░█▀█░█▀█░█▀▀  v8.0 — Production Grade  ║
  ║   ░░█░░█▀▀░█▀▄░▀▀█░█░░░█▀█░█░█░█▀▀                              ║
  ║   ░░▀░░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀░▀░▀░▀░▀▀▀                              ║
  ║                                                                      ║
  ║   SYN/ACK/FIN/XMAS/NULL · CVE+CVSS · CIS · Plugins · Resume · IPv6 ║
  ╚══════════════════════════════════════════════════════════════════════╝

  Target:         192.168.1.0/24
  Hosts:          254
  TCP Ports:      65535 (1-65535)
  Scan Type:      SYN
  Concurrency:    5000 sockets
  Timeout:        1.5s
  Deep Intel:     ENABLED
  Verification:   ENABLED

  [PHASE 1/5] HOST DISCOVERY — ICMP Ping Sweep (254 hosts)
  ● 192.168.1.1 is alive (ICMP)
  ● 192.168.1.10 is alive (ICMP)
  ● 192.168.1.20 is alive (ICMP)
  ✓ Found 3 live host(s)

  [PHASE 2/5] PORT SCAN (SYN) (3 hosts × 65535 ports = 196605 checks)
  [██████████████████████████████████████████████████] 100.0%  47 open  196558 filtered  0 closed  1500/s  ETA 0m00s

  ✓ Found 47 open port(s) on 3 host(s)

  [PHASE 3/5] VERSION DETECTION & CVE MATCHING (47 services)
  ✓ Detected versions for 47 services
  ⚠ Found 3 CVE matches!

  [PHASE 4/5] DEEP INTEL — Service Enumeration (47 services)
  ✓ Deep probed 47 services

  [PHASE 5/6] VULNERABILITY VERIFICATION — Safe PoC Checks
  ✓ 192.168.1.10: 2/3 vulnerabilities confirmed
  ✓ Verification complete: 2/3 vulnerabilities confirmed

  [PHASE 6/6] RISK ANALYSIS & OS FINGERPRINTING
  ✓ Risk analysis complete

  ══════════════════════════════════════════════════════════════════════
    ✓ SCAN COMPLETE
  ══════════════════════════════════════════════════════════════════════

  Duration:       127.3s
  Hosts alive:    3
  Hosts w/ports:  3
  Open ports:     47 (0 UDP)
  CVEs found:     3
  Vulns found:    2
  Risk:           1 CRITICAL  1 HIGH

  ▸ 192.168.1.10  [CRITICAL 90pts]  5 open
     445/tcp  open  SMB  [CRITICAL]
       ├─ CVE: MS17-010 (CVSS 9.8) — EternalBlue SMB RCE
       ├─ CIS 9.2.5: Ensure SMB is restricted (Level 1)
       └─ Fix: Disable SMBv1, restrict to trusted networks
     6379/tcp  open  Redis  [CRITICAL]
       ├─ CVE: CVE-2021-32625 (CVSS 8.8) — Redis integer overflow
       ├─ CIS Custom: Ensure Redis requires auth (Level 1)
       └─ Fix: Set requirepass, bind to localhost

    ATTACK PATHS (2 found, exploitability: 192/100):
      445/EternalBlue SMB RCE [TRIVIAL] [CATASTROPHIC] Score: 100
        Campaigns: WannaCry (2017), NotPetya (2017)
        Attack: SMB Exploit → SYSTEM Shell → Credential Dump → Lateral Movement
        MITRE: T1210 - Exploitation of Remote Services
        Tools: metasploit: exploit/windows/smb/ms17_010_eternalblue
        Threat Actors: Lazarus Group (DPRK), Sandworm (Russia)

  Reports saved:
    • security_assessment.json
    • security_assessment.csv
    • security_assessment.html
```

### **JSON Output**
```json
{
  "target": "192.168.1.0/24",
  "scan_time": "2026-08-07T03:47:39",
  "duration_seconds": 127.3,
  "scan_type": "syn",
  "ports_scanned": 65535,
  "hosts_alive": 3,
  "hosts_with_ports": 3,
  "total_open_ports": 47,
  "cves_found": 3,
  "vulns_found": 2,
  "results": {
    "192.168.1.10": {
      "mac": "00:11:22:33:44:55",
      "risk_score": 90,
      "risk_level": "CRITICAL",
      "ports": [
        {
          "port": 445,
          "protocol": "tcp",
          "state": "open",
          "service": "SMB",
          "version": "Windows Server 2012 R2",
          "risk_level": "CRITICAL",
          "cves": [
            {
              "cve": "MS17-010",
              "severity": "CRITICAL",
              "cvss_score": 9.8,
              "description": "EternalBlue SMB RCE"
            }
          ]
        }
      ]
    }
  }
}
```

---

## 🎯 Scan Presets

| Preset | Ports | Speed | Use Case |
|--------|-------|-------|----------|
| `--quick` | Top 50 | Fast | Quick reconnaissance |
| `--fast` | Top 100 | Fast | Standard scanning |
| `--stealth` | Top 100 | Slow | Evasive scanning |
| `--thorough` | All 65535 | Slow | Complete assessment |
| `--full` | All 65535 + UDP | Slow | Comprehensive scan |
| `--vuln` | All 65535 | Slow | Vulnerability focus |

---

## 🔧 Advanced Options

### **Timing Templates**
```bash
# T0 - Paranoid (very slow, very stealthy)
sudo python3 yerscan.py 192.168.1.0/24 --timing T0

# T1 - Sneaky (slow, stealthy)
sudo python3 yerscan.py 192.168.1.0/24 --timing T1

# T2 - Polite (moderate)
sudo python3 yerscan.py 192.168.1.0/24 --timing T2

# T3 - Normal (default)
sudo python3 yerscan.py 192.168.1.0/24 --timing T3

# T4 - Aggressive (fast)
sudo python3 yerscan.py 192.168.1.0/24 --timing T4

# T5 - Insane (very fast)
sudo python3 yerscan.py 192.168.1.0/24 --timing T5
```

### **Evasion Techniques**
```bash
# Decoy scanning (spoof source IP)
sudo python3 yerscan.py 192.168.1.0/24 --decoy RND,RND,RND

# Packet fragmentation (bypass IDS)
sudo python3 yerscan.py 192.168.1.0/24 --mtu 24

# Random delays (avoid detection)
sudo python3 yerscan.py 192.168.1.0/24 --max-delay 3.0

# Shuffle port order
sudo python3 yerscan.py 192.168.1.0/24 --shuffle
```

### **Output Formats**
```bash
# JSON only
sudo python3 yerscan.py 192.168.1.0/24 -f json -o scan_results

# CSV only
sudo python3 yerscan.py 192.168.1.0/24 -f csv -o scan_results

# HTML only
sudo python3 yerscan.py 192.168.1.0/24 -f html -o scan_results

# All formats
sudo python3 yerscan.py 192.168.1.0/24 -f all -o scan_results
```

---

## 🛡️ Vulnerability Detection

### **Supported Vulnerabilities**

| Service | Port | Vulnerability | Risk |
|---------|------|---------------|------|
| SMB | 445 | EternalBlue (MS17-010) | CRITICAL |
| Redis | 6379 | No Authentication RCE | CRITICAL |
| MongoDB | 27017 | No Authentication | CRITICAL |
| Memcached | 11211 | DDoS Amplification | CRITICAL |
| SSH | 22 | Weak Algorithms | HIGH |
| FTP | 21 | Anonymous Login | HIGH |
| Elasticsearch | 9200 | No Authentication | CRITICAL |
| Docker API | 2375 | Unauthenticated API | CRITICAL |

### **MITRE ATT&CK Mapping**

| Technique ID | Technique Name | Mapped Services |
|--------------|----------------|-----------------|
| T1210 | Exploitation of Remote Services | SMB, Redis, MongoDB |
| T1021.002 | SMB/Windows Admin Shares | SMB |
| T1190 | Exploit Public-Facing Application | Redis, MongoDB, Elasticsearch |
| T1059.004 | Unix Shell | Redis, MongoDB |
| T1078.001 | Default Accounts | FTP, SNMP |
| T1498.002 | Reflection Amplification | Memcached, SNMP |

---

## 📋 Command Reference

```
usage: yerscan.py [options] target

Positional Arguments:
  target                    Target IP, CIDR, or hostname

Scan Options:
  -p, --ports PORTS         Port specification (default: all)
  --top N                   Scan top N ports
  --udp                     Enable UDP scanning
  -s, --scan-type TYPE      Scan type: connect/syn/ack/fin/xmas/null/window
  -c, --concurrency N       Concurrent connections (default: 5000)
  -T, --timeout SECONDS     Connection timeout (default: 1.5)
  --timing T0-T5            Timing template

Discovery:
  --icmp                    Use ICMP ping sweep
  --no-banner               Skip banner grabbing
  --no-mac                  Skip MAC address resolution

Advanced:
  --deep                    Enable deep intel probes
  --verify                  Enable vulnerability verification
  --decoy IPS               Decoy IPs (comma-separated or RND)
  --mtu N                   Packet fragmentation MTU
  --max-delay SECONDS       Maximum random delay
  --shuffle                 Shuffle port order
  --exclude IPS             Exclude IPs (comma-separated)
  --scope FILE              Allowlist file (one CIDR/IP per line); targets outside it abort the scan
  --authorize               Confirm authorization to scan public targets

Output:
  -o, --output FILE         Output filename base
  -f, --format FORMAT       Output format: json/csv/html/all
  --log FILE                Audit log file

Presets:
  --quick                   Quick scan (top 50 ports)
  --fast                    Fast scan (top 100 ports)
  --stealth                 Stealth mode with evasion
  --thorough                Thorough scan (all ports)
  --full                    Full scan (all ports + UDP)
  --vuln                    Vulnerability-focused scan

Other:
  --self-test               Run self-test suite
  --checkpoint FILE         Save checkpoint file
  --resume FILE             Resume from checkpoint
  --config FILE             Load configuration file
  --save-profile FILE       Save current configuration
  -y, --yes                 Auto-confirm warnings
  -h, --help                Show help message
```

---

## 🔒 Security Considerations

### **Authorization**
Always ensure you have proper authorization before scanning:
- Written permission from network owner
- Documented scope and purpose
- Defined testing window
- Emergency contact information

### **Legal Compliance**
- **Never scan networks you don't own or have explicit permission to test**
- **Document all scanning activities**
- **Follow responsible disclosure practices**
- **Comply with local laws and regulations**

### **Ethical Guidelines**
- Use only for legitimate security assessments
- Never use for malicious purposes
- Report vulnerabilities responsibly
- Respect privacy and confidentiality

---

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

### **Running the tests**
```bash
# No privileges needed (raw-socket tests are skipped)
python3 -m unittest discover -s tests -v

# Also run raw SYN/ACK/FIN/NULL/XMAS/WINDOW tests on loopback
sudo python3 -m unittest discover -s tests -v
```

### **Known limitations**
- Raw TCP scan types (SYN, ACK, FIN, NULL, XMAS, WINDOW) are IPv4-only. IPv6 targets use connect semantics.
- Window scan: Linux answers open ports with RST and window 0, so it reports them as closed. It is most useful against stacks that report a non-zero window.
- CVE matching uses a small curated table with version ranges. Banner matches are not confirmed vulnerabilities. MS17-010 is inferred from the OS name and is not verified.
- Attack paths are marked `POTENTIAL` unless a verification probe or deep-probe finding confirms them.

### **Development Guidelines**
- Follow PEP 8 style guide
- Add docstrings to all functions
- Write unit tests for new features
- Update documentation

---

## 📄 License

MIT License - see LICENSE file for details

---

## 🙏 Acknowledgments

- **nmap** — Inspiration for scanning techniques
- **MITRE ATT&CK** — Attack technique mapping
- **CVE Details** — Vulnerability database
- **CIS Benchmarks** — Compliance standards

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/yerscan/issues)
- **Documentation**: [Wiki](https://github.com/yourusername/yerscan/wiki)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/yerscan/discussions)

---

## 🎓 Learning Resources

- [Nmap Network Scanning](https://nmap.org/book/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [CVE Details](https://www.cvedetails.com/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

---

**Built with ❤️ for the security community**

*Remember: With great power comes great responsibility. Use responsibly and ethically.*
