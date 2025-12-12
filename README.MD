# NARC — Nmap Automated Report Creator

NARC (Nmap Automated Report Creator) is a Python-based command-line tool that automates Nmap scanning, applies analysis ready scan presets, and generates `.txt` deliverables suitable for security assessments, vulnerability reviews, and reports.

It is designed to bridge the gap between **raw network scanning** and **actionable analyst output**, with optional CVE enrichment using Nmap’s `vulners` NSE script.

---

## Features

- Interactive CLI workflow
- Scan presets: **stealth**, **standard**, **noisy**
- Flexible port selection:
  - Common ports
  - Top 100 / Top 1000
  - All ports
  - Custom ranges
- Optional CVE enrichment via **Vulners NSE**
- Generates timestamped `.txt` Nmap reports
- Clear, report-ready output suitable for pasting into assessments
- Windows-compatible

---

## Design Philosophy

NARC was built as a way to test both my understanding of Nmap and Python scripting while still having real world application:

- Use Nmap for discovery and service identification
- Enrich findings with known vulnerabilities (CVEs)
- Produce a **human-readable artifact**, not just raw data
- Leave final validation and risk assessment to a human analyst

This tool does **not** claim to confirm exploitable vulnerabilities.  
It surfaces **candidate findings** for analyst review.

---

##  Requirements

- **Python 3.10+**
- **Nmap** (installed locally)
- Optional: **Vulners API key** (for enhanced CVE results)

### Python dependencies
```bash
pip install python-nmap
```
---                                 

## Installation

Clone the repository:
```bash
git clone https://github.com/<your-username>/NARC.git
cd NARC
```

Ensure Nmap is installed and accessible:
```bash
nmap --version
```

(Optional) Set Vulners API key:
```bash
setx VULNERS_API_KEY "your_api_key_here"
```

Run the tool:
```bash
python narc.py
```
---
                                 
## Usage Flow

Enter a target:

- Single IP (192.168.1.10)
- CIDR range (192.168.1.0/24)
- Hostname (scanme.nmap.org)

Choose a scan preset:

- stealth — slower, minimal noise
- standard — balanced with service detection
- noisy — fast and aggressive

Choose port strategy:

- Common ports
- Top ports
- All ports
- Custom ranges

**(Optional) Add extra Nmap flags**

**(Optional) Enable Vulners CVE enrichment**

Run the scan and receive a .txt report:
```bash
narc_192.168.1.0_24_20251212_142233.txt
```
---
                                 
## Output Example

The generated report includes:

- Host discovery results
- Open ports and services
- Version information
- Vulners CVE listings (when enabled)
- CVSS scores and references

This output is intentionally formatted to match standard Nmap output, making it easy to:

- Paste into reports
- Attach to tickets
- Share with stakeholders
- Archive as evidence

```bash
# Nmap 7.98 scan initiated Fri Dec 12 12:43:45 2025 as: nmap -sS -T4 -n -A --top-ports 1000 --script vulners -oN .\\narc_scanme.nmap.org_20251212_124345.txt scanme.nmap.org
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.055s latency).
Other addresses for scanme.nmap.org (not scanned): 2600:3c01::f03c:91ff:fe18:bb2f
Not shown: 996 filtered tcp ports (no-response)
PORT      STATE SERVICE    VERSION
22/tcp    open  tcpwrapped
80/tcp    open  http       Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
| vulners: 
|   cpe:/a:apache:http_server:2.4.7: 
|     	*This is where the vulnerability list appears with possible vulnerabilities related to open and running services on a scanned device*
    -  VULNERABILITY 1
    -  VULNERABILITY 2
    -  VULNERABILITY 3
9929/tcp  open  nping-echo Nping echo
31337/tcp open  tcpwrapped
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, Linux 4.19, Linux 5.0 - 5.14, OpenWrt 21.02 (Linux 5.4), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 19 hops

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   1.00 ms  10.0.0.1
2   13.00 ms 100.92.136.2
3   15.00 ms 96.110.197.77
4   17.00 ms 96.108.82.62
5   15.00 ms 96.110.153.1
6   16.00 ms 96.110.153.1
7   18.00 ms 68.86.95.89
8   18.00 ms 68.86.95.93
9   ... 10
11  20.00 ms 23.209.172.71
12  20.00 ms 23.209.172.71
13  56.00 ms 23.207.232.39
14  56.00 ms 23.207.232.39
15  ... 18
19  57.00 ms 45.33.32.156

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Dec 12 12:44:02 2025 -- 1 IP address (1 host up) scanned in 17.72 seconds
```

---
                                 
## Permissions & Scan Types

Some scan types (e.g., -sS, -O) require elevated privileges on Windows.

If you encounter permission errors:

- Run PowerShell as Administrator, or
- Switch to -sT (TCP connect scan)

---
                                 
## Legal & Ethical Notice

This tool is intended only for:

- Systems you own
- Networks you administer
- Environments where you have explicit written authorization

Unauthorized scanning is illegal and unethical.

---
                                 
## Future Enhancements

Planned or possible extensions:

- JSON / CSV structured output
- Service-to-CPE confidence scoring
- Analyst notes section in reports
- Comparison scans (detect new services over time)
- SIEM or ticketing system integration

---
                                 
## Author

Brayden Arnold
Cybersecurity | IT | Automation
Portfolio project demonstrating network discovery, vulnerability enrichment, and report-focused tooling.

---
                                 
## License

MIT License
