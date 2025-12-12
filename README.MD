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
