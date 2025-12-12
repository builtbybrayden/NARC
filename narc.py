import os
os.environ["PATH"] += r";C:\Program Files (x86)\Nmap"

import re
import subprocess
import sys
import textwrap
import nmap
from datetime import datetime

FLAG_HELP = {
    "-sS": "TCP Syn scan ('stealthy'), requires admin privileges, fast & common",
    "-sT": "TCP Connect scan, works without admin, noisier on target",
    "-sU": "UDP scan (slow), useful for services like DNS(53), NTP (123), SNMP(161), etc.",
    "-sV": "Service & version detection on open ports (adds traffic & time)",
    "-O": "OS detection (can be unreliable through firewalls & NAT)",
    "-A": "Agressive, sets -sV, -O, traceroute, and some scripts (very noisy)",
    "-Pn": "Treats all hosts as up (skips host discovery), useful when ping is blocked",
    "-n": "No DNS resolution, faster & less traffic",
    "-T2": "Timing: slow/polite (less network load & noise)",
    "-T3": "Timing: normal (default speed)",
    "-T4": "Timing: faster (common for internal scans)",
    "-T5": "Timing: very fast (noisy, can miss results or affect some networks)",
    "--top-ports": "Scan top N most common ports (e.g., --top ports 100)",
    "-p": "Specify ports (e.g., -p 22,80,443 or -p 1-1024)",
    "-p-": "All 65535 TCP ports (slow)",
}

PRESETS = {
    "stealth": {
        "arguments": "-sS -T2 -n",
        "default_ports_mode": "top_100",
        "notes": "Lower speed, minimal extra requests, good for cautious recon but is still detectable"
    },
    "standard": {
        "arguments": "-sS -T3 -n -sV",
        "default_ports_mode": "top_1000",
        "notes": "Balanced scan with service detection, good default for most cases"
    },
    "noisy": {
        "arguments": "-sS -T4 -n -A",
        "default_ports_mode": "top_1000",
        "notes": "Fast & agressive detection, loud and can trigger alerts & throttling"
    }
}

PORT_MODES = {
    "common_1k": ("", "Defaults Nmap common port set (roughly top ~1000)"),
    "top_100": ("--top-ports 100", "Top 100 most common ports"),
    "top_1000": ("--top-ports 1000", "Top 1,000 most common ports"),
    "all": ("-p-", "All TCP ports 1-65535 (slow)"),
    "specific": ("", "Enter port & ranges manually (e.g., 22,80,443 or 1-1024)"),
}

def print_flag_guide():
    print("\n Flag guide (common & useful flags):")
    for flag, desc in FLAG_HELP.items():
        print (f"  {flag:10} {desc}")

def choose(prompt, options):
    """Simple numbered menu chooser"""
    keys = list(options.keys())
    print(f"\n{prompt}")
    for i, k in enumerate(keys, 1):
        print(f"  {i}) {k} - {options[k]}")
    while True:
        choice = input("Select a number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(keys):
            return keys[int(choice) - 1]
        print("Invalid choice, try again")

def safe_filename(s: str) -> str:
    s = s.strip().replace("/", "_")
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:80]

def run_nmap_to_txt(target: str, args: str, output_dir: str = ".") -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_name = f"narc_{safe_filename(target)}_{ts}.txt"
    out_path = os.path.join(output_dir, out_name)

    # Build command: namp <args> -oN <file> <target>
    cmd = ["nmap", *args.split(), "-oN", out_path, target]

    print("\nRunning command:")
    print(" ".join(cmd))

    proc = subprocess.run(cmd, text=True, capture_output=True)

    if proc.returncode != 0:
        print("\nNmap failed. stderr:\n")
        print(proc.stderr)
        raise RuntimeError("Nmap scan failed (see stderr above)")
    
    print(f"\nSaved report: {out_path}")
    return out_path

def main():
    print("NARC - Nmap Automated Report Creator")
    print("Use only on systems & networks you own or have explicit permission to test.\n")

    target = input("enter target (IP, CIDR, hostname) Examples: 192.168.1.10 | 192.168.1.0/24 | scanme.nmap.org\n> ").strip()
    if not target:
        print("No target provided. Exiting")
        sys.exit(1)

    # Preset selection
    print("\nPresets:")
    for name, p in PRESETS.items():
        print(f"  - {name:8} {p['notes']}")
    preset = input("\nChoose preset [stealth/standard/noisy] (default = standard): ").strip().lower() or "standard"
    if preset not in PRESETS:
        print("unknown preset. Using standard.")
        preset = "standard"
    
    # Flag guide
    want_help = input("\nDo you want to see a quick flag guide? [y/N]: ").strip().lower()
    if want_help == "y":
        print_flag_guide()
    
    # Port mode
    default_port_mode = PRESETS[preset]["default_ports_mode"]
    print("\nPort Options:")
    print("  1) common_1k    - common ports (Nmap default set)")
    print("  2) top_100      - top 100 ports")
    print("  3) top_1000     - top 1,000 ports")
    print("  4) all          - all TCP ports")
    print("  5) specific     - enter ports/ranges")
    port_mode = input(f"\nChoose port mode (default={default_port_mode}): ").strip().lower() or default_port_mode
    if port_mode not in PORT_MODES:
        print("Unknown port mode. Using default")
        port_mode = default_port_mode
    
    port_args = PORT_MODES[port_mode][0]
    if port_mode == "specific":
        ports = input("Enter ports (e.g., 22,80,443 or 1-1024): ").strip()
        if not ports:
            print("No ports provided, falling back to common ports")
            port_mode = "common_1k"
            port_args = PORT_MODES[port_mode][0]
        else:
            port_args = f"-p {ports}"
    
    # Extra flags
    extra = input("\nOptional: enter extra Nmap flags (or press enter), Example: -Pn or -sU\n> ").strip()

    # Vulnerability scan
    use_vulners = input("\nEnable Vulners CVE lookup to search for possible vulnerabilities? (Not effective on stealth) [y/N]: ").strip().lower() == "y"

    # Build final argument string
    base_args = PRESETS[preset]["arguments"]
    final_args = " ".join(x for x in [base_args, port_args, extra] if x).strip()
    if use_vulners:
        if "-sV" not in final_args and "-A" not in final_args:
            final_args += " -sV"
        final_args += " --script vulners"

    print("\n --- Planned Scan ---")
    print(f"Target: {target}")
    print(f"Preset: {preset} ({PRESETS[preset]['notes']})")
    print(f"Args:   {final_args}")

    # Execute scan
    run = input("\nRun scan now and write .txt report? [y/N]: ").strip().lower()
    if run != "y":
        print("Cancelled")
        return
    
    try:
        report_path = run_nmap_to_txt(target, final_args, output_dir=".")
    except RuntimeError:
        print("\nCommon fixes:")
        print(" - If using -sS / -O on Windows, run PowerShell as Administrator or switch to -sT.")
        print(" - Ensure Nmap is installed and accessible (PATH).")
        return
    
    print("\nDone. Report created:")
    print(report_path)
    
if __name__ == "__main__":
    main()
