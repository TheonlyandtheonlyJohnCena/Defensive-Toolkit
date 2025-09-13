#!/usr/bin/env python3
"""
Cybersecurity Engineer: ToolKit (defensive)
Author: Zayne Bowen
Purpose: Defensive / educational toolkit for local systems you own.

Features:
- Local-only port scan (non-invasive banner grabs)
- Password audit from file or interactive input
- Log file audit (auth-like logs)
- File integrity snapshots (SHA-256)
- Snapshot comparisons
- HTML report generation
- Two modes:
    * CLI mode (use subcommands like before)
    * Interactive menu mode (run with NO arguments to get a Villain-style menu)

Usage (CLI mode):
    python3 CybersecurityToolkit.py scan-ports --ip 127.0.0.1
    python3 CybersecurityToolkit.py password-audit --passwords my-passwords.txt
    python3 CybersecurityToolkit.py log-audit --logfile ./auth.log
    python3 CybersecurityToolkit.py integrity-snapshot --paths /etc /home/you --out snap1.json
    python3 CybersecurityToolkit.py compare-snapshots --old snap1.json --new snap2.json
    python3 CybersecurityToolkit.py report --out report.html --scan-json scan.json --pw-json password_audit.json --logfiles auth.log --snapshot-diff-json snapshot_diff.json

Interactive mode:
    python3 CybersecurityToolkit.py
"""

from __future__ import annotations
import argparse
import socket
import sys
import os
import hashlib
import json
import datetime
import getpass
import time
import re
from typing import List, Dict, Any, Optional
import html
import pathlib


# Try to import rich for prettier output; fall back if unavailable
try:
    from rich.console import Console
    RICH = True
    console = Console()
except Exception:
    RICH = False
    console = None
try:
    from rich.table import Table
except Exception:
    Table = None
try:
    from rich.panel import Panel
except Exception:
    Panel = None
try:
    from rich.prompt import Prompt
except Exception:
    Prompt = None
try:
    from rich import box
except Exception:
    box = None

# --------------------------
# Configuration & constants
# --------------------------
DEFAULT_LOCAL_IP = "127.0.0.1"
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    5900: "VNC",
    6379: "Redis",
    27017: "MongoDB"
}
PORT_TIMEOUT = 0.4  # seconds, small to stay responsive

# --------------------------
# ASCII Banner (SHADOW)
# --------------------------
SHADOW_BANNER = r"""
  ________  ___  ___  ________  ________  ________  ___       __      
|\   ____\|\  \|\  \|\   __  \|\   ___ \|\   __  \|\  \     |\  \    
\ \  \___|\ \  \\\  \ \  \|\  \ \  \_|\ \ \  \|\  \ \  \    \ \  \   
 \ \_____  \ \   __  \ \   __  \ \  \ \\ \ \  \\\  \ \  \  __\ \  \  
  \|____|\  \ \  \ \  \ \  \ \  \ \  \_\\ \ \  \\\  \ \  \|\__\_\  \ 
    ____\_\  \ \__\ \__\ \__\ \__\ \_______\ \_______\ \____________\
   |\_________\|__|\|__|\|__|\|__|\|_______|\|_______|\|____________|
   \|_________|                                                      

Stealy Host Analysis & Defense Override                              
made by Zayne Bowen
Cybersecurity Engineer - Defensive Toolkit
Use responsibly on systems you own or have permission to test.
"""

def print_banner():
    if RICH and console is not None:
        console.print(SHADOW_BANNER, style="bold cyan")
    else:
        print(SHADOW_BANNER)

def info_line(msg: str):
    if RICH and console is not None:
        console.print(f"[bold green][Info][/bold green] {msg}")
    else: 
        print(f"[Info] {msg}")

def scan_line(msg: str):
    if RICH and console is not None:
        console.print(f"[bold yellow][Scan][/bold yellow] {msg}")
    else:
        print(f"[Scan] {msg}")

def warn_line(msg: str):
    if RICH and console is not None:
        console.print(f"[bold red][Warn][/bold red] {msg}")
    else:
        print(f"[Warn] {msg}")

# --------------------------
# Utilities
# --------------------------
def now_iso() -> str:
    """Return timezone-aware UTC ISO timestamp (RFC3339ish)."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def sha256_file(path: str) -> Optional[str]:
    """Return SHA256 hex digest for a file, or None if can't read."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, IsADirectoryError):
        return None

def is_local_address(addr: str) -> bool:
    return addr in ("127.0.0.1", "localhost", "::1")

# --------------------------
# Local-only Port Scanner
# --------------------------
def scan_local_ports(ports: Dict[int, str] = COMMON_PORTS, ip: str = DEFAULT_LOCAL_IP) -> Dict[int, Dict[str, Any]]:
    """
    Scan a list of ports on localhost only.
    Returns a dictionary: port -> {open: bool, service: name, banner: optional}
    """
    if not is_local_address(ip):
        raise ValueError("This scanner only supports local addresses by default. Use 127.0.0.1 or localhost.")
    results = {}
    for port, name in sorted(ports.items()):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(PORT_TIMEOUT)
        try:
            err = s.connect_ex((ip, port))
            if err == 0:
                banner = None
                # Attempt a safe, non-invasive banner grab: send nothing, just try to recv a short banner
                try:
                    s.settimeout(0.5)
                    banner_bytes = s.recv(256)
                    if banner_bytes:
                        try:
                            banner = banner_bytes.decode("utf-8", errors="replace").strip()
                        except Exception:
                            banner = str(banner_bytes)
                except Exception:
                    banner = None
                results[port] = {"open": True, "service": name, "banner": banner}
            else:
                results[port] = {"open": False, "service": name, "banner": None}
        except Exception as e:
            results[port] = {"open": False, "service": name, "banner": None, "error": str(e)}
        finally:
            s.close()
    return results

def pretty_print_port_results(results: Dict[int, Dict[str, Any]], ip: str = DEFAULT_LOCAL_IP):
    """Pretty-print port scan using rich if available, otherwise plain text table."""
    if RICH and console is not None and Table is not None and box is not None:
        t = Table(title=f"Port Scan Results ({ip})", box=box.SIMPLE_HEAVY)
        t.add_column("Port", justify="right", style="bold")
        t.add_column("Service", justify="left")
        t.add_column("Open", justify="center")
        t.add_column("Banner", justify="left")
        for port in sorted(results.keys()):
            r = results[port]
            open_str = "Yes" if r.get("open") else "No"
            banner = r.get("banner") or ""
            t.add_row(str(port), str(r.get("service")), open_str, banner)
        console.print(t)
    else:
        header = f"{'Port':>5} | {'Service':<12} | {'Open':<4} | Banner"
        sep = "-" * max(len(header), 60)
        print(sep)
        print(f" Port Scan Results ({ip})")
        print(sep)
        print(header)
        print(sep)
        for port in sorted(results.keys()):
            r = results[port]
            open_str = "Yes" if r.get("open") else "No"
            banner = (r.get("banner") or "")[:60]
            print(f"{str(port).rjust(5)} | {str(r.get('service')).ljust(12)} | {open_str.ljust(4)} | {banner}")
        print(sep)

# --------------------------
# Password strength / policy auditor
# --------------------------
COMMON_WORDS = {
    # small sample; in production use curated lists and never store secrets
    "password", "123456", "qwerty", "admin", "letmein", "iloveyou", "welcome", "changeme"
}

def estimate_entropy(password: str) -> float:
    """
    Rough entropy estimate (bits) using character class heuristics.
    """
    classes = 0
    if re.search(r'[a-z]', password): classes += 26
    if re.search(r'[A-Z]', password): classes += 26
    if re.search(r'[0-9]', password): classes += 10
    if re.search(r'[^A-Za-z0-9]', password): classes += 32
    import math
    if classes == 0:
        return 0.0
    bits_per_char = math.log2(classes)
    return bits_per_char * len(password)

def build_password_recommendation(issues: List[str], pw: str) -> str:
    recs = []
    if "too-short" in issues:
        recs.append("increase length to 12+ characters")
    if "low-entropy" in issues:
        recs.append("use mixed character classes and avoid dictionary words")
    if "repetition" in issues:
        recs.append("avoid repeated characters")
    if "common-password" in issues or "contains-easy-token" in issues:
        recs.append("avoid common words or easily guessable substrings")
    if not recs:
        recs.append("looks reasonably strong — consider a password manager and 2FA")
    return "; ".join(recs)

def audit_password_list(passwords: List[str]) -> List[Dict[str, Any]]:
    """
    Audit a list of passwords provided by the user.
    Don't echo full secrets in outputs.
    """
    results = []
    for p in passwords:
        p = p.strip()
        if not p:
            continue
        entropy = estimate_entropy(p)
        issues = []
        if len(p) < 8:
            issues.append("too-short")
        if entropy < 28:
            issues.append("low-entropy")
        if re.search(r'(.)\1\1', p):
            issues.append("repetition")
        if p.lower() in COMMON_WORDS:
            issues.append("common-password")
        if re.search(r'password|pass|admin|welcome', p, re.I):
            issues.append("contains-easy-token")
        results.append({
            "password_sample": p[:4] + "..." if len(p) > 7 else p,
            "length": len(p),
            "entropy_bits": round(entropy, 1),
            "issues": issues,
            "recommendation": build_password_recommendation(issues, p)
        })
    return results

# --------------------------
# Log auditing (auth-like logs)
# --------------------------
AUTH_FAIL_PATTERNS = [
    re.compile(r'Failed password for (invalid user )?(?P<user>[\w\-\._]+) from (?P<ip>[\d.]+)', re.I),
    re.compile(r'authentication failure;.*rhost=(?P<ip>[\d.]+).*user=(?P<user>[\w\-\._]+)', re.I),
    re.compile(r'Failed login for user (?P<user>[\w\-\._]+) from (?P<ip>[\d.]+)', re.I),
]
SUDO_PATTERN = re.compile(r'sudo: (?:pam_unix\(\)|)?: session (?:opened|closed) for user (?P<user>[\w\-\._]+)', re.I)

def parse_log_for_failures(log_content: str, window_lines: int = 5) -> Dict[str, Any]:
    """
    Parse log text for repeated failed logins. Returns summary:
    - per_ip, per_user, clusters, total_failures
    """
    lines = log_content.splitlines()
    per_ip = {}
    per_user = {}
    events = []
    for idx, line in enumerate(lines):
        for pat in AUTH_FAIL_PATTERNS:
            m = pat.search(line)
            if m:
                ip = m.groupdict().get("ip")
                user = m.groupdict().get("user", "(unknown)")
                per_ip.setdefault(ip, 0)
                per_ip[ip] += 1
                per_user.setdefault(user, 0)
                per_user[user] += 1
                events.append((idx, ip, user, line))
                break
    clusters = []
    if events:
        cluster = [events[0]]
        for e in events[1:]:
            if e[0] - cluster[-1][0] <= window_lines:
                cluster.append(e)
            else:
                if len(cluster) >= 3:
                    clusters.append(cluster)
                cluster = [e]
        if len(cluster) >= 3:
            clusters.append(cluster)
    return {"per_ip": per_ip, "per_user": per_user, "clusters": clusters, "total_failures": len(events)}

def audit_log_file(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        return {"error": f"Could not read log: {e}"}
    failures = parse_log_for_failures(content)
    sudo_count = len(SUDO_PATTERN.findall(content))
    return {"path": path, "sudo_events": sudo_count, "failures": failures}

# --------------------------
# File integrity snapshot
# --------------------------
def build_snapshot(paths: List[str], follow_symlinks: bool = False) -> Dict[str, Any]:
    snapshot = {"generated_at": now_iso(), "paths": {}, "host": socket.gethostname()}
    for base in paths:
        base = os.path.abspath(base)
        collected = {}
        if not os.path.exists(base):
            snapshot["paths"][base] = {"error": "not found"}
            continue
        for root, dirs, files in os.walk(base, followlinks=follow_symlinks):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    rel = os.path.relpath(fpath, base)
                    st = os.lstat(fpath)
                    h = sha256_file(fpath)
                    collected[rel] = {
                        "size": st.st_size,
                        "mode": oct(st.st_mode),
                        "uid": st.st_uid,
                        "gid": st.st_gid,
                        "sha256": h
                    }
                except Exception as e:
                    collected[fname] = {"error": str(e)}
        snapshot["paths"][base] = {"collected_files": collected}
    return snapshot

def compare_snapshots(old_snap: Dict[str, Any], new_snap: Dict[str, Any]) -> Dict[str, Any]:
    result = {"compared_at": now_iso(), "differences": {}}
    for base in set(list(old_snap.get("paths", {}).keys()) + list(new_snap.get("paths", {}).keys())):
        old_files = old_snap.get("paths", {}).get(base, {}).get("collected_files", {}) or {}
        new_files = new_snap.get("paths", {}).get(base, {}).get("collected_files", {}) or {}
        added = [f for f in new_files.keys() if f not in old_files]
        removed = [f for f in old_files.keys() if f not in new_files]
        modified = []
        for f in set(old_files.keys()).intersection(set(new_files.keys())):
            old_h = old_files[f].get("sha256")
            new_h = new_files[f].get("sha256")
            if old_h != new_h:
                modified.append({"file": f, "old": old_h, "new": new_h})
        result["differences"][base] = {"added": added, "removed": removed, "modified": modified}
    return result

# --------------------------
# HTML report generator
# --------------------------
def generate_html_report(report_path: str,
                         port_scan: Optional[Dict[int, Dict[str, Any]]] = None,
                         password_audit: Optional[List[Dict[str, Any]]] = None,
                         log_audits: Optional[List[Dict[str, Any]]] = None,
                         snapshot_diffs: Optional[Dict[str, Any]] = None) -> None:
    title = "Cyber Lab Toolkit Report"
    parts = []
    parts.append(f"<h1>{html.escape(title)}</h1>")
    parts.append(f"<p>Generated at {html.escape(now_iso())}</p>")
    if port_scan is not None:
        parts.append("<h2>Local Port Scan (127.0.0.1)</h2>")
        parts.append("<table border='1' cellpadding='4'><tr><th>Port</th><th>Service</th><th>Open</th><th>Banner</th></tr>")
        for port in sorted(port_scan.keys()):
            r = port_scan[port]
            parts.append("<tr><td>{}</td><td>{}</td><td>{}</td><td><pre>{}</pre></td></tr>".format(
                port, html.escape(str(r.get("service"))), "Yes" if r.get("open") else "No", html.escape(str(r.get("banner") or ""))))
        parts.append("</table>")
    if password_audit is not None:
        parts.append("<h2>Password Audit</h2>")
        parts.append("<table border='1' cellpadding='4'><tr><th>Sample</th><th>Length</th><th>Entropy(bits)</th><th>Issues</th><th>Recommendation</th></tr>")
        for r in password_audit:
            parts.append("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                html.escape(r["password_sample"]), r["length"], r["entropy_bits"], html.escape(", ".join(r["issues"])), html.escape(r["recommendation"])))
        parts.append("</table>")
    if log_audits:
        parts.append("<h2>Log Audits</h2>")
        for la in log_audits:
            if "error" in la:
                parts.append(f"<h3>Log: {html.escape(la.get('path','<unknown>'))} - ERROR</h3><pre>{html.escape(la['error'])}</pre>")
                continue
            parts.append(f"<h3>Log: {html.escape(la['path'])}</h3>")
            fa = la["failures"]
            parts.append(f"<p>Sudo events (approx): {la.get('sudo_events',0)}</p>")
            parts.append(f"<p>Total failed auth events found: {fa.get('total_failures',0)}</p>")
            if fa.get("per_ip"):
                parts.append("<h4>Failures per IP</h4><ul>")
                for ip, cnt in fa["per_ip"].items():
                    parts.append(f"<li>{html.escape(str(ip))}: {cnt}</li>")
                parts.append("</ul>")
            if fa.get("per_user"):
                parts.append("<h4>Failures per user</h4><ul>")
                for user, cnt in fa["per_user"].items():
                    parts.append(f"<li>{html.escape(str(user))}: {cnt}</li>")
                parts.append("</ul>")
            if fa.get("clusters"):
                parts.append("<h4>Suspicious clusters</h4><ul>")
                for cluster in fa["clusters"]:
                    parts.append("<li>Cluster of {} events. Sample lines:<pre>{}</pre></li>".format(len(cluster),
                        html.escape("\n".join([c[3] for c in cluster][:10]))))
                parts.append("</ul>")
    if snapshot_diffs:
        parts.append("<h2>Snapshot Differences</h2>")
        for base, dif in snapshot_diffs.get("differences", {}).items():
            parts.append(f"<h3>Path base: {html.escape(base)}</h3>")
            parts.append(f"<p>Added files: {len(dif['added'])}, Removed: {len(dif['removed'])}, Modified: {len(dif['modified'])}</p>")
            if dif['added']:
                parts.append("<details><summary>Added</summary><pre>{}</pre></details>".format(html.escape("\n".join(dif['added']))))
            if dif['removed']:
                parts.append("<details><summary>Removed</summary><pre>{}</pre></details>".format(html.escape("\n".join(dif['removed']))))
            if dif['modified']:
                parts.append("<details><summary>Modified</summary><pre>{}</pre></details>".format(html.escape(
                    "\n".join([f['file'] + " (old: " + str(f['old'])[:8] + "... -> new: " + str(f['new'])[:8] + "...)"
                               for f in dif['modified']]))))
    full_html = "<html><head><meta charset='utf-8'><title>{}</title></head><body>{}</body></html>".format(html.escape(title), "\n".join(parts))
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(full_html)
        info_line(f"Report written to {report_path}")
    except Exception as e:
        warn_line(f"Failed to write report: {e}")


# --------------------------
# CLI wiring (argparse)
# --------------------------
def cli_main(argv: Optional[List[str]] = None):
    confirm_local_only = lambda: (info_line("- Zayne, This toolkit is for defensive use on systems you own or have permission to test."),
                                  info_line("By default this tool will only probe localhost (127.0.0.1)."))
    confirm_local_only()

    parser = argparse.ArgumentParser(description="Cyber Lab Toolkit - defensive tasks for local systems")
    sub = parser.add_subparsers(dest="cmd")

    p_scan = sub.add_parser("scan-ports", help="Scan common ports on localhost")
    p_scan.add_argument("--ip", default=DEFAULT_LOCAL_IP, help="IP to scan (default 127.0.0.1)")

    p_pw = sub.add_parser("password-audit", help="Audit passwords from a file or single input")
    p_pw.add_argument("--passwords", help="Path to newline-separated file with password samples")
    p_pw.add_argument("--interactive", action="store_true", help="Enter a password interactively for immediate audit")

    p_log = sub.add_parser("log-audit", help="Audit a local log file for failed auth attempts")
    p_log.add_argument("--logfile", required=True, help="Path to log file (supply a copy of /var/log/auth.log or similar)")

    p_snap = sub.add_parser("integrity-snapshot", help="Create a file integrity snapshot for given paths")
    p_snap.add_argument("--paths", nargs="+", required=True, help="Paths to snapshot (space-separated)")
    p_snap.add_argument("--out", required=True, help="Output JSON file to write snapshot to")

    p_compare = sub.add_parser("compare-snapshots", help="Compare two snapshots created with integrity-snapshot")
    p_compare.add_argument("--old", required=True, help="Old snapshot JSON")
    p_compare.add_argument("--new", required=True, help="New snapshot JSON")

    p_report = sub.add_parser("report", help="Generate an HTML report from various inputs")
    p_report.add_argument("--out", required=True, help="Output HTML path")
    p_report.add_argument("--scan-json", help="Optional JSON path produced by scan-ports (local only) to include")
    p_report.add_argument("--pw-json", help="Optional JSON path produced by password-audit to include")
    p_report.add_argument("--logfiles", nargs="*", help="Optional list of log file paths to include")
    p_report.add_argument("--snapshot-diff-json", help="Optional JSON diff (from compare-snapshots) to include")

    args = parser.parse_args(argv)

    if not args.cmd:
        # No subcommand supplied -> interactive menu
        interactive_menu()
        return

    # dispatch
    if args.cmd == "scan-ports":
        if not is_local_address(args.ip):
            warn_line("ERROR: scanner only supports local addresses by default.")
            sys.exit(1)
        scan_line(f"Scanning {args.ip} common ports (this only checks localhost)...")
        res = scan_local_ports(COMMON_PORTS, args.ip)
        outpath = "scan_ports_local.json"
        with open(outpath, "w") as f:
            json.dump({"generated_at": now_iso(), "results": res}, f, indent=2)
        info_line(f"Scan results saved to {outpath}")
        pretty_print_port_results(res, ip=args.ip)

    elif args.cmd == "password-audit":
        passwords = []
        if args.passwords:
            try:
                with open(args.passwords, "r", errors="ignore") as f:
                    passwords.extend([l.strip() for l in f.readlines() if l.strip()])
            except Exception as e:
                warn_line(f"Could not read password file: {e}")
                sys.exit(1)
        if args.interactive:
            pw = getpass.getpass("Enter password to audit (will not be stored in file): ")
            passwords.append(pw)
        if not passwords:
            warn_line("No passwords supplied. Use --passwords or --interactive.")
            sys.exit(1)
        audit = audit_password_list(passwords)
        outpath = "password_audit.json"
        with open(outpath, "w") as f:
            json.dump({"generated_at": now_iso(), "results": audit}, f, indent=2)
        info_line(f"Password audit written to {outpath}")
        for r in audit:
            if RICH and console is not None:
                console.print(f"[cyan]Sample:[/cyan] {r['password_sample']} [magenta]len=[/magenta]{r['length']} [yellow]entropy=[/yellow]{r['entropy_bits']} [red]issues=[/red]{','.join(r['issues'])}")
            else:
                print(f"Sample: {r['password_sample']}, len={r['length']}, entropy={r['entropy_bits']}, issues={r['issues']}")

    elif args.cmd == "log-audit":
        if not os.path.exists(args.logfile):
            warn_line("Log file not found.")
            sys.exit(1)
        la = audit_log_file(args.logfile)
        outpath = pathlib.Path(args.logfile).name + ".audit.json"
        with open(outpath, "w") as f:
            json.dump({"generated_at": now_iso(), "audit": la}, f, indent=2)
        info_line(f"Log audit saved to {outpath}")
        info_line(f"Summary: sudo_events={la.get('sudo_events')}, total_failures={la.get('failures',{}).get('total_failures',0)}")

    elif args.cmd == "integrity-snapshot":
        snap = build_snapshot(args.paths)
        with open(args.out, "w") as f:
            json.dump(snap, f, indent=2)
        info_line(f"Snapshot written to {args.out}")

    elif args.cmd == "compare-snapshots":
        if not os.path.exists(args.old) or not os.path.exists(args.new):
            warn_line("Snapshot file(s) missing")
            sys.exit(1)
        with open(args.old, "r") as f:
            old = json.load(f)
        with open(args.new, "r") as f:
            new = json.load(f)
        diff = compare_snapshots(old, new)
        outpath = "snapshot_diff.json"
        with open(outpath, "w") as f:
            json.dump(diff, f, indent=2)
        info_line(f"Snapshot diff written to {outpath}")

    elif args.cmd == "report":
        port_scan = None
        pw_audit = None
        log_audits = []
        snapshot_diffs = None
        if args.scan_json:
            try:
                with open(args.scan_json, "r") as f:
                    port_scan = json.load(f).get("results")
            except Exception as e:
                warn_line(f"Could not load scan json: {e}")
        if args.pw_json:
            try:
                with open(args.pw_json, "r") as f:
                    pw_audit = json.load(f).get("results")
            except Exception as e:
                warn_line(f"Could not load pw json: {e}")
        if args.logfiles:
            for lf in args.logfiles:
                if os.path.exists(lf):
                    log_audits.append(audit_log_file(lf))
                else:
                    warn_line(f"Log file not found: {lf}")
        if args.snapshot_diff_json:
            try:
                with open(args.snapshot_diff_json, "r") as f:
                    snapshot_diffs = json.load(f)
            except Exception as e:
                warn_line(f"Could not load snapshot diff: {e}")
        generate_html_report(args.out, port_scan=port_scan, password_audit=pw_audit, log_audits=log_audits, snapshot_diffs=snapshot_diffs)

    else:
        parser.print_help()

# --------------------------
# Interactive menu
# --------------------------
def interactive_menu():
    print_banner()
    info_line("This toolkit is for defensive use only on systems you own or have permission to test.")
    while True:
        if RICH and console is not None and Prompt is not None:
            console.rule("[bold cyan]Main Menu[/bold cyan]")
            console.print("[1] Scan localhost ports")
            console.print("[2] Password audit")
            console.print("[3] Log audit")
            console.print("[4] Integrity snapshot")
            console.print("[5] Compare snapshots")
            console.print("[6] Generate HTML report")
            console.print("[0] Exit")
            choice = Prompt.ask("Select an option", choices=["0","1","2","3","4","5","6"], default="0")
        else:
            print("\nMain Menu")
            print(" 1) Scan localhost ports")
            print(" 2) Password audit")
            print(" 3) Log audit")
            print(" 4) Integrity snapshot (create)")
            print(" 5) Compare snapshots")
            print(" 6) Generate HTML report")
            print(" 0) Exit")
            choice = input("Select an option: ").strip()

        if choice == "1":
            ip = DEFAULT_LOCAL_IP
            if RICH and console is not None and Prompt is not None:
                ip = Prompt.ask("IP to scan (local only)", default=DEFAULT_LOCAL_IP)
            else:
                t = input(f"IP to scan (default {DEFAULT_LOCAL_IP}): ").strip()
                if t:
                    ip = t
            try:
                if not is_local_address(ip):
                    warn_line("Scanner only supports local addresses by default.")
                else:
                    scan_line(f"Scanning {ip} common ports...")
                    res = scan_local_ports(COMMON_PORTS, ip)
                    outpath = "scan_ports_local.json"
                    with open(outpath, "w") as f:
                        json.dump({"generated_at": now_iso(), "results": res}, f, indent=2)
                    info_line(f"Scan saved to {outpath}")
                    pretty_print_port_results(res, ip=ip)
            except Exception as e:
                warn_line(f"Scan failed: {e}")

        elif choice == "2":
            if RICH and console is not None and Prompt is not None:
                mode = Prompt.ask("Load from file or interactive?", choices=["file","interactive"], default="interactive")
            else:
                mode = input("Load from file or interactive? (file/interactive) [interactive]: ").strip() or "interactive"
            passwords = []
            if mode == "file":
                path = Prompt.ask("Path to password file") if RICH and console is not None and Prompt is not None else input("Path to password file: ").strip()
                try:
                    with open(path, "r", errors="ignore") as f:
                        passwords = [l.strip() for l in f.readlines() if l.strip()]
                except Exception as e:
                    warn_line(f"Could not read file: {e}")
                    continue
            else:
                pw = getpass.getpass("Enter password to audit (will not be stored in file): ")
                passwords = [pw]
            audit = audit_password_list(passwords)
            outpath = "password_audit.json"
            with open(outpath, "w") as f:
                json.dump({"generated_at": now_iso(), "results": audit}, f, indent=2)
            info_line(f"Password audit written to {outpath}")
            if RICH and console is not None:
                for r in audit:
                    console.print(f"[cyan]Sample:[/cyan] {r['password_sample']} [magenta]len=[/magenta]{r['length']} [yellow]entropy=[/yellow]{r['entropy_bits']} [red]issues=[/red]{','.join(r['issues'])}")
            else:
                for r in audit:
                    print(f"Sample: {r['password_sample']}, len={r['length']}, entropy={r['entropy_bits']}, issues={r['issues']}")

        elif choice == "3":
            path = Prompt.ask("Path to log file (use a copy of /var/log/auth.log)") if RICH and console is not None and Prompt is not None else input("Path to log file: ").strip()
            if not os.path.exists(path):
                warn_line("Log file not found.")
                continue
            la = audit_log_file(path)
            outpath = pathlib.Path(path).name + ".audit.json"
            with open(outpath, "w") as f:
                json.dump({"generated_at": now_iso(), "audit": la}, f, indent=2)
            info_line(f"Log audit saved to {outpath}")
            info_line(f"Summary: sudo_events={la.get('sudo_events')}, total_failures={la.get('failures',{}).get('total_failures',0)}")

        elif choice == "4":
            paths_raw = Prompt.ask("Paths to snapshot (space-separated)") if RICH and console is not None and Prompt is not None else input("Paths (space-separated): ").strip()
            paths = paths_raw.split()
            out = Prompt.ask("Output JSON file name", default="snapshot.json") if RICH and console is not None and Prompt is not None else input("Output JSON file name [snapshot.json]: ").strip() or "snapshot.json"
            snap = build_snapshot(paths)
            with open(out, "w") as f:
                json.dump(snap, f, indent=2)
            info_line(f"Snapshot written to {out}")

        elif choice == "5":
            old = Prompt.ask("Old snapshot JSON path") if RICH and console is not None and Prompt is not None else input("Old snapshot JSON path: ").strip()
            new = Prompt.ask("New snapshot JSON path") if RICH and console is not None and Prompt is not None else input("New snapshot JSON path: ").strip()
            if not (os.path.exists(old) and os.path.exists(new)):
                warn_line("One of the snapshot files does not exist.")
                continue
            with open(old, "r") as f:
                old_snap = json.load(f)
            with open(new, "r") as f:
                new_snap = json.load(f)
            diff = compare_snapshots(old_snap, new_snap)
            outpath = "snapshot_diff.json"
            with open(outpath, "w") as f:
                json.dump(diff, f, indent=2)
            info_line(f"Snapshot diff written to {outpath}")

        elif choice == "6":
            out = Prompt.ask("Output HTML file", default="report.html") if RICH and console is not None and Prompt is not None else input("Output HTML file [report.html]: ").strip() or "report.html"
            # ask for optional inputs
            scan_json = Prompt.ask("Path to scan json (or blank)", default="") if RICH and console is not None and Prompt is not None else input("Path to scan json (or blank): ").strip()
            pw_json = Prompt.ask("Path to pw json (or blank)", default="") if RICH and console is not None and Prompt is not None else input("Path to pw json (or blank): ").strip()
            logs = Prompt.ask("Log file paths (space-separated) or blank", default="") if RICH and console is not None and Prompt is not None else input("Log file paths (space-separated) or blank: ").strip()
            snapdiff = Prompt.ask("Snapshot diff json (or blank)", default="") if RICH and console is not None and Prompt is not None else input("Snapshot diff json (or blank): ").strip()

            port_scan = None
            pw_audit = None
            log_audits = []
            snapshot_diffs = None

            if scan_json:
                try:
                    with open(scan_json, "r") as f:
                        port_scan = json.load(f).get("results")
                except Exception as e:
                    warn_line(f"Could not load scan json: {e}")
            if pw_json:
                try:
                    with open(pw_json, "r") as f:
                        pw_audit = json.load(f).get("results")
                except Exception as e:
                    warn_line(f"Could not load pw json: {e}")
            if logs:
                for lf in logs.split():
                    if os.path.exists(lf):
                        log_audits.append(audit_log_file(lf))
                    else:
                        warn_line(f"Log file not found: {lf}")
            if snapdiff:
                try:
                    with open(snapdiff, "r") as f:
                        snapshot_diffs = json.load(f)
                except Exception as e:
                    warn_line(f"Could not load snapshot diff: {e}")
            generate_html_report(out, port_scan=port_scan, password_audit=pw_audit, log_audits=log_audits, snapshot_diffs=snapshot_diffs)
            info_line(f"Report generated at {out}")

        elif choice == "0":
            info_line("Exiting.")
            break

        else:
            warn_line("Invalid choice. Try again.")





# --------------------------
# Entrypoint
# --------------------------
if __name__ == "__main__":
    if len(sys.argv) == 1:  # no arguments provided
        interactive_menu()  # run interactive mode
    else:
        cli_main()  # run CLI mode
