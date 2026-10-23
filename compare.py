#!/usr/bin/env python3
"""
CyberPatriot VM Diff Tool
Compares a mounted practice VM against a clean Ubuntu 22.04 base image
and reports everything that looks misconfigured.

Usage:
    python3 compare.py [--vm /mnt/vm_mint] [--base /path/to/base]
"""

import argparse
import os
import sys
import subprocess
import pwd
import grp
from pathlib import Path

# ── colour helpers ────────────────────────────────────────────────────────────
RED   = "\033[91m"
YEL   = "\033[93m"
GRN   = "\033[92m"
BLU   = "\033[94m"
BOLD  = "\033[1m"
RST   = "\033[0m"

def bad(msg):  print(f"  {RED}[!]{RST} {msg}")
def warn(msg): print(f"  {YEL}[~]{RST} {msg}")
def ok(msg):   print(f"  {GRN}[+]{RST} {msg}")
def hdr(msg):  print(f"\n{BOLD}{BLU}{'═'*60}{RST}\n{BOLD}  {msg}{RST}\n{BOLD}{BLU}{'═'*60}{RST}")
def sub(msg):  print(f"\n{BOLD}  ── {msg} ──{RST}")

def read(path, sudo=False):
    try:
        if sudo:
            r = subprocess.run(["sudo","cat",str(path)], capture_output=True, text=True)
            return r.stdout
        return Path(path).read_text(errors="replace")
    except Exception:
        return ""

def readlines(path, sudo=False):
    return [l for l in read(path, sudo).splitlines() if l.strip() and not l.strip().startswith("#")]

def sudoread(path):
    return read(path, sudo=True)

def sudoreadlines(path):
    return readlines(path, sudo=True)

# ── 1. Users ──────────────────────────────────────────────────────────────────
def check_users(vm, base):
    hdr("1. USER ACCOUNTS")

    vm_passwd   = sudoread(f"{vm}/etc/passwd")
    base_passwd = read(f"{base}/etc/passwd")

    vm_users   = {l.split(":")[0]: l.split(":") for l in vm_passwd.splitlines()   if l.strip()}
    base_users = {l.split(":")[0]: l.split(":") for l in base_passwd.splitlines() if l.strip()}

    sub("UID-0 accounts (should be root only)")
    for name, fields in vm_users.items():
        if fields[2] == "0" and name != "root":
            bad(f"UID-0 account found: {name}")
        elif fields[2] == "0":
            ok("root is the only UID-0 account")
            break

    sub("Non-system users (UID >= 1000)")
    vm_human = {n: f for n, f in vm_users.items() if int(f[2]) >= 1000 and n != "nobody"}
    base_human = {n: f for n, f in base_users.items() if int(f[2]) >= 1000 and n != "nobody"}
    extra = set(vm_human) - set(base_human)
    for u in sorted(extra):
        shell = vm_human[u][6].strip()
        warn(f"User: {u}  shell={shell}")

    sub("Accounts with login shells that are new vs base")
    SHELLS = {"/bin/bash","/bin/sh","/bin/zsh","/bin/fish","/usr/bin/bash","/usr/bin/zsh"}
    for name, fields in vm_users.items():
        if name not in base_users and fields[6].strip() in SHELLS:
            bad(f"New interactive account: {name} (shell={fields[6].strip()})")

# ── 2. Groups / sudo ──────────────────────────────────────────────────────────
def check_sudo(vm, base):
    hdr("2. SUDO & GROUP MEMBERSHIP")

    sub("sudo group members")
    vm_group = {l.split(":")[0]: l for l in sudoread(f"{vm}/etc/group").splitlines() if l.strip()}
    base_group = {l.split(":")[0]: l for l in read(f"{base}/etc/group").splitlines() if l.strip()}

    for gname in ("sudo", "admin", "wheel"):
        vm_line   = vm_group.get(gname, "")
        base_line = base_group.get(gname, "")
        vm_members   = set(vm_line.split(":")[-1].split(","))   - {""} if vm_line   else set()
        base_members = set(base_line.split(":")[-1].split(",")) - {""} if base_line else set()
        extra = vm_members - base_members
        if extra:
            bad(f"Extra members in '{gname}': {', '.join(sorted(extra))}")
        elif vm_members:
            ok(f"'{gname}' group: {', '.join(sorted(vm_members))}")

    sub("sudoers file")
    for line in sudoreadlines(f"{vm}/etc/sudoers"):
        if "NOPASSWD" in line and "mint-refresh-cache" not in line and "synaptic" not in line and "dpkg_lock" not in line:
            bad(f"NOPASSWD in sudoers: {line.strip()}")
        elif "ALL=(ALL" in line and not line.strip().startswith("%") and not line.strip().startswith("root"):
            bad(f"Broad sudo grant: {line.strip()}")

    sub("sudoers.d/ files")
    sudoers_d = Path(f"{vm}/etc/sudoers.d")
    if sudoers_d.exists():
        for f in sorted(sudoers_d.iterdir()):
            for line in sudoreadlines(str(f)):
                if "NOPASSWD: ALL" in line:
                    bad(f"{f.name}: {line.strip()}")

# ── 3. SSH ────────────────────────────────────────────────────────────────────
SSHD_CHECKS = {
    "PermitRootLogin":      ("yes",  "no",    "Root login via SSH"),
    "PermitEmptyPasswords": ("yes",  "no",    "Empty password SSH login"),
    "X11Forwarding":        ("yes",  "no",    "X11 forwarding"),
    "Protocol":             ("1",    "2",     "SSH protocol version"),
    "PasswordAuthentication": (None, None,    None),   # just report value
}

def check_ssh(vm, base):
    hdr("3. SSH CONFIGURATION")
    conf_path = f"{vm}/etc/ssh/sshd_config"
    if not Path(conf_path).exists():
        warn("sshd_config not found")
        return

    conf = {}
    for line in sudoread(conf_path).splitlines():
        line = line.strip()
        if line and not line.startswith("#") and " " in line:
            k, v = line.split(None, 1)
            conf[k.lower()] = v.strip().lower()

    checks = [
        ("permitrootlogin",      "yes",  "PermitRootLogin yes  → should be no"),
        ("permitemptypasswords", "yes",  "PermitEmptyPasswords yes  → critical"),
        ("x11forwarding",        "yes",  "X11Forwarding yes  → should be no"),
        ("protocol",             "1",    "Protocol 1  → insecure, use 2"),
    ]
    for key, bad_val, msg in checks:
        val = conf.get(key)
        if val == bad_val:
            bad(msg)
        elif val:
            ok(f"{key} = {val}")
        else:
            warn(f"{key} not set (using default)")

    sub("Authorized keys in home dirs")
    result = subprocess.run(["sudo","find", f"{vm}/home", f"{vm}/root",
                             "-name","authorized_keys"], capture_output=True, text=True)
    for f in result.stdout.splitlines():
        content = sudoread(f).strip()
        if content:
            bad(f"authorized_keys found: {f}")
            print(f"      {content[:80]}")
        else:
            warn(f"authorized_keys exists but empty: {f}")

# ── 4. Services ───────────────────────────────────────────────────────────────
# Services that should NOT be running on a hardened desktop
BAD_SERVICES = {
    "vsftpd.service":    "FTP server — unencrypted file transfer",
    "telnet.service":    "Telnet — unencrypted remote shell",
    "rsh.service":       "Remote shell — no auth",
    "rlogin.service":    "Remote login — no auth",
    "finger.service":    "Finger — user info leak",
    "openvpn.service":   "OpenVPN — unauthorized VPN service",
    "inetd.service":     "inetd — legacy super-server",
    "xinetd.service":    "xinetd — legacy super-server",
    "nfs-server.service":"NFS server",
    "rpcbind.service":   "RPC portmapper",
    "avahi-daemon.service": "Avahi mDNS — network discovery (low severity)",
    "cups-browsed.service": "CUPS browsed — network printer discovery",
}

def check_services(vm, base):
    hdr("4. SERVICES")
    result = subprocess.run(
        ["sudo","find", f"{vm}/etc/systemd/system", "-name","*.service"],
        capture_output=True, text=True)
    enabled = {Path(p).name for p in result.stdout.splitlines()}

    for svc, reason in BAD_SERVICES.items():
        if svc in enabled:
            bad(f"{svc} enabled — {reason}")

    sub("vsftpd config")
    vconf = f"{vm}/etc/vsftpd.conf"
    if Path(vconf).exists():
        for line in sudoreadlines(vconf):
            if "ssl_enable=no" in line.lower():
                bad("vsftpd: ssl_enable=NO — FTP running without encryption")
            if "anonymous_enable=yes" in line.lower():
                bad("vsftpd: anonymous_enable=YES — anonymous FTP access allowed")
            if "write_enable=yes" in line.lower():
                warn("vsftpd: write_enable=YES — uploads allowed")

# ── 5. Firewall ───────────────────────────────────────────────────────────────
def check_firewall(vm, base):
    hdr("5. FIREWALL (UFW)")
    ufw_conf = f"{vm}/etc/ufw/ufw.conf"
    if not Path(ufw_conf).exists():
        bad("ufw.conf not found — firewall not installed?")
        return
    for line in sudoreadlines(ufw_conf):
        if line.strip().upper() == "ENABLED=NO":
            bad("UFW is DISABLED")
        elif line.strip().upper() == "ENABLED=YES":
            ok("UFW is enabled")

# ── 6. Packages ───────────────────────────────────────────────────────────────
BANNED_PKGS = {
    "netcat-openbsd":  "netcat — network swiss-army knife",
    "netcat-traditional":"netcat",
    "ncat":            "ncat (nmap netcat)",
    "socat":           "socat — bidirectional relay",
    "nmap":            "nmap — network scanner",
    "hydra":           "hydra — password cracker",
    "john":            "John the Ripper — password cracker",
    "hashcat":         "hashcat — GPU password cracker",
    "aircrack-ng":     "aircrack-ng — WiFi cracker",
    "wireshark":       "wireshark — packet capture GUI",
    "wireshark-qt":    "wireshark-qt",
    "tshark":          "tshark — packet capture CLI",
    "sqlmap":          "sqlmap — SQL injection tool",
    "nikto":           "nikto — web scanner",
    "masscan":         "masscan — fast port scanner",
    "medusa":          "medusa — password cracker",
    "hping3":          "hping3 — packet generator",
    "metasploit-framework": "Metasploit",
    "beef-xss":        "BeEF XSS framework",
    "ftp":             "ftp — unencrypted FTP client",
    "tnftp":           "tnftp — FTP client",
    "telnet":          "telnet — unencrypted remote login",
    "rsh-client":      "rsh — no-auth remote shell",
    "rlogin":          "rlogin",
    "vsftpd":          "vsftpd — FTP server",
    "proftpd":         "proftpd — FTP server",
    "pure-ftpd":       "pure-ftpd — FTP server",
    "zangband":        "zangband — prohibited game",
    "freeciv":         "freeciv — prohibited game",
    "openttd":         "openttd — prohibited game",
    "ophcrack":        "ophcrack — Windows password cracker",
    "ettercap-common": "ettercap — MITM tool",
    "kismet":          "kismet — wireless sniffer",
}

def check_packages(vm, base):
    hdr("6. INSTALLED PACKAGES")
    status = f"{vm}/var/lib/dpkg/status"
    if not Path(status).exists():
        warn("dpkg status not found")
        return

    result = subprocess.run(
        ["sudo","grep","-A1","^Package:", status],
        capture_output=True, text=True)
    installed = set()
    for line in result.stdout.splitlines():
        if line.startswith("Package:"):
            installed.add(line.split(":",1)[1].strip())

    for pkg, reason in BANNED_PKGS.items():
        if pkg in installed:
            bad(f"{pkg} installed — {reason}")

    # Also check base packages not in VM (optional info)
    base_status = f"{base}/var/lib/dpkg/status"
    if Path(base_status).exists():
        result2 = subprocess.run(
            ["grep","-A1","^Package:", base_status],
            capture_output=True, text=True)
        base_pkgs = set()
        for line in result2.stdout.splitlines():
            if line.startswith("Package:"):
                base_pkgs.add(line.split(":",1)[1].strip())
        extra = installed - base_pkgs - set(BANNED_PKGS.keys())
        sub("Packages installed beyond Ubuntu 22.04 base (informational)")
        for p in sorted(extra)[:40]:
            print(f"    {p}")

# ── 7. Password policy ────────────────────────────────────────────────────────
def check_passwords(vm, base):
    hdr("7. PASSWORD POLICY")

    sub("login.defs")
    vm_defs   = {}
    base_defs = {}
    for line in sudoreadlines(f"{vm}/etc/login.defs"):
        parts = line.split()
        if len(parts) >= 2:
            vm_defs[parts[0]] = parts[1]
    for line in readlines(f"{base}/etc/login.defs"):
        parts = line.split()
        if len(parts) >= 2:
            base_defs[parts[0]] = parts[1]

    checks = [
        ("PASS_MAX_DAYS", "99999", "Password never expires (should be ≤90)"),
        ("PASS_MIN_DAYS", "0",     "Min days between changes = 0 (ok but weak)"),
        ("PASS_MIN_LEN",  "0",     "Minimum password length = 0"),
    ]
    for key, bad_val, msg in checks:
        val = vm_defs.get(key)
        if val == bad_val:
            bad(f"{key}={val} — {msg}")
        elif val:
            ok(f"{key}={val}")

    sub("PAM password complexity (common-password)")
    pam = sudoread(f"{vm}/etc/pam.d/common-password")
    if "pam_pwquality" in pam or "pam_cracklib" in pam:
        ok("Password complexity module found")
    else:
        bad("No pam_pwquality or pam_cracklib — zero complexity requirements")

    sub("Accounts with password hashes (vs base)")
    result = subprocess.run(
        ["sudo","awk","-F:","$2 !~ /^[!*]/ && $2 != \"\" {print $1}",
         f"{vm}/etc/shadow"], capture_output=True, text=True)
    with_pass = result.stdout.strip().splitlines()
    if with_pass:
        ok(f"Accounts with passwords set: {', '.join(with_pass)}")

# ── 8. Cron ───────────────────────────────────────────────────────────────────
def check_cron(vm, base):
    hdr("8. CRON JOBS")
    spool = Path(f"{vm}/var/spool/cron/crontabs")
    if spool.exists():
        result = subprocess.run(["sudo","ls", str(spool)], capture_output=True, text=True)
        for user in result.stdout.splitlines():
            lines = sudoreadlines(f"{spool}/{user}")
            if lines:
                bad(f"User crontab for {user}:")
                for l in lines:
                    print(f"    {l}")

    for f in Path(f"{vm}/etc/cron.d").iterdir():
        lines = sudoreadlines(str(f))
        # flag anything not in the base
        base_f = Path(f"{base}/etc/cron.d/{f.name}")
        if not base_f.exists() and lines:
            warn(f"Non-base cron.d file: {f.name}")
            for l in lines:
                print(f"    {l}")

# ── 9. SUID ───────────────────────────────────────────────────────────────────
def check_suid(vm, base):
    hdr("9. SUID / SGID BINARIES")

    result_vm = subprocess.run(
        ["sudo","find", vm, "-perm","/4000","-type","f"],
        capture_output=True, text=True)
    result_base = subprocess.run(
        ["find", base, "-perm","/4000","-type","f"],
        capture_output=True, text=True)

    vm_suid   = {p.replace(vm,"")   for p in result_vm.stdout.splitlines()}
    base_suid = {p.replace(base,"") for p in result_base.stdout.splitlines()}

    extra = vm_suid - base_suid
    missing = base_suid - vm_suid

    for f in sorted(extra):
        bad(f"SUID not in base: {f}")
    for f in sorted(missing):
        warn(f"SUID in base but missing in VM: {f}")
    if not extra:
        ok("No unexpected SUID binaries")

# ── 10. Hosts / network ───────────────────────────────────────────────────────
def check_network(vm, base):
    hdr("10. HOSTS & NETWORK")

    sub("/etc/hosts")
    vm_hosts   = sudoreadlines(f"{vm}/etc/hosts")
    base_hosts = readlines(f"{base}/etc/hosts")
    for line in vm_hosts:
        if line not in base_hosts:
            warn(f"Non-standard hosts entry: {line}")

    sub("apt sources")
    for f in Path(f"{vm}/etc/apt/sources.list.d").iterdir():
        for line in sudoreadlines(str(f)):
            if "linuxmint" not in line and "ubuntu" not in line and "canonical" not in line:
                bad(f"Suspicious apt source in {f.name}: {line}")

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="CyberPatriot Mint 21 diff tool")
    parser.add_argument("--vm",   default="/mnt/vm_mint",
        help="Mounted practice VM root (default: /mnt/vm_mint)")
    parser.add_argument("--base", default="/tmp/claude-1000/-home-casper/cb86f38e-fca7-4ec9-964b-cdbd97aa5acd/scratchpad/base_mint21",
        help="Clean base image root")
    args = parser.parse_args()

    if not Path(f"{args.vm}/etc").exists():
        print(f"ERROR: VM not mounted at {args.vm}")
        sys.exit(1)
    if not Path(f"{args.base}/etc").exists():
        print(f"ERROR: Base image not found at {args.base}")
        sys.exit(1)

    print(f"\n{BOLD}CyberPatriot Mint 21 — Misconfiguration Report{RST}")
    print(f"VM:   {args.vm}")
    print(f"Base: {args.base}")

    check_users(args.vm, args.base)
    check_sudo(args.vm, args.base)
    check_ssh(args.vm, args.base)
    check_services(args.vm, args.base)
    check_firewall(args.vm, args.base)
    check_packages(args.vm, args.base)
    check_passwords(args.vm, args.base)
    check_cron(args.vm, args.base)
    check_suid(args.vm, args.base)
    check_network(args.vm, args.base)

    print(f"\n{BOLD}{GRN}Done.{RST}\n")

if __name__ == "__main__":
    main()
