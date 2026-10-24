# CyberPatriot Live Auditor

Scans a live Linux Mint 21 VM for common CyberPatriot misconfigurations and offers to auto-fix them. Built for CP19 Practice Round E (Linux Mint 21).

---

## Quick Start — one line, paste into a terminal on the VM

```bash
curl -fsSL https://raw.githubusercontent.com/School-User/cp19-mint-diff/main/setup.sh | sh
```

Shows a menu (audit / compare / forensics / users / undo / both), asks for your sudo password itself, runs the tool, and cleans up after. Pick a tool directly with `| sh -s audit`, `| sh -s compare`, `| sh -s forensics`, `| sh -s users`, `| sh -s undo`. Report-only: `curl ... | DRY_RUN=1 sh`. Or run files directly: `sudo bash audit.sh`. Fix just one category, no prompts: `curl ... | FIX_ONLY=Firewall sh -s audit` (categories: SSH, Firewall, Services, Packages, "Password policy", vsftpd, SUID, Hardening, Media — comma-separate for more than one). Apply the preconfigured secure password policy with no detection and no prompt: `curl ... | PW_POLICY=secure sh -s audit`.

| Tool | What it does | Changes things? |
|---|---|---|
| `audit.sh` | Finds misconfigurations (SSH, UFW, services, packages, password policy, SUID, hardening) and offers to fix each | Yes, asks per fix |
| `compare_live.sh` | Shows how the live VM differs from a clean Mint 21 base, offers to restore | Yes, asks per item |
| `forensics.sh` | Read-only helper for forensics questions: newest/hidden/media files, search (plain + base64), file info/hashes, decode, users, persistence, network, browser history | **No, read-only** |
| `useraudit.sh` | Paste the README's authorized users/admins; it flags unauthorized accounts and wrong admin rights and **prints** the commands to run | **No, prints commands only** |
| `undo.sh` | Reverses a previous audit/compare run from its backup folder (files, services, packages, SUID, media, UFW) | Yes, asks per step |

Every run is saved to `~/cp-reports/<tool>-<time>.txt` (colors stripped). Turn off with `NO_REPORT=1`, move with `REPORT_DIR=...`.

**None of the tools ever modify user accounts.** (`setup.sh` is plain POSIX `sh`, so it works with Mint's `dash`.)

---

## useraudit.sh and undo.sh

```bash
sudo bash useraudit.sh                    # paste the README's user sections, Ctrl-D
sudo bash useraudit.sh --file readme.txt  # or read them from a file
sudo bash undo.sh                         # pick a backup set;  `undo.sh last` = newest
```

`useraudit.sh` understands lines under "Authorized Administrators" / "Authorized Users" (extra words like `(you)` or `password: ...` are ignored) and prints the `gpasswd`, `deluser`, `usermod`, `adduser` commands for you to review. It runs none of them and never changes the auto-login user.

`audit.sh` and `compare_live.sh` log everything they change to `/root/cp-*-backup-<time>/`. `undo.sh` restores edited files, removes files the tools created, restores permissions and SUID bits, re-enables services, reinstalls removed packages, and puts moved media files back (media is moved into the backup folder, not deleted). It skips the account files, and it can't undo runtime sysctl values (reboot) or the `libpam-pwquality` install. Tested: running every fix and then `undo.sh` returns the system to a byte-identical state.

---

## forensics.sh

```bash
sudo bash forensics.sh                 # menu
sudo bash forensics.sh report | tee report.txt
sudo bash forensics.sh search "secret" # names + contents + base64 form
sudo bash forensics.sh info /path/file # owner, times, hashes, strings, archive listing
sudo bash forensics.sh decode "aGk="   # base64 / hex / rot13 / rot47 / url / reverse
```

Other commands: `questions` `newest [N]` `hidden` `media` `users` `persist` `net` `browser`. Browser history is read from temp copies. It never writes to the system.

---

## What it checks & fixes

| # | Category | Auto-fix |
|---|----------|----------|
| 1 | Users: non-authorized sudo/adm/lpadmin members, extra UID 0, empty passwords | No, report only (prints the manual command) |
| 2 | SSH (PermitRootLogin, PermitEmptyPasswords, X11Forwarding, PermitUserEnvironment) | Yes |
| 3 | UFW firewall | Yes |
| 4 | Services (vsftpd, openvpn, telnet/rsh sockets; optional avahi, cups-browsed) | Yes |
| 5 | Prohibited packages (netcat, wireshark, ftp, telnet, vsftpd, zangband, hacking tools) | Yes (no autoremove) |
| 6 | Password policy (login.defs, pam_pwquality, `nullok`) | Yes |
| 7 | vsftpd config | Yes |
| 8 | Unexpected SUID binaries | Yes |
| 9 | Hardening: sysctl, guest login, apt auto-update, /etc/shadow etc. perms | Yes |
| 10 | NOPASSWD sudoers, media files in /home, cron jobs, listening ports | Media delete only (default N) |

Each fix asks `Fix: ...? [y/N]`. Edited files are backed up to `/root/cp-audit-backup-<timestamp>/`.

```bash
sudo bash audit.sh                              # interactive
sudo DRY_RUN=1 bash audit.sh                    # report only
sudo AUTH_ADMINS="benjamin alice" bash audit.sh # admins the README allows (default: benjamin)
```

README rules to respect: don't change the auto-login user's password, don't remove authorized users or home dirs, don't change timezone/date/time.

User accounts are **never auto-modified**. Review them against the real README.

---

## compare_live.sh — live image vs base

Shows what is different between the live VM and a clean Mint 21 base, then offers to change it.

```bash
sudo bash compare_live.sh                       # interactive
sudo DRY_RUN=1 bash compare_live.sh             # differences only
sudo BASE_ROOT=/mnt/clean bash compare_live.sh  # use a mounted clean Mint 21 rootfs as the base
curl -fsSL https://raw.githubusercontent.com/School-User/cp19-mint-diff/main/setup.sh | sudo bash -s compare
```

Without `BASE_ROOT`, "base" = what the installed packages themselves ship (pristine config files) plus the install date (packages added after the base image was built). Sections: config diffs (offer to restore the base version), modified program files (offer reinstall), unowned SUID/SGID, added packages (offer removal, guarded by an `apt-get -s` simulation), extra enabled services, users (read-only).

**It never touches users.** passwd/shadow/group/sudoers, home dirs and login config are protected; package operations run under a guard that restores `passwd/shadow/group/gshadow/subuid/subgid` byte-for-byte if a package script changes them (vsftpd's removal script deletes the `ftp` account, for example). The summary prints `USERS UNTOUCHED` after verifying before/after hashes. Packages are removed, not purged.

It cannot flag insecure stock defaults (UFW off, `PASS_MAX_DAYS 99999`, vsftpd `ssl_enable=NO`); `audit.sh` covers those.

---

## CP19 Practice Round E — Known Findings

These are the actual misconfigurations found in the CP19 Practice Round E Mint 21 VM image (`cp19_pr_e_mint21`).

### VM Info
- Display name: CyberPatriot Practice Round Mint 21
- OS: Linux Mint 21
- Kernel: 5.15.0-41-generic
- RAM: 4 GB | vCPUs: 2
- Network: NAT (e1000)
- Disk: `Mint 21 64-bit-cl4.vmdk` (twoGbMaxExtentSparse, ~24 GB)
- Partition layout: p1=487M (EFI), p2=1.9G (swap), p3=21.6G (root)

---

### CRITICAL findings

#### SSH (`/etc/ssh/sshd_config`)
| Setting | VM value | Should be |
|---------|----------|-----------|
| PermitRootLogin | `yes` | `no` |
| PermitEmptyPasswords | `yes` | `no` |
| X11Forwarding | `yes` | `no` |

#### Firewall
- `/etc/ufw/ufw.conf` → `ENABLED=no` — firewall completely disabled

#### Services enabled (should not be)
- `vsftpd.service` — FTP server running
- `openvpn.service` — unauthorized VPN
- `avahi-daemon` — mDNS/Bonjour discovery (minor)
- `cups-browsed` — network printer browsing (minor)

#### vsftpd (`/etc/vsftpd.conf`)
- `ssl_enable=NO` — FTP not encrypted

---

### HIGH findings

#### Unauthorized sudo members (`/etc/group`, `sudoers.d/`)
Only **benjamin** should be in the admin/sudo group per the README.

Extra members found:
- `dscott`
- `hspecter`
- `jpearson`
- `llitt`

Fix manually:
```bash
sudo deluser <username> sudo
```

---

### MEDIUM findings

#### Prohibited packages installed
| Package | Category |
|---------|----------|
| `netcat-openbsd` | Network tool |
| `wireshark` | Packet capture |
| `wireshark-qt` | Packet capture |
| `ftp` | Insecure file transfer |
| `tnftp` | Insecure file transfer |
| `telnet` | Insecure remote access |
| `vsftpd` | FTP server |
| `zangband` | Prohibited game |

#### Password policy (`/etc/login.defs`)
| Setting | VM value | Should be |
|---------|----------|-----------|
| PASS_MAX_DAYS | `99999` | `90` |
| PASS_MIN_DAYS | `0` | `7` |
| PASS_WARN_AGE | (default) | `14` |

#### PAM (`/etc/pam.d/common-password`)
- `pam_pwquality` not configured — no password complexity enforcement

---

### LOW findings

- 17 non-system users all with `/bin/bash` shells (review against README)
- `PASS_MIN_DAYS=0` (allows immediate password changes)

---

### Scoring binary (informational)

The scoring engine lives at `/opt/CyberPatriot/`:
- `ccsclient` — ELF 64-bit, statically linked, stripped, ~1.5 MB Nim binary. Contacts the scoring server to fetch the README and report scores.
- `scoringresource.dat` — 8008 bytes, entropy 7.977/8.0 (AES-encrypted). Contains the scoring criteria; decrypted server-side or at runtime.
- `readme.html` — placeholder only. Real README is delivered by the scoring server when `ccsclient` connects.

> **Note:** Do not modify or remove files in `/opt/CyberPatriot/` — the scoring engine needs them to report your score.

---

## Files

| File | Purpose |
|------|---------|
| `audit.sh` | Live-machine auditor — scans for misconfigurations and offers to fix |
| `compare_live.sh` | Live image vs clean Mint 21 base — shows differences, offers to restore |
| `forensics.sh` | Read-only forensics helper (see above) |
| `useraudit.sh` | Read-only user audit against the README; prints commands (see above) |
| `undo.sh` | Reverses a previous audit/compare run (see above) |
| `setup.sh` | One-line launcher: menu or `sh -s audit/compare/forensics/both` |
| `compare.py` | Offline comparison tool (mounted VMDK vs base image) |
| `mount_vm.sh` | Mounts/unmounts the VMDK via qemu-nbd |
| `mint_diff.sh` | Bash analysis script, writes findings to `findings.txt` |
| `README.md` | This file |

---

## Offline mode (analyze VMDK without booting)

Used to inspect the VM image from another machine (e.g. the 1TB drive at `/mnt/1tb/`).

```bash
# 1. Mount the VMDK
sudo bash mount_vm.sh mount
# Mounts to /mnt/vm_mint (partition p3, the root filesystem)

# 2. Run comparison against Ubuntu 22.04 base
python3 compare.py --vm /mnt/vm_mint --base /path/to/base_mint21

# 3. Unmount when done
sudo bash mount_vm.sh unmount
```

To build the base image (one-time):
```bash
mkdir -p base_mint21
docker export $(docker create ubuntu:22.04) | sudo tar -xf - -C base_mint21
```

---

## Requirements

**Live mode (`audit.sh`):**
- Linux (runs on the scored VM itself)
- `bash`, `sudo`, standard GNU tools

**Offline mode (`compare.py`, `mount_vm.sh`):**
- `qemu-nbd`, `python3`
- `docker` (to pull Ubuntu 22.04 base image)

---

## Fix reference (manual steps)

For things the script doesn't auto-fix:

```bash
# Remove user from sudo group
sudo deluser <username> sudo

# Lock an account
sudo passwd -l <username>

# Set password expiry on existing users
sudo chage -M 90 -m 7 -W 14 <username>

# Check what's listening on the network
ss -tlnp

# Check all enabled services
systemctl list-unit-files --state=enabled
```

---

## Practice VM notes (cp19_pr_e_mint21)

- `ccsclient` (scoring client) has been stripped from the VM; originals are in `ccs_extracted/`, README shortcut backup in `readme_backup/`. The VM's README is only the placeholder because the real one comes from the scoring server.
- On first boot after the practice window expired, ccsclient's destruct logic zeroed the partition table, MBR and the `/boot` inode table. Recovery: restore GPT from the backup header (`gdisk`), rebuild the ext4 group descriptors from the backup copy (clear UNINIT flags, then `e2fsck -fy`), recreate `/boot`, reinstall kernel and BIOS GRUB. The image boots via BIOS (not UEFI); `p4` is a bios_grub partition.
- Do not run `sysctl --system` from a chroot that bind-mounts `/proc`: it applies to the host kernel.
