#!/usr/bin/env bash
# CyberPatriot Mint 21 diff tool
# Compares a mounted practice VM against known-good Linux Mint 21 defaults.
#
# Usage:
#   Step 1 (once, needs sudo):
#     sudo modprobe nbd max_part=8
#     sudo qemu-nbd -c /dev/nbd0 "/mnt/1tb/cp19_pr_e_mint21/Mint 21 64-bit-cl4.vmdk"
#     sudo partprobe /dev/nbd0
#     sudo mkdir -p /mnt/vm_mint && sudo mount /dev/nbd0p2 /mnt/vm_mint
#   Step 2 (this script):
#     bash ~/Projects/cp19-mint-diff/mint_diff.sh [/mnt/vm_mint]
#
# Cleanup when done:
#     sudo umount /mnt/vm_mint && sudo qemu-nbd -d /dev/nbd0

set -euo pipefail

VM="${1:-/mnt/vm_mint}"
OUT="${HOME}/Projects/cp19-mint-diff/findings.txt"
IDA="${HOME}/ida-free-9.4/ida"
SCRATCH="${HOME}/Projects/cp19-mint-diff/bin_samples"

mkdir -p "$(dirname "$OUT")" "$SCRATCH"
> "$OUT"

log()  { echo "$*" | tee -a "$OUT"; }
head_() { log ""; log "════════════════════════════════════════"; log "  $*"; log "════════════════════════════════════════"; }

if [[ ! -d "$VM/etc" ]]; then
    echo "ERROR: $VM doesn't look like a mounted Linux root. Did you run the mount commands?"
    exit 1
fi

head_ "1. USER ACCOUNTS"

# Mint 21 default users: root + standard system accounts + the competition user (usually ~1000)
# Flag: any UID=0 that isn't root, any extra non-system accounts
log "--- /etc/passwd (non-system users, UID >= 1000) ---"
awk -F: '$3 >= 1000 {print}' "$VM/etc/passwd" | tee -a "$OUT"

log ""
log "--- UID 0 accounts (should be ONLY root) ---"
awk -F: '$3 == 0 {print $1}' "$VM/etc/passwd" | tee -a "$OUT"

log ""
log "--- Accounts with interactive shells ---"
grep -E '(/bin/bash|/bin/sh|/bin/zsh|/bin/fish)$' "$VM/etc/passwd" | tee -a "$OUT"

head_ "2. SUDO PRIVILEGES"
log "--- /etc/sudoers ---"
grep -v '^#\|^$' "$VM/etc/sudoers" 2>/dev/null | tee -a "$OUT" || log "(no sudoers)"
log ""
log "--- /etc/sudoers.d/ ---"
for f in "$VM/etc/sudoers.d/"*; do
    [[ -f "$f" ]] || continue
    log "  >> $f"
    grep -v '^#\|^$' "$f" | tee -a "$OUT"
done

head_ "3. SSH CONFIGURATION"
log "--- sshd_config key settings ---"
if [[ -f "$VM/etc/ssh/sshd_config" ]]; then
    grep -iE '^\s*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|AllowGroups|Port|PermitEmptyPasswords|X11Forwarding|Protocol)' \
        "$VM/etc/ssh/sshd_config" | tee -a "$OUT"
else
    log "(no sshd_config)"
fi

log ""
log "--- Authorized keys in user homes ---"
find "$VM/home" "$VM/root" -name "authorized_keys" 2>/dev/null | while read -r f; do
    log "  >> $f"
    cat "$f" | tee -a "$OUT"
done

head_ "4. CRON JOBS"
log "--- /etc/crontab ---"
cat "$VM/etc/crontab" 2>/dev/null | grep -v '^#\|^$' | tee -a "$OUT" || log "(empty)"
log ""
log "--- /var/spool/cron/crontabs ---"
ls "$VM/var/spool/cron/crontabs/" 2>/dev/null | tee -a "$OUT" || log "(empty)"
for f in "$VM/var/spool/cron/crontabs/"*; do
    [[ -f "$f" ]] || continue
    log "  >> $(basename "$f")"
    grep -v '^#\|^$' "$f" | tee -a "$OUT"
done
log ""
log "--- /etc/cron.d/ ---"
for f in "$VM/etc/cron.d/"*; do
    [[ -f "$f" ]] || continue
    log "  >> $f"; grep -v '^#\|^$' "$f" | tee -a "$OUT"
done

head_ "5. ENABLED SERVICES (systemd)"
if [[ -d "$VM/etc/systemd/system" ]]; then
    log "--- Enabled unit symlinks ---"
    find "$VM/etc/systemd/system" -name "*.service" -o -name "*.timer" | \
        xargs -I{} basename {} | sort | tee -a "$OUT"
else
    log "(systemd dir not found)"
fi

head_ "6. INSTALLED PACKAGES — anything suspicious"
if [[ -f "$VM/var/lib/dpkg/status" ]]; then
    log "--- Manually-suspicious packages (netcat, ncat, socat, nmap, hydra, john, etc.) ---"
    grep -A1 '^Package:' "$VM/var/lib/dpkg/status" | grep '^Package:' | \
        awk '{print $2}' | grep -iE \
        'netcat|ncat|socat|nmap|hydra|john|hashcat|aircrack|wireshark|metasploit|beef|sqlmap|nikto|masscan|gobuster|dirbuster|medusa|hping|scapy|ftp|telnet|rsh-|rlogin' \
        | tee -a "$OUT" || log "(none found)"
else
    log "(dpkg status not found)"
fi

head_ "7. SUID / SGID BINARIES"
log "--- Files with SUID bit (compare against standard Mint 21 list) ---"
# Standard Mint 21 expected SUID set:
EXPECTED_SUID=(
  /bin/fusermount3 /bin/mount /bin/su /bin/umount
  /usr/bin/chfn /usr/bin/chsh /usr/bin/gpasswd /usr/bin/newgrp
  /usr/bin/passwd /usr/bin/sudo /usr/bin/pkexec
  /usr/lib/dbus-1.0/dbus-daemon-launch-helper
  /usr/lib/openssh/ssh-keysign
  /usr/lib/policykit-1/polkit-agent-helper-1
  /usr/lib/eject/dmcrypt-get-device
  /usr/sbin/pppd
)
FOUND_SUID=()
while IFS= read -r f; do
    rel="${f#$VM}"
    FOUND_SUID+=("$rel")
done < <(find "$VM" \( -path "$VM/proc" -o -path "$VM/sys" -o -path "$VM/dev" -o -path "$VM/run" \) -prune -o -perm /4000 -type f -print 2>/dev/null)

log "Found SUID files:"
printf '  %s\n' "${FOUND_SUID[@]}" | tee -a "$OUT"
log ""
log "UNEXPECTED (not in standard list):"
for f in "${FOUND_SUID[@]}"; do
    match=0
    for e in "${EXPECTED_SUID[@]}"; do
        [[ "$f" == "$e" ]] && match=1 && break
    done
    [[ $match -eq 0 ]] && log "  *** $f ***"
done | tee -a "$OUT"

head_ "8. WORLD-WRITABLE FILES (outside /tmp /proc /sys)"
log "--- World-writable non-symlink files ---"
find "$VM" \( -path "$VM/proc" -o -path "$VM/sys" -o -path "$VM/tmp" \
              -o -path "$VM/run" -o -path "$VM/dev" \) -prune -o \
     -type f -perm -o+w -print 2>/dev/null | head -40 | tee -a "$OUT"

head_ "9. /ETC/HOSTS AND NETWORK"
log "--- /etc/hosts ---"
cat "$VM/etc/hosts" | grep -v '^#\|^$' | tee -a "$OUT"
log ""
log "--- /etc/resolv.conf ---"
cat "$VM/etc/resolv.conf" 2>/dev/null | grep -v '^#\|^$' | tee -a "$OUT" || log "(not found)"
log ""
log "--- /etc/apt/sources.list (unauthorized repos?) ---"
grep -v '^#\|^$' "$VM/etc/apt/sources.list" 2>/dev/null | tee -a "$OUT" || log "(not found)"
find "$VM/etc/apt/sources.list.d/" -name "*.list" 2>/dev/null | while read -r f; do
    log "  >> $f"
    grep -v '^#\|^$' "$f" | tee -a "$OUT"
done

head_ "10. FIREWALL (UFW)"
if [[ -f "$VM/etc/ufw/ufw.conf" ]]; then
    log "--- ufw.conf ---"
    grep -v '^#\|^$' "$VM/etc/ufw/ufw.conf" | tee -a "$OUT"
    log "--- ufw/user.rules (custom rules) ---"
    cat "$VM/etc/ufw/user.rules" 2>/dev/null | grep -v '^#\|^$' | tee -a "$OUT"
else
    log "(ufw not configured)"
fi

head_ "11. MEDIA / HIDDEN FILES IN HOMES"
log "--- Unusual hidden files in /home and /root ---"
find "$VM/home" "$VM/root" -maxdepth 3 \( -name ".bash_history" -o -name ".viminfo" \
     -o -name "*.sh" -o -name "*.py" -o -name "*.pl" \) 2>/dev/null | tee -a "$OUT"

head_ "12. RECENT FILE MODIFICATIONS (mtime < 7 days relative to image date)"
log "--- Files modified after 2026-09-21 (image last modified Sep 28) ---"
find "$VM/etc" "$VM/home" "$VM/root" "$VM/usr/local" \
     -newer "$VM/etc/hostname" -not -type d 2>/dev/null | head -50 | tee -a "$OUT"

head_ "13. IDA FREE — SUSPICIOUS BINARY ANALYSIS"
# Collect non-standard SUID binaries + any executables in unusual locations
SUSPICIOUS_BINS=()
for f in "${FOUND_SUID[@]}"; do
    match=0
    for e in "${EXPECTED_SUID[@]}"; do [[ "$f" == "$e" ]] && match=1 && break; done
    [[ $match -eq 0 ]] && SUSPICIOUS_BINS+=("$VM$f")
done

# Also check for executables in home dirs and /tmp
while IFS= read -r f; do SUSPICIOUS_BINS+=("$f"); done < \
    <(find "$VM/home" "$VM/root" "$VM/tmp" -type f -executable 2>/dev/null)

if [[ ${#SUSPICIOUS_BINS[@]} -gt 0 ]]; then
    log "Suspicious executables found — copying for IDA Free analysis:"
    for f in "${SUSPICIOUS_BINS[@]}"; do
        bn="$(basename "$f")"
        dest="$SCRATCH/$bn"
        cp "$f" "$dest" 2>/dev/null && log "  Copied: $dest" || log "  (could not copy $f)"
    done
    log ""
    log "To open in IDA Free:"
    log "  $IDA <binary>"
    log ""
    log "Quick ELF check on each:"
    for f in "$SCRATCH"/*; do
        [[ -f "$f" ]] || continue
        file "$f" | tee -a "$OUT"
        # Check for suspicious strings
        strings "$f" 2>/dev/null | grep -iE \
            '(nc |netcat|bash -i|/dev/tcp|reverse.shell|wget|curl.*sh|chmod 777|base64)' \
            | head -5 | while read -r s; do log "  [!] string: $s"; done
    done
else
    log "No suspicious binaries found."
fi

head_ "SUMMARY"
log "Full findings written to: $OUT"
log "Suspicious binaries for IDA Free: $SCRATCH/"
log ""
log "Next steps:"
log "  1. Review flagged items above against the Mint 21 scoring checklist"
log "  2. Open suspicious binaries in IDA:  $IDA $SCRATCH/<binary>"
log "  3. Fix issues in the LIVE VM (not this mount) and re-check"
