#!/usr/bin/env bash
# CyberPatriot Live Auditor v2 — runs ON the scored Linux Mint 21 VM, as root.
#   sudo bash audit.sh                 interactive: asks before each fix
#   sudo DRY_RUN=1 bash audit.sh       report only, change nothing
#   sudo AUTH_ADMINS="benjamin bob" bash audit.sh   admins allowed by the README
#   sudo FIX_ONLY="Firewall" bash audit.sh   only fix this category (comma-separated), no prompts,
#                                             everything else is scanned and reported but left alone
#   Categories: SSH, Firewall, Services, Packages, "Password policy", vsftpd, SUID, Hardening, Media
#   sudo PW_POLICY=secure bash audit.sh      apply the preconfigured secure password policy (no prompt,
#                                             no detection): pwquality, 5-try lockout, history, SHA-256
# User accounts are NEVER modified — only reported, with the manual command.
# Every file edited is first copied to /root/cp-audit-backup-<timestamp>/.
#
# Competition rules (README): don't change the auto-login user's password,
# don't remove authorized users/home dirs, don't change timezone/date/time,
# don't stop the CCS client.

set -uo pipefail

R=$'\033[0;31m' G=$'\033[0;32m' Y=$'\033[1;33m' B=$'\033[1;34m' N=$'\033[0m'
bad()  { echo -e "  ${R}[!]${N} $*"; }
warn() { echo -e "  ${Y}[~]${N} $*"; }
ok()   { echo -e "  ${G}[+]${N} $*"; }
hdr()  { echo -e "\n${B}== $* ==${N}"; }

[[ $EUID -eq 0 ]] || { echo -e "${R}Run with sudo.${N}"; exit 1; }

DRY_RUN=${DRY_RUN:-0}
FIX_ONLY=${FIX_ONLY:-}
PW_POLICY=${PW_POLICY:-}
[[ -z $PW_POLICY || $PW_POLICY == secure ]] || { echo -e "${R}PW_POLICY must be empty or 'secure'.${N}"; exit 1; }
AUTH_ADMINS=${AUTH_ADMINS:-benjamin}
if ( : </dev/tty ) 2>/dev/null; then exec 4</dev/tty; else exec 4<&0; fi   # prompts survive curl | bash

# --- access gate: the script will not run until the team passphrase is typed. Only a salted SHA-256 crypt
# hash is stored here, never the passphrase. Set GATE_HASH with:  openssl passwd -5 "<passphrase>"
GATE_HASH=''
gate() {
    [[ -n $GATE_HASH ]] || { echo "error: GATE_HASH is not set in this copy of audit.sh; refusing to run." >&2; exit 1; }
    local salt pp
    salt=$(cut -d'$' -f3 <<<"$GATE_HASH")
    read -rsp "Team passphrase: " pp <&4; echo
    if [[ $(openssl passwd -5 -salt "$salt" "$pp" 2>/dev/null) != "$GATE_HASH" ]]; then
        echo "Wrong passphrase." >&2; exit 1
    fi
    unset pp
}
gate
BK=/root/cp-audit-backup-$(date +%Y%m%d-%H%M%S)
ISSUES=()

# --- saved report: everything printed is also written (colors stripped) to ~/cp-reports/ ----------
REPORT=""
start_report() {
    [[ ${NO_REPORT:-0} == 1 ]] && return
    local who=${SUDO_USER:-root} dir
    dir=${REPORT_DIR:-$(getent passwd "$who" | cut -d: -f6)/cp-reports}
    mkdir -p "$dir" && chown "$who" "$dir" 2>/dev/null
    REPORT="$dir/$1-$(date +%Y%m%d-%H%M%S).txt"; : >"$REPORT"; chown "$who" "$REPORT" 2>/dev/null
    exec > >(tee >(sed -u 's/\x1b\[[0-9;]*m//g' >>"$REPORT")) 2>&1
}
end_report() { [[ -n $REPORT ]] && echo "  Report saved: $REPORT"; }

# --- action log: lets undo.sh reverse what this run did (tab-separated lines in $BK/actions.log) ----
logact() { mkdir -p "$BK"; ( IFS=$'\t'; echo "$*" ) >>"$BK/actions.log"; }
newfile() { [[ -e $1 ]] && backup "$1" || logact NEWFILE "$1"; }   # file this run creates (or backs up if it exists)
in_chroot() { [[ $(stat -c %d:%i / 2>/dev/null) != $(stat -c %d:%i /proc/1/root/. 2>/dev/null) ]]; }

start_report audit

backup() { [[ -e $BK$1 ]] && return 0; mkdir -p "$BK$(dirname "$1")"; cp -a "$1" "$BK$1" 2>/dev/null || true; }   # first copy wins

# Package maintainer scripts can delete system accounts (e.g. vsftpd removes "ftp"). Run a command,
# then put the account files back exactly as they were, so users/groups are never altered.
exec 5>&1
keep_users() {
    local d f rc; d=$(mktemp -d)
    for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/subuid /etc/subgid; do [[ -e $f ]] && cp -a "$f" "$d/"; done
    "$@"; rc=$?
    for f in "$d"/*; do
        cmp -s "$f" "/etc/${f##*/}" || { cp -a "$f" "/etc/${f##*/}"; warn "package scripts changed ${f##*/}; restored it exactly" >&5; }
    done
    rm -rf "$d"; return $rc
}

ask_fix() {  # ask_fix "Category" "label" fn [args...]
    local cat=$1 label=$2 ans=""; shift 2
    if [[ $DRY_RUN == 1 ]]; then warn "[dry-run] would fix: $label"; return; fi
    if [[ -n $FIX_ONLY ]]; then
        local match=0 c; IFS=',' read -ra _cats <<<"$FIX_ONLY"
        for c in "${_cats[@]}"; do [[ ${cat,,} == "$(echo "$c" | xargs | tr A-Z a-z)" ]] && match=1; done
        if [[ $match == 1 ]]; then
            if "$@"; then ok "Done ($cat): $label"; else bad "Failed ($cat): $label"; fi
        else
            warn "Skipped (FIX_ONLY=$FIX_ONLY excludes $cat): $label"
        fi
        return
    fi
    read -rp "  Fix: $label? [y/N] " ans <&4
    if [[ $ans =~ ^[Yy]$ ]]; then
        if "$@"; then ok "Done: $label"; else bad "Failed: $label"; fi
    else
        warn "Skipped: $label"
    fi
}

in_list() { local x=$1; shift; local i; for i in "$@"; do [[ $i == "$x" ]] && return 0; done; return 1; }
pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }
svc_on() {
    systemctl is-enabled --quiet "$1" 2>/dev/null && return 0
    systemctl list-unit-files --no-legend "$1" 2>/dev/null | grep -q . && systemctl is-active --quiet "$1" 2>/dev/null
}

# replace "key <sep> value" if present, else append (for flat key/value files)
set_kv() {  # file key value [sep]
    local f=$1 k=$2 v=$3 sep=${4:- } pat
    if [[ $sep == "=" ]]; then pat="^\s*$k\s*="; else pat="^\s*$k\s+"; sep=" "; fi
    backup "$f"
    if grep -qE "$pat" "$f" 2>/dev/null; then sed -i -E "s|$pat.*|$k$sep$v|" "$f"
    else echo "$k$sep$v" >> "$f"; fi
}

# ============================================================================
hdr "1. USER ACCOUNTS (report only)"
# ============================================================================
echo "  Login users (UID >= 1000):"
awk -F: '$3>=1000 && $1!="nobody" {printf "    %-16s uid=%s shell=%s\n",$1,$3,$7}' /etc/passwd

read -ra AUTH <<<"$AUTH_ADMINS"
echo; echo "  Admin groups (authorized admins: ${AUTH[*]}):"
for g in sudo adm lpadmin admin; do
    members=$(getent group "$g" | cut -d: -f4)
    [[ -z $members ]] && continue
    for m in ${members//,/ }; do
        [[ $m == syslog ]] && continue
        if in_list "$m" "${AUTH[@]}"; then ok "$g: $m"
        else bad "$g: $m is NOT an authorized admin  ->  gpasswd -d $m $g"; ISSUES+=("Users"); fi
    done
done

extra0=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd)
[[ -n $extra0 ]] && { bad "extra UID 0 accounts: $extra0"; ISSUES+=("Users"); }

empty=$(awk -F: '$2==""{print $1}' /etc/shadow)
[[ -n $empty ]] && { bad "accounts with EMPTY password: $empty  ->  passwd -l <user> (not the auto-login user!)"; ISSUES+=("Users"); }

sh_sys=$(awk -F: '$3<1000 && $3!=0 && $7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1}' /etc/passwd)
[[ -n $sh_sys ]] && warn "system accounts with a login shell: $sh_sys"

warn "Compare the user list against the README. Do NOT touch the auto-login user's password."

# ============================================================================
hdr "2. SSH"
# ============================================================================
if [[ -f /etc/ssh/sshd_config ]]; then
    sshd_val() {
        local v; v=$(sshd -T 2>/dev/null | awk -v k="$1" '$1==k{print $2; exit}')
        [[ -z $v ]] && v=$(grep -iE "^\s*$1\s" /etc/ssh/sshd_config | tail -1 | awk '{print $2}')
        echo "${v,,}"
    }
    ssh_bad=0
    for k in permitrootlogin permitemptypasswords x11forwarding permituserenvironment; do
        v=$(sshd_val "$k")
        if [[ $v == yes ]]; then bad "$k = yes"; ssh_bad=1; else ok "$k = ${v:-default}"; fi
    done
    fix_ssh() {
        local f=/etc/ssh/sshd_config kv k v
        backup "$f"
        for kv in "PermitRootLogin no" "PermitEmptyPasswords no" "X11Forwarding no" "PermitUserEnvironment no"; do
            read -r k v <<<"$kv"
            if grep -qiE "^\s*$k\s" "$f"; then sed -i -E "s|^\s*$k\s.*|$k $v|I" "$f"
            else sed -i "1i $k $v" "$f"; fi
        done
        mkdir -p /etc/ssh/sshd_config.d /run/sshd
        newfile /etc/ssh/sshd_config.d/00-cp-hardening.conf
        printf 'PermitRootLogin no\nPermitEmptyPasswords no\nX11Forwarding no\nPermitUserEnvironment no\n' \
            > /etc/ssh/sshd_config.d/00-cp-hardening.conf
        sshd -t && { systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true; }
    }
    [[ $ssh_bad == 1 ]] && { ISSUES+=("SSH"); ask_fix "SSH" "SSH hardening" fix_ssh; }
else
    ok "sshd not installed"
fi

# ============================================================================
hdr "3. FIREWALL (UFW)"
# ============================================================================
if ufw status 2>/dev/null | head -1 | grep -qi "inactive"; then
    bad "UFW is disabled"; ISSUES+=("Firewall")
    fix_ufw() {
        if in_chroot; then warn "chroot detected: not touching the firewall"; return 1; fi
        ufw default deny incoming && ufw default allow outgoing && ufw --force enable && logact UFW_ENABLED
    }
    ask_fix "Firewall" "enable UFW (default deny incoming)" fix_ufw
else
    ok "UFW: $(ufw status 2>/dev/null | head -1)"
fi

# ============================================================================
hdr "4. SERVICES"
# ============================================================================
BADSVC=(); OPTSVC=()
for s in vsftpd openvpn telnet.socket rsh.socket rlogin.socket rexec.socket proftpd tftpd-hpa; do
    svc_on "$s" && { bad "$s enabled/running"; BADSVC+=("$s"); }
done
for s in avahi-daemon cups-browsed; do
    svc_on "$s" && { warn "$s enabled/running (disable unless README needs it)"; OPTSVC+=("$s"); }
done
for s in apache2 nginx smbd nmbd snmpd postfix mysql mariadb postgresql nfs-server rpcbind bluetooth; do
    svc_on "$s" && warn "$s is running — verify the README requires it"
done
dis_svcs() {
    local s en act
    for s in "$@"; do
        systemctl is-enabled --quiet "$s" 2>/dev/null && en=1 || en=0
        systemctl is-active --quiet "$s" 2>/dev/null && act=1 || act=0
        systemctl disable --now "$s" 2>/dev/null
        systemctl is-enabled --quiet "$s" 2>/dev/null || { [[ $en == 1 || $act == 1 ]] && logact SVC "$s" "$en" "$act"; }
    done; return 0
}
if ((${#BADSVC[@]})); then ISSUES+=("Services"); ask_fix "Services" "disable ${BADSVC[*]}" dis_svcs "${BADSVC[@]}"; fi
if ((${#OPTSVC[@]})); then ask_fix "Services" "also disable optional ${OPTSVC[*]}" dis_svcs "${OPTSVC[@]}"; fi
((${#BADSVC[@]}+${#OPTSVC[@]})) || ok "no prohibited services running"

# ============================================================================
hdr "5. PROHIBITED PACKAGES"
# ============================================================================
PKGS=(netcat-openbsd netcat-traditional ncat wireshark wireshark-qt wireshark-common tshark
      ftp tnftp telnet telnetd vsftpd proftpd-basic nmap zenmap masscan hydra john hashcat
      aircrack-ng ophcrack nikto zangband nethack-console angband)
FOUND=()
for p in "${PKGS[@]}"; do pkg_installed "$p" && { bad "$p installed"; FOUND+=("$p"); }; done
rm_pkgs() { keep_users env DEBIAN_FRONTEND=noninteractive apt-get remove -y "$@" && logact PKG "$@"; }   # no --purge
if ((${#FOUND[@]})); then ISSUES+=("Packages"); ask_fix "Packages" "remove ${FOUND[*]}" rm_pkgs "${FOUND[@]}"; else ok "none found"; fi

# ============================================================================
hdr "6. PASSWORD POLICY"
# ============================================================================
LD=/etc/login.defs; pw_bad=0
chk_def() {  # key want_op(max|min) value
    local cur; cur=$(awk -v k="$1" '$1==k{print $2}' "$LD" | tail -1)
    if [[ -z $cur ]] || { [[ $2 == max ]] && ((cur > $3)); } || { [[ $2 == min ]] && ((cur < $3)); }; then
        bad "$1 = ${cur:-unset} (want $([[ $2 == max ]] && echo '<=' || echo '>=') $3)"; pw_bad=1
    else ok "$1 = $cur"; fi
}
chk_def PASS_MAX_DAYS max 90; chk_def PASS_MIN_DAYS min 7; chk_def PASS_WARN_AGE min 14

if grep -q 'pam_pwquality\|pam_cracklib' /etc/pam.d/common-password; then ok "pam_pwquality configured"
else bad "no password complexity module in common-password"; pw_bad=1; fi
if grep -qE '^[^#]*pam_unix\.so.*nullok' /etc/pam.d/common-auth /etc/pam.d/common-password 2>/dev/null; then
    bad "nullok present (blank passwords can log in)"; pw_bad=1; fi
if ! grep -q 'pam_faillock' /etc/pam.d/common-auth; then bad "no account lockout (pam_faillock)"; pw_bad=1; fi
if ! grep -q 'pam_pwhistory' /etc/pam.d/common-password; then bad "no password history (pam_pwhistory)"; pw_bad=1; fi
if ! grep -qE '^\s*minlen\s*=\s*1[2-9]' /etc/security/pwquality.conf 2>/dev/null; then bad "pwquality minlen is not 12 or more"; pw_bad=1; fi

PW_FILES=("$LD" /etc/pam.d/common-password /etc/pam.d/common-auth /etc/security/pwquality.conf /etc/security/opasswd /etc/security/faillock.conf)

# Drives the real passwd(1) on a pty as a non-root test user. Returns 0 only if every expectation holds:
# weak passwords rejected, strong accepted, reuse of a recent password rejected. Test user is always removed.
pw_selftest() {
    local u=pwtest-audit d f=0 old new1 new2
    old="Tst#$(openssl rand -hex 6)-Qa"; new1="Wn#$(openssl rand -hex 6)-Zq"; new2="Ln#$(openssl rand -hex 6)-Yb"
    d=$(mktemp -d) || return 1
    cat >"$d/chg.exp" <<'EXP'
#!/usr/bin/expect -f
set user [lindex $argv 0]
set old [lindex $argv 1]
set new [lindex $argv 2]
set timeout 20
spawn sudo -u $user passwd
expect {
  -re "Current password: *" { send -- "$old\r"; exp_continue }
  -re "New password: *"     { send -- "$new\r"; exp_continue }
  -re "Retype new password: *" { send -- "$new\r"; exp_continue }
  eof
}
catch wait result
exit [lindex $result 3]
EXP
    chmod 700 "$d/chg.exp"
    pw_user_cleanup() {   # stop anything the test account still runs, then remove it and its fixed-name home
        pkill -KILL -u "$u" >/dev/null 2>&1; sleep 1
        userdel -r "$u" >/dev/null 2>&1; rm -rf "/home/$u"; sed -i "/^$u:/d" /etc/security/opasswd
    }
    pw_chg() { "$d/chg.exp" "$u" "$1" "$2" >/dev/null 2>&1; }
    # a reject only counts if passwd itself refused (exit 1..20); 126/127 mean the helper did not run
    pw_expect() {  # pw_expect ok|reject OLD NEW
        local rc; pw_chg "$2" "$3"; rc=$?
        if [[ $1 == ok ]]; then [[ $rc -eq 0 ]] || f=1
        else [[ $rc -ge 1 && $rc -le 20 ]] || f=1; fi
    }
    pw_user_cleanup
    useradd -m "$u" && chage -m 0 -M 90 "$u" && echo "$u:$old" | chpasswd || { pw_user_cleanup; rm -rf "$d"; return 1; }
    pw_expect reject "$old" 'short1!'
    pw_expect reject "$old" 'alllowercase1234'
    pw_expect reject "$old" 'Password1234!'
    pw_expect reject "$old" 'Aaaa#bbbb1234'
    pw_expect reject "$old" "${old%?}b"                 # too similar to the old one
    pw_expect ok     "$old" "$new1"
    pw_expect reject "$new1" "$old"                     # reuse within history
    pw_expect ok     "$new1" "$new2"
    # lockout: real sshd logins with wrong passwords, then the right one must be refused until faillock is reset
    cat >"$d/ssh.exp" <<'EXP'
#!/usr/bin/expect -f
set user [lindex $argv 0]
set pw [lindex $argv 1]
set timeout 20
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 $user@127.0.0.1 true
expect {
  -re "assword: *" { send -- "$pw\r"; exp_continue }
  eof
}
catch wait result
exit [lindex $result 3]
EXP
    local i
    for i in 1 2 3 4 5; do expect -f "$d/ssh.exp" "$u" 'WrongPass-0000' >/dev/null 2>&1; done
    expect -f "$d/ssh.exp" "$u" "$new2" >/dev/null 2>&1 && f=1          # must be locked out
    faillock --user "$u" --reset >/dev/null 2>&1
    expect -f "$d/ssh.exp" "$u" "$new2" >/dev/null 2>&1 || f=1          # must work after reset
    pw_user_cleanup; rm -rf "$d"
    return $f
}

fix_pw() {
    local cp=/etc/pam.d/common-password ca=/etc/pam.d/common-auth f
    for f in "${PW_FILES[@]}"; do backup "$f"; done    # before anything below, including the package install
    set_kv "$LD" PASS_MAX_DAYS 90 "   "; set_kv "$LD" PASS_MIN_DAYS 7 "   "; set_kv "$LD" PASS_WARN_AGE 14 "   "
    set_kv "$LD" ENCRYPT_METHOD SHA256 "   "
    set_kv "$LD" SHA_CRYPT_MIN_ROUNDS 100000 "   "; set_kv "$LD" SHA_CRYPT_MAX_ROUNDS 100000 "   "
    # Check prerequisites BEFORE touching anything. A PAM line that names a missing module makes password
    # changes (and possibly logins) fail, so install first and refuse to edit PAM if anything is absent.
    keep_users env DEBIAN_FRONTEND=noninteractive apt-get install -y libpam-pwquality expect >/dev/null 2>&1
    if ! command -v expect >/dev/null || ! find /lib /usr/lib -name pam_pwquality.so -print -quit 2>/dev/null | grep -q . \
       || ! find /lib /usr/lib -name pam_pwhistory.so -print -quit 2>/dev/null | grep -q . \
       || ! find /lib /usr/lib -name pam_faillock.so -print -quit 2>/dev/null | grep -q .; then
        bad "cannot apply password policy: pam_pwquality/pam_pwhistory/expect missing and apt could not install them (no changes made)"
        return 1
    fi
    # complexity: enforce_for_root deliberately NOT set, so an admin can always recover a locked account
    cat >/etc/security/pwquality.conf <<'PQ'
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
minclass = 3
maxrepeat = 3
maxsequence = 3
usercheck = 1
gecoscheck = 1
dictcheck = 1
difok = 5
retry = 3
PQ
    sed -i '/pam_pwquality\|pam_pwhistory/d' "$cp"
    sed -i '/pam_unix\.so/i password\trequisite\t\t\tpam_pwquality.so retry=3' "$cp"
    sed -i '/pam_unix\.so/i password\trequired\t\t\tpam_pwhistory.so remember=5 use_authtok' "$cp"
    sed -i -E '/^[^#]*pam_unix\.so/ s/\s+nullok(_secure)?//' "$ca" "$cp"
    sed -i -E '/^[^#]*pam_unix\.so/ s/\syescrypt\b/ sha256 rounds=100000/' "$cp"    # pam_unix sets the hash here, not in login.defs
    touch /etc/security/opasswd && chmod 600 /etc/security/opasswd
    # lockout: 5 failures in 15 min locks the account for 15 min. root is never locked (no even_deny_root), so an admin can always get in and reset.
    cat >/etc/security/faillock.conf <<'FL'
deny = 5
unlock_time = 900
fail_interval = 900
FL
    sed -i '/pam_faillock/d' "$ca"
    sed -i '/pam_unix\.so/i auth\trequired\t\t\tpam_faillock.so preauth' "$ca"           # its own line, before pam_unix
    sed -i '/pam_unix\.so/a auth\t[default=die]\t\t\tpam_faillock.so authfail\nauth\tsufficient\t\t\tpam_faillock.so authsucc' "$ca"
    if keep_users pw_selftest; then ok "password policy self-test passed"; return 0; fi
    warn "password policy self-test FAILED; restoring the original password files"
    for f in "${PW_FILES[@]}"; do if [[ -e $BK$f ]]; then cp -a "$BK$f" "$f"; else [[ $f == */faillock.conf ]] && rm -f "$f"; fi; done
    return 1
}
if [[ $PW_POLICY == secure ]]; then
    # preconfigured option: apply the secure policy directly, skipping detection and the prompt
    if [[ $DRY_RUN == 1 ]]; then warn "[dry-run] would apply the secure password policy (PW_POLICY=secure)"
    elif fix_pw; then ok "Secure password policy applied (PW_POLICY=secure)"
    else bad "Secure password policy failed (PW_POLICY=secure); original password files restored"; ISSUES+=("Password policy"); fi
else
    ((pw_bad)) && { ISSUES+=("Password policy"); ask_fix "Password policy" "password policy (login.defs, pwquality, nullok)" fix_pw; } || ok "password policy fine"
fi
warn "login.defs only affects NEW accounts; per-user: chage -M 90 -m 7 -W 14 <user> (skip the auto-login user)"

# ============================================================================
hdr "7. VSFTPD CONFIG"
# ============================================================================
if [[ -f /etc/vsftpd.conf ]] && pkg_installed vsftpd; then
    v_bad=0
    grep -qiE '^\s*ssl_enable\s*=\s*yes' /etc/vsftpd.conf || { bad "ssl_enable is not YES"; v_bad=1; }
    grep -qiE '^\s*anonymous_enable\s*=\s*yes' /etc/vsftpd.conf && { bad "anonymous_enable=YES"; v_bad=1; }
    fix_ftp() {
        set_kv /etc/vsftpd.conf ssl_enable YES =; set_kv /etc/vsftpd.conf anonymous_enable NO =
        set_kv /etc/vsftpd.conf write_enable NO =; systemctl restart vsftpd 2>/dev/null; return 0
    }
    ((v_bad)) && { ISSUES+=("vsftpd"); ask_fix "vsftpd" "harden vsftpd (or just remove it in step 5)" fix_ftp; }
else
    ok "vsftpd not installed"
fi

# ============================================================================
hdr "8. SUID BINARIES"
# ============================================================================
EXPECT=(/bin/fusermount3 /bin/mount /bin/su /bin/umount /usr/bin/chfn /usr/bin/chsh /usr/bin/gpasswd
    /usr/bin/newgrp /usr/bin/passwd /usr/bin/sudo /usr/bin/pkexec /usr/bin/fusermount3
    /usr/bin/at /usr/bin/crontab /usr/bin/wall /usr/bin/mount /usr/bin/su /usr/bin/umount
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/lib/openssh/ssh-keysign
    /usr/lib/policykit-1/polkit-agent-helper-1 /usr/lib/eject/dmcrypt-get-device /usr/sbin/pppd
    /usr/lib/xorg/Xorg.wrap /usr/lib/snapd/snap-confine /usr/sbin/unix_chkpwd
    /usr/lib/x86_64-linux-gnu/utempter/utempter /usr/bin/ntfs-3g /usr/sbin/mount.nfs
    /usr/bin/vmware-user-suid-wrapper /usr/bin/Xorg /usr/libexec/polkit-agent-helper-1
    /usr/lib/chromium/chrome-sandbox /usr/sbin/mount.ecryptfs_private /usr/sbin/mount.cifs)
UNEX=()
while IFS= read -r f; do
    in_list "$f" "${EXPECT[@]}" || { bad "unexpected SUID: $f"; UNEX+=("$f"); }
done < <(find / -xdev \( -path /proc -o -path /sys -o -path /snap \) -prune -o -type f -perm -4000 -print 2>/dev/null)
fix_suid() { local f m; for f in "$@"; do m=$(stat -c %a "$f"); chmod u-s "$f" && logact SUID "$f" "$m" && echo "    cleared $f"; done; }
if ((${#UNEX[@]})); then ISSUES+=("SUID"); ask_fix "SUID" "clear SUID on ${#UNEX[@]} file(s)" fix_suid "${UNEX[@]}"; else ok "none unexpected"; fi

# ============================================================================
hdr "9. SYSTEM HARDENING (sysctl, guest login, updates, file perms)"
# ============================================================================
declare -A SYS=([net.ipv4.tcp_syncookies]=1 [net.ipv4.ip_forward]=0 [net.ipv4.conf.all.accept_source_route]=0
    [net.ipv4.conf.all.accept_redirects]=0 [net.ipv4.conf.all.send_redirects]=0 [net.ipv4.conf.all.rp_filter]=1
    [kernel.randomize_va_space]=2 [fs.suid_dumpable]=0)
hard_bad=0
for k in "${!SYS[@]}"; do
    cur=$(sysctl -n "$k" 2>/dev/null)
    [[ $cur == "${SYS[$k]}" ]] && ok "$k = $cur" || { bad "$k = ${cur:-?} (want ${SYS[$k]})"; hard_bad=1; }
done
guest=$(grep -rhiE '^\s*allow-guest' /usr/share/lightdm /etc/lightdm 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
if [[ -d /etc/lightdm ]]; then
    [[ ${guest,,} == false ]] && ok "guest login disabled" || { bad "guest login allowed (allow-guest=${guest:-default true})"; hard_bad=1; }
fi
au=/etc/apt/apt.conf.d/20auto-upgrades
grep -qs 'Update-Package-Lists "1"' $au && ok "apt auto-update lists on" || { bad "apt periodic update not enabled"; hard_bad=1; }
perm_bad=()
chk_perm() {  # file max_mode_octal_other_mask
    [[ -e $1 ]] || return 0
    local m; m=$(stat -c %a "$1")
    (( (8#$m & 8#$2) )) && { bad "$1 mode $m too open"; perm_bad+=("$1"); hard_bad=1; } || ok "$1 mode $m"
}
for f in "/etc/shadow 007 640" "/etc/gshadow 007 640" "/etc/passwd 022 644" "/etc/group 022 644"; do
    read -r pf pm want <<<"$f"; m=$(stat -c %a "$pf" 2>/dev/null) || continue
    (( (8#$m & 8#$pm) )) && bad "$pf mode $m too open (user database: report only, fix by hand: chmod $want $pf)" || ok "$pf mode $m"
done
chk_perm /etc/ssh/sshd_config 022

fix_hard() {
    local k f=/etc/sysctl.d/99-cp-hardening.conf
    newfile "$f"; : > "$f"; for k in "${!SYS[@]}"; do echo "$k = ${SYS[$k]}" >> "$f"; done
    if in_chroot; then warn "chroot detected: not applying sysctl to the running kernel"; else sysctl --system >/dev/null 2>&1; fi
    if [[ -d /etc/lightdm ]] && [[ ${guest,,} != false ]]; then
        mkdir -p /etc/lightdm/lightdm.conf.d; newfile /etc/lightdm/lightdm.conf.d/50-no-guest.conf
        printf '[Seat:*]\nallow-guest=false\n' > /etc/lightdm/lightdm.conf.d/50-no-guest.conf
    fi
    newfile $au
    printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > $au
    if [[ -f /etc/ssh/sshd_config ]] && (( (8#$(stat -c %a /etc/ssh/sshd_config) & 8#022) )); then
        logact MODE /etc/ssh/sshd_config "$(stat -c %a /etc/ssh/sshd_config)"; chmod 644 /etc/ssh/sshd_config
    fi
    return 0
}
((hard_bad)) && { ISSUES+=("Hardening"); ask_fix "Hardening" "apply sysctl / guest / updates / permissions fixes" fix_hard; }

# ============================================================================
hdr "10. SUDOERS, MEDIA FILES, CRON, LISTENING PORTS"
# ============================================================================
echo "  Sudoers NOPASSWD / !authenticate (report only; mintupdate entries are normal):"
sl=$(grep -rHE 'NOPASSWD|!authenticate' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -vE '/mintupdate:|:\s*#')
[[ -n $sl ]] && { echo "$sl" | while read -r l; do bad "$l"; done; ISSUES+=("Sudoers"); } || ok "none"

MEDIA=(); while IFS= read -r f; do MEDIA+=("$f"); done < <(find /home /root -xdev -type f \
    \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.mkv' -o -iname '*.avi' -o -iname '*.mov' -o -iname '*.flac' \
       -o -iname '*.ogg' -o -iname '*.wav' -o -iname '*.m4a' -o -iname '*.wmv' \) \
    -not -path '*/.cache/*' -not -path '*/.local/*' -not -path '*/.config/*' -not -path '*/.mozilla/*' 2>/dev/null)
if ((${#MEDIA[@]})); then
    warn "media files in home dirs (prohibited if the README says no media):"
    printf '    %s\n' "${MEDIA[@]}"; ISSUES+=("Media")
    del_media() { local f; for f in "$@"; do mkdir -p "$BK/deleted-media$(dirname "$f")"; mv -v -- "$f" "$BK/deleted-media$f" && logact MEDIA "$f"; done; }
    ask_fix "Media" "MOVE these ${#MEDIA[@]} media file(s) into the backup folder (undo.sh can put them back; check README first!)" del_media "${MEDIA[@]}"
else ok "no media files"; fi

echo; echo "  Cron jobs (report only):"
for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
    [[ -f $f ]] && grep -vE '^\s*(#|$|SHELL=|PATH=|MAILTO=)' "$f" | sed "s|^|    $f: |"
done
[[ -f /etc/rc.local ]] && grep -vE '^\s*(#|$|exit)' /etc/rc.local | sed 's|^|    rc.local: |'

echo; echo "  Listening sockets (report only):"
ss -H -tulnp 2>/dev/null | awk '{printf "    %-5s %-26s %s\n",$1,$5,$7}'

# ============================================================================
hdr "SUMMARY"
# ============================================================================
if ((${#ISSUES[@]})); then
    mapfile -t uniq < <(printf '%s\n' "${ISSUES[@]}" | sort -u)
    echo -e "  ${Y}Categories with findings:${N} ${uniq[*]}"
    [[ -d $BK ]] && echo "  Config backups: $BK"
    warn "Re-run to verify. Users, forensics question and README-specific items need manual work."
    [[ -f $BK/actions.log || -d $BK ]] && echo "  Undo with: sudo bash undo.sh"
else
    ok "nothing flagged"
fi
echo
end_report
