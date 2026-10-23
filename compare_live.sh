#!/usr/bin/env bash
# CyberPatriot live-vs-base comparer — runs ON the live Linux Mint 21 VM, as root.
#   sudo bash compare_live.sh                       interactive
#   sudo DRY_RUN=1 bash compare_live.sh             show differences only
#   sudo BASE_ROOT=/mnt/clean bash compare_live.sh  use a mounted clean Mint 21 rootfs as the base
#
# Without BASE_ROOT the "base" is a clean Mint 21 install as defined by the packages themselves:
#   config files   -> the package's pristine copy (apt-get download, or the copy it ships for ucf)
#   package list   -> everything installed on the base image's build date; later ones are "added"
# With BASE_ROOT every file under /etc and the dpkg package list are compared to that rootfs.
#
# USERS ARE NEVER TOUCHED: passwd/shadow/group/sudoers, home dirs and login config are on a
# protected list, and a before/after check at the end proves nothing user-related changed.

set -uo pipefail
R=$'\033[0;31m' G=$'\033[0;32m' Y=$'\033[1;33m' B=$'\033[1;34m' N=$'\033[0m'
bad()  { echo -e "  ${R}[!]${N} $*"; }
warn() { echo -e "  ${Y}[~]${N} $*"; }
ok()   { echo -e "  ${G}[+]${N} $*"; }
hdr()  { echo -e "\n${B}== $* ==${N}"; }
[[ $EUID -eq 0 ]] || { echo -e "${R}Run with sudo.${N}"; exit 1; }

DRY_RUN=${DRY_RUN:-0}; BASE_ROOT=${BASE_ROOT:-}
if ( : </dev/tty ) 2>/dev/null; then exec 4</dev/tty; else exec 4<&0; fi   # answers come from fd 4
WORK=$(mktemp -d /tmp/cp-compare.XXXXXX); trap 'rm -rf "$WORK"' EXIT
BK=/root/cp-compare-backup-$(date +%Y%m%d-%H%M%S)
N_CONF=0 N_CUSTOM=0 N_PKGF=0 N_SUID=0 N_PKG=0 N_SVC=0

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
end_report() { [[ -n $REPORT ]] && echo "  Report saved: $REPORT"; sleep 0.3; }

# --- action log: lets undo.sh reverse what this run did (tab-separated lines in $BK/actions.log) ----
logact() { mkdir -p "$BK"; ( IFS=$'\t'; echo "$*" ) >>"$BK/actions.log"; }
newfile() { [[ -e $1 ]] && backup "$1" || logact NEWFILE "$1"; }   # file this run creates (or backs up if it exists)
in_chroot() { [[ $(stat -c %d:%i / 2>/dev/null) != $(stat -c %d:%i /proc/1/root/. 2>/dev/null) ]]; }

start_report compare

PROTECTED=(/etc/passwd* /etc/shadow* /etc/group* /etc/gshadow* /etc/subuid* /etc/subgid*
    /etc/sudoers /etc/sudoers.d/* /etc/security/opasswd /etc/lightdm/* /etc/fstab /etc/hostname
    /etc/machine-id /etc/localtime /etc/timezone /etc/adjtime /home/* /root/* /opt/*)
protected() { local p; for p in "${PROTECTED[@]}"; do [[ $1 == $p ]] && return 0; done; return 1; }

user_state() {
    sha256sum /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/subuid /etc/subgid /etc/sudoers 2>/dev/null
    ls -d /home/* 2>/dev/null; getent group sudo adm lpadmin
}
USERS_BEFORE=$(user_state)

backup() { [[ -e $BK$1 ]] && return 0; mkdir -p "$BK$(dirname "$1")"; [[ -e $1 ]] && cp -a "$1" "$BK$1"; }   # first copy wins

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
ask() { local a=""; if [[ $DRY_RUN == 1 ]]; then echo s; return; fi; read -rp "$1 " a <&4; echo "${a,,}"; }
in_list() { local x=$1; shift; local i; for i in "$@"; do [[ $i == "$x" ]] && return 0; done; return 1; }
owner() {   # package owning a path; also tries the /bin <-> /usr/bin merged-usr twin
    local p o
    for p in "$1" "${1#/usr}" "/usr$1"; do
        o=$(dpkg -S -- "$p" 2>/dev/null | head -1)
        [[ -n $o ]] && { o=${o%%: *}; o=${o%%, *}; echo "${o%:amd64}"; return; }
    done
}

# pristine path pkg [alt] -> base content on stdout (empty if none available)
pristine() {
    local path=$1 pkg=$2 alt=${3:-} ver
    if [[ -n $BASE_ROOT ]]; then [[ -f $BASE_ROOT$path ]] && cat "$BASE_ROOT$path"; return; fi
    if [[ -n $alt && -f $alt ]]; then cat "$alt"; return; fi
    [[ -n $pkg ]] || return 1
    if ! ls "$WORK/$pkg".deb >/dev/null 2>&1; then
        ver=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null)
        ( cd "$WORK" && { apt-get download "$pkg=$ver" || apt-get download "$pkg"; } >/dev/null 2>&1 ) || return 1
        mv "$WORK/${pkg}_"*.deb "$WORK/$pkg.deb" 2>/dev/null || return 1
    fi
    dpkg-deb --fsys-tarfile "$WORK/$pkg.deb" | tar -xOf - ".$path" 2>/dev/null
}

# review_file path flags pkg [alt]: show the live-vs-base difference, offer to restore base
review_file() {
    local path=$1 flags=$2 pkg=$3 alt=${4:-} base=$WORK/base a
    N_CONF=$((N_CONF+1))
    if [[ $flags == missing ]]; then bad "$path is DELETED (package: ${pkg:-?})"
    else bad "$path differs from base (package: ${pkg:-?})"; fi
    pristine "$path" "$pkg" "$alt" >"$base" 2>/dev/null
    if [[ ! -s $base ]]; then warn "no base copy available (generated file or offline) — skipped"; return; fi
    [[ $flags != missing ]] && diff --color=always -u --label "base:$path" --label "live:$path" "$base" "$path" | head -n 30
    while :; do
        a=$(ask "    [r]estore base version / [d]iff in full / [s]kip (default)?")
        case $a in
            d*) diff --color=always -u --label "base:$path" --label "live:$path" "$base" "$path" | (less -R || cat) ;;
            r*) backup "$path"
                if [[ -e $path ]]; then cat "$base" >"$path"; else newfile "$path"; install -D -m 644 "$base" "$path"; fi
                if [[ $path == /etc/ssh/sshd_config ]]; then
                    mkdir -p /run/sshd
                    if sshd -t 2>/dev/null; then systemctl restart ssh 2>/dev/null; ok "restored (sshd validated)"
                    else cp -a "$BK$path" "$path"; bad "sshd rejected the base config; reverted"; fi
                else ok "restored (backup in $BK); restart the related service if needed"; fi
                return ;;
            *) warn "skipped"; return ;;
        esac
    done
}

echo "Scanning live system against a clean Mint 21 base (dpkg verify takes a minute)..."
VERIFY=$WORK/verify.txt; dpkg -V >"$VERIFY" 2>/dev/null

# ============================================================================
hdr "1. CONFIG FILES: live vs base"
# ============================================================================
while read -r flags path; do
    [[ -n $path ]] || continue
    if protected "$path"; then warn "$path differs — PROTECTED, never modified"; continue; fi
    if [[ $flags != *5* && $flags != missing ]]; then warn "$path permissions/owner differ ($flags) — report only"; continue; fi
    review_file "$path" "$flags" "$(owner "$path")"
done < <(awk 'NF==3 && $2=="c"{print $1, $3}' "$VERIFY")

# files whose pristine copy the package ships separately (ucf-managed, not dpkg conffiles)
for pair in "/etc/ssh/sshd_config /usr/share/openssh/sshd_config"; do
    read -r path alt <<<"$pair"
    [[ -f $path && -f $alt ]] && ! cmp -s "$path" "$alt" && review_file "$path" differ "$(owner "$path")" "$alt"
done

if [[ -n $BASE_ROOT && -d $BASE_ROOT/etc ]]; then   # real base available: compare all of /etc
    SKIP='^/etc/(ssl/certs|alternatives|ld\.so\.cache|resolv\.conf|mtab|ssh/ssh_host_|cups/ssl|NetworkManager/system-connections|ufw/(user|before|after)|\.pwd\.lock|adjtime|ca-certificates)'
    while IFS= read -r line; do
        case $line in
            "Files "*" differ") path=${line#Files * and }; path=${path% differ}
                protected "$path" || [[ $path =~ $SKIP ]] || review_file "$path" differ "" ;;
            "Only in /etc"*) d=${line#Only in }; path=${d%%: *}/${d#*: }
                protected "$path" || [[ $path =~ $SKIP ]] || { N_CUSTOM=$((N_CUSTOM+1)); bad "$path exists only on the live image"; } ;;
            "Only in $BASE_ROOT/etc"*) d=${line#Only in }; rel=${d%%: *}/${d#*: }; path=${rel#"$BASE_ROOT"}
                protected "$path" || [[ $path =~ $SKIP ]] || warn "$path exists on the base but not live" ;;
        esac
    done < <(diff -rq "$BASE_ROOT/etc" /etc 2>/dev/null)
else   # no base: custom files dropped into sensitive config dirs
    for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/ssh/sshd_config.d \
             /etc/profile.d /etc/init.d /etc/systemd/system /etc/xdg/autostart /etc/polkit-1/rules.d \
             /etc/polkit-1/localauthority /etc/modprobe.d /etc/sysctl.d /etc/security; do
        [[ -d $d ]] || continue
        while IFS= read -r f; do
            protected "$f" && continue
            [[ -z $(owner "$f") ]] && { bad "$f is not from any package"; N_CUSTOM=$((N_CUSTOM+1)); }
        done < <(find "$d" -maxdepth 2 -type f 2>/dev/null)
    done
fi
((N_CONF+N_CUSTOM)) || ok "no config differences"

# ============================================================================
hdr "2. PROGRAM FILES modified or missing (possible tampering)"
# ============================================================================
declare -A PKGFILES
while read -r f; do
    p=$(owner "$f"); [[ -n $p ]] || continue
    PKGFILES[$p]+="$f "; bad "$f (package: $p)"; N_PKGF=$((N_PKGF+1))
done < <(awk 'NF==2 && ($1 ~ /5/ || $1=="missing"){print $2}' "$VERIFY" \
         | grep -E '^/(bin|sbin|usr/bin|usr/sbin|usr/libexec|usr/lib|lib)/' | grep -vE '\.pyc$|^/usr/lib/python3')
for p in "${!PKGFILES[@]}"; do
    [[ $(ask "    reinstall $p to restore its files? [y/N]") == y* ]] &&
        { keep_users env DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y "$p" >/dev/null 2>&1 && ok "reinstalled $p" || bad "reinstall of $p failed"; }
done
((N_PKGF)) || ok "all program files match their packages"

# ============================================================================
hdr "3. FILES not from any package (SUID/SGID and /usr/local executables)"
# ============================================================================
UNOWNED=()
while IFS= read -r f; do
    [[ -z $(owner "$f") ]] && { UNOWNED+=("$f"); bad "SUID/SGID file owned by no package: $f ($(stat -c %a "$f"))"; }
done < <(find / -xdev \( -path /proc -o -path /sys -o -path /snap \) -prune -o -type f -perm /6000 -print 2>/dev/null)
N_SUID=${#UNOWNED[@]}
if ((N_SUID)) && [[ $(ask "    clear SUID/SGID bits on these? [y/N]") == y* ]]; then
    for f in "${UNOWNED[@]}"; do m=$(stat -c %a "$f"); chmod ug-s "$f" && logact SUID "$f" "$m" && ok "cleared $f"; done
fi
while IFS= read -r f; do [[ -z $(owner "$f") ]] && warn "extra executable (not from a package): $f"; done \
    < <(find /usr/local/bin /usr/local/sbin -type f -perm /111 2>/dev/null)
((N_SUID)) || ok "no unowned SUID/SGID files"

# ============================================================================
hdr "4. PACKAGES added after the base image was built"
# ============================================================================
declare -A PKGDATE; EXTRA=()
if [[ -n $BASE_ROOT && -f $BASE_ROOT/var/lib/dpkg/status ]]; then
    awk '/^Package:/{p=$2} /^Status:.* installed/{print p}' "$BASE_ROOT/var/lib/dpkg/status" | sort -u >"$WORK/base_pkgs"
    while read -r p; do grep -qx "$p" "$WORK/base_pkgs" || { EXTRA+=("$p"); PKGDATE[$p]=""; }; done \
        < <(dpkg-query -W -f='${Package} ${Status}\n' | awk '$NF=="installed"{print $1}')
else
    dpkg-query -W -f='${db-fsys:Last-Modified} ${Package} ${Status}\n' 2>/dev/null | awk '$NF=="installed"{print $1, $2}' >"$WORK/times"
    # base build day = the day most packages were installed; anything a week later was added afterwards
    cutoff=$(awk '{d=int($1/86400); c[d]++} END{for(k in c) if(c[k]>m){m=c[k]; b=k} print (b+7)*86400}' "$WORK/times")
    while read -r t p; do
        ((t > cutoff)) || continue
        [[ $p =~ ^(linux-|grub|initramfs|dkms) ]] && continue
        EXTRA+=("$p"); PKGDATE[$p]=$(date -d "@$t" +%F)
    done <"$WORK/times"
fi
mapfile -t AUTO < <(apt-mark showauto)
DEPS=()
for p in "${EXTRA[@]}"; do
    if in_list "$p" "${AUTO[@]}"; then DEPS+=("$p"); else bad "$p ${PKGDATE[$p]:+(installed ${PKGDATE[$p]})}"; fi
done
((${#DEPS[@]})) && warn "plus ${#DEPS[@]} dependencies of the above: ${DEPS[*]}"
N_PKG=${#EXTRA[@]}
if ((N_PKG)); then
    a=$(ask "    remove which? [package names / all / Enter=skip]:")
    [[ $a == all ]] && sel=("${EXTRA[@]}") || read -ra sel <<<"$a"
    pick=(); for p in "${sel[@]:-}"; do in_list "$p" "${EXTRA[@]}" && pick+=("$p"); done
    if ((${#pick[@]})); then
        outside=(); while read -r r; do in_list "${r%%:*}" "${EXTRA[@]}" || outside+=("$r"); done \
            < <(apt-get -s remove "${pick[@]}" 2>/dev/null | awk '/^Remv/{print $2}')
        if ((${#outside[@]})); then bad "refusing: removing these would also remove base packages: ${outside[*]}"
        else keep_users env DEBIAN_FRONTEND=noninteractive apt-get remove -y "${pick[@]}" >/dev/null 2>&1 && logact PKG "${pick[@]}" && ok "removed ${pick[*]} (system accounts left exactly as they were)" || bad "apt failed"; fi
    fi
else ok "no packages added after the base"; fi

# ============================================================================
hdr "5. ENABLED SERVICES not from the base"
# ============================================================================
EXTRASVC=()
while read -r u; do
    fp=""; for d in /etc/systemd/system /lib/systemd/system; do [[ -e $d/$u ]] && { fp=$d/$u; break; }; done
    [[ -n $fp ]] || continue
    p=$(owner "$fp")
    if [[ -z $p ]]; then bad "$u — unit file owned by no package ($fp)"; EXTRASVC+=("$u")
    elif in_list "$p" "${EXTRA[@]}"; then bad "$u (from added package $p)"; EXTRASVC+=("$u"); fi
done < <(systemctl list-unit-files --state=enabled --type=service,socket,timer --no-legend 2>/dev/null | awk '{print $1}' | grep -v '@\.')
N_SVC=${#EXTRASVC[@]}
if ((N_SVC)); then
    a=$(ask "    disable which? [unit names / all / Enter=skip]:")
    [[ $a == all ]] && sel=("${EXTRASVC[@]}") || read -ra sel <<<"$a"
    for u in "${sel[@]:-}"; do
        in_list "$u" "${EXTRASVC[@]}" || continue
        systemctl is-enabled --quiet "$u" 2>/dev/null && en=1 || en=0; systemctl is-active --quiet "$u" 2>/dev/null && act=1 || act=0
        systemctl disable --now "$u" 2>/dev/null
        systemctl is-enabled --quiet "$u" 2>/dev/null || { logact SVC "$u" "$en" "$act"; ok "disabled $u"; }
    done
else ok "no extra enabled services"; fi

# ============================================================================
hdr "6. USERS: read-only comparison (NEVER modified)"
# ============================================================================
awk -F: 'NR==FNR{m[$1]; next} $3<1000 && !($1 in m) && $3!=0 {print "    non-standard system account: "$1" uid="$3" shell="$7}' \
    /usr/share/base-passwd/passwd.master /etc/passwd | grep -v -E 'shell=(/usr/sbin/nologin|/bin/false)$' || true
awk -F: '$3==0 && $1!="root"{print "    EXTRA UID 0: "$1}' /etc/passwd
echo "  Login users (UID >= 1000):"; awk -F: '$3>=1000 && $1!="nobody"{printf "    %s (%s)\n",$1,$7}' /etc/passwd
for g in sudo adm lpadmin; do echo "    group $g: $(getent group $g | cut -d: -f4)"; done
warn "Compare these against the README yourself. Fix users by hand, e.g.: gpasswd -d <user> sudo"

# ============================================================================
hdr "SUMMARY"
# ============================================================================
echo "  config diffs: $N_CONF | custom config files: $N_CUSTOM | modified program files: $N_PKGF | unowned SUID: $N_SUID"
echo "  added packages: $N_PKG | extra enabled services: $N_SVC"
[[ -d $BK ]] && { echo "  Backups of changed files: $BK"; echo "  Undo with: sudo bash undo.sh"; }
if [[ "$USERS_BEFORE" == "$(user_state)" ]]; then ok "USERS UNTOUCHED: passwd/shadow/group/sudoers/home dirs identical to before this run"
else bad "user-related state changed during this run — investigate!"; fi
echo "  Note: a base comparison can't flag insecure stock defaults (e.g. UFW off, PASS_MAX_DAYS 99999); run audit.sh for those."
echo
end_report
