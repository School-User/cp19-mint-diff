#!/usr/bin/env bash
# CyberPatriot forensics helper — READ-ONLY. Never changes the system, users, or files.
#   sudo bash forensics.sh                 menu
#   sudo bash forensics.sh report          run every scan (save with: report | tee report.txt)
#   sudo bash forensics.sh <command> [arg]
# Commands:
#   questions        show the Forensics Question files on the desktops
#   newest [N]       the N most recently modified user/config files (default 40)
#   hidden           hidden files/dirs in home dirs that aren't standard dotfiles
#   media            audio/video/image/archive/document files in home dirs
#   search TERM      files whose NAME or CONTENT contains TERM (also tries its base64 form)
#   info FILE        owner, perms, times, type, hashes, strings, archive listing
#   decode STRING    try base64 / hex / rot13 / rot47 / url-decoding on a string
#   users            logins, password status, groups, authorized_keys, history sizes
#   persist          cron, timers, autostart, shell-startup additions, preload, keys
#   net              listening ports, connections, hosts file, firewall
#   browser          Chromium/Firefox history and downloads (works on a temp copy)

set -uo pipefail
R=$'\033[0;31m' G=$'\033[0;32m' Y=$'\033[1;33m' B=$'\033[1;34m' N=$'\033[0m'
hdr()  { echo -e "\n${B}== $* ==${N}"; }
note() { echo -e "  ${Y}[~]${N} $*"; }
[[ $EUID -eq 0 ]] || echo -e "${Y}Not root: some files will be unreadable. Use sudo.${N}"
if ( : </dev/tty ) 2>/dev/null; then exec 4</dev/tty; else exec 4<&0; fi


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
SCAN=(/home /root /opt /srv /var/www /tmp /usr/local /mnt /media)
NOISE='/\.(cache|mozilla|thumbnails|gvfs)/|/\.local/share/(recently-used|gvfs|Trash|zeitgeist|tracker)|/\.config/(dconf|pulse|ibus|Code|chromium|google-chrome)|\.xsession-errors|/\.(dbus|gnupg)/'
homes() { awk -F: '$3==0 || ($3>=1000 && $3<65000){print $6}' /etc/passwd | sort -u; }

questions() {
    hdr "FORENSICS QUESTION FILES"
    local f found=0
    while IFS= read -r f; do found=1; echo "--- $f"; cat "$f"; done < <(find /home /root /opt -maxdepth 4 -iname '*forensic*' -type f 2>/dev/null)
    ((found)) || note "none found (the real question text comes from the scoring server's README)"
}

newest() {
    hdr "NEWEST ${1:-40} FILES (user data, config, tmp)"
    find "${SCAN[@]}" /etc -type f -printf '%T@\t%TY-%Tm-%Td %TH:%TM\t%u\t%m\t%s\t%p\n' 2>/dev/null \
        | grep -Ev "$NOISE" | sort -rn | head -n "${1:-40}" | cut -f2- | column -t -s$'\t'
}

hidden() {
    hdr "NON-STANDARD HIDDEN FILES IN HOME DIRS"
    local STD='^\.(bash_logout|bashrc|profile|bash_history|cache|config|local|mozilla|cinnamon|gnupg|ssh|dbus|xsession-errors.*|Xauthority|ICEauthority|sudo_as_admin_successful|face|thumbnails|pki|gvfs|nv|java|vim.*|lesshst|viminfo|wget-hsts|selected_editor|python_history|gtkrc-2\.0|gtkrc-xfce|icons|themes|linuxmint|angband|pki|fltk)$'
    local h f
    for h in $(homes); do
        [[ -d $h ]] || continue
        find "$h" -maxdepth 3 -name '.*' -not -name . -not -path "$h/.cache/*" -not -path "$h/.config/*" -not -path "$h/.local/*" \
             -not -path "$h/.mozilla/*" -not -path "$h/.cinnamon/*" -not -path "$h/.gnupg/*" 2>/dev/null \
        | while read -r f; do [[ $(basename "$f") =~ $STD ]] || ls -ld --time-style=long-iso "$f" | awk '{printf "  %s %s %s %s  ",$1,$3,$6,$7; $1=$2=$3=$4=$5=$6=$7=""; print substr($0,8)}'; done
    done
}

media() {
    hdr "MEDIA / ARCHIVES / DOCUMENTS IN HOME DIRS"
    find /home /root /srv /var/www /opt -type f \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.mkv' -o -iname '*.avi' -o -iname '*.mov' \
        -o -iname '*.flac' -o -iname '*.ogg' -o -iname '*.wav' -o -iname '*.m4a' -o -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' \
        -o -iname '*.gif' -o -iname '*.zip' -o -iname '*.tar*' -o -iname '*.gz' -o -iname '*.7z' -o -iname '*.rar' -o -iname '*.pdf' \
        -o -iname '*.doc*' -o -iname '*.xls*' -o -iname '*.txt' -o -iname '*.csv' -o -iname '*.sh' -o -iname '*.py' -o -iname '*.pl' \) \
        -printf '%u\t%TY-%Tm-%Td\t%s\t%p\n' 2>/dev/null | grep -Ev "$NOISE|/usr/share|/opt/(google|vmware)" | sort -t$'\t' -k4 | head -150 | column -t -s$'\t'
}

search() {
    local t=${1:-}; [[ -n $t ]] || { echo "usage: search TERM"; return 1; }
    local b64; b64=$(printf %s "$t" | base64 | tr -d '=\n')
    hdr "FILE NAMES containing '$t'"
    find / -xdev \( -path /proc -o -path /sys -o -path /usr/share -o -path /var/lib/dpkg -o -path /usr/lib \) -prune -o -iname "*$t*" -print 2>/dev/null | head -40
    hdr "FILE CONTENTS containing '$t' (first matching line per file)"
    grep -rIiH -m1 -n --exclude-dir={.cache,.mozilla,proc,sys} -e "$t" "${SCAN[@]}" /etc /var/log 2>/dev/null | cut -c1-200 | head -40
    hdr "BASE64 form '$b64' (hidden-in-plain-sight check)"
    grep -rIl -e "$b64" "${SCAN[@]}" /etc 2>/dev/null | head -10
}

info() {
    local f=${1:-}; [[ -e $f ]] || { echo "usage: info FILE"; return 1; }
    hdr "INFO: $f"
    stat -c '  owner=%U:%G  mode=%a  size=%s  modified=%y  created=%w' "$f"
    file "$f" | sed 's/^/  /'
    [[ -f $f ]] || return 0
    md5sum "$f" | sed 's/^/  /'; sha1sum "$f" | sed 's/^/  /'; sha256sum "$f" | sed 's/^/  /'
    case $(file -b --mime-type "$f") in
        application/zip) unzip -l "$f" 2>/dev/null | sed 's/^/  /' ;;
        application/gzip|application/x-tar|application/x-xz|application/x-bzip2) tar -tf "$f" 2>/dev/null | head -30 | sed 's/^/  /' ;;
        image/*) command -v exiftool >/dev/null && exiftool "$f" | head -25 | sed 's/^/  /' ;;
    esac
    echo "  -- strings (first 25 of length>=8):"; strings -n 8 "$f" 2>/dev/null | head -25 | sed 's/^/  /'
}

decode() {
    local s=${1:-}; [[ -n $s ]] || { echo "usage: decode STRING"; return 1; }
    hdr "DECODE: $s"
    printf '  base64 : '; printf %s "$s" | base64 -d 2>/dev/null | tr -c '[:print:]\n' '.' ; echo
    printf '  hex    : '; printf %s "$s" | python3 -c "import sys,binascii;print(binascii.unhexlify(sys.stdin.read().replace(' ','')).decode('latin1'))" 2>/dev/null; echo
    printf '  rot13  : '; printf %s "$s" | tr 'A-Za-z' 'N-ZA-Mn-za-m'; echo
    printf '  rot47  : '; printf %s "$s" | tr '!-~' 'P-~!-O'; echo
    printf '  url    : '; printf %s "$s" | python3 -c "import sys,urllib.parse;print(urllib.parse.unquote(sys.stdin.read()))" 2>/dev/null
    printf '  reverse: '; printf %s "$s" | rev
}

users() {
    hdr "USERS (read-only)"
    printf '  %-14s %-5s %-10s %-22s %-5s %s\n' USER UID PASSWD LASTLOGIN HOME GROUPS
    awk -F: '$3==0 || ($3>=1000 && $3<65000){print $1}' /etc/passwd | while read -r u; do
        ps_=$(passwd -S "$u" 2>/dev/null | awk '{print $2}'); ll=$(lastlog -u "$u" 2>/dev/null | tail -1 | awk '{ if ($2=="**Never") print "never"; else print $4,$5,$6,$9}')
        printf '  %-14s %-5s %-10s %-22s %-5s %s\n' "$u" "$(id -u "$u")" "${ps_:-?}" "$ll" "$(stat -c %a "$(getent passwd "$u" | cut -d: -f6)" 2>/dev/null)" "$(id -nG "$u" | tr ' ' ',')"
    done
    note "PASSWD column: P=has password, L=locked, NP=NO password"
    hdr "RECENT LOGINS"; last -n 15 2>/dev/null | head -17
    hdr "PER-USER FILES"
    local h; for h in $(homes); do
        [[ -f $h/.ssh/authorized_keys ]] && echo "  authorized_keys: $h/.ssh/authorized_keys ($(wc -l <"$h/.ssh/authorized_keys") keys)"
        [[ -s $h/.bash_history ]] && echo "  history: $h/.bash_history ($(wc -l <"$h/.bash_history") lines)"
        find "$h" -maxdepth 1 -name '.*_history' -size +0 2>/dev/null | grep -v bash_history | sed 's/^/  history: /'
    done
    hdr "SPECIAL GROUPS"; getent group sudo adm lpadmin shadow root docker wireshark ssh 2>/dev/null | sed 's/^/  /'
}

persist() {
    hdr "CRON JOBS"
    local u; for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | grep -vE '^\s*(#|$)' | sed "s/^/  [$u] /"; done
    grep -vhE '^\s*(#|$|SHELL=|PATH=|MAILTO=)' /etc/crontab /etc/cron.d/* 2>/dev/null | sed 's/^/  [system] /'
    find /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly -type f 2>/dev/null | while read -r f; do
        dpkg -S "$f" >/dev/null 2>&1 || echo "  cron script (not from a package): $f"; done
    atq 2>/dev/null | sed 's/^/  at job: /'
    hdr "SYSTEMD UNITS NOT FROM A PACKAGE"
    find /etc/systemd/system -maxdepth 2 \( -name '*.service' -o -name '*.timer' \) -type f 2>/dev/null | while read -r f; do dpkg -S "$f" >/dev/null 2>&1 || echo "  $f"; done
    hdr "STARTUP FILES"
    ls -l /etc/rc.local 2>/dev/null; cat /etc/ld.so.preload 2>/dev/null | sed 's/^/  ld.so.preload: /'
    find /etc/xdg/autostart -type f 2>/dev/null | while read -r f; do dpkg -S "$f" >/dev/null 2>&1 || echo "  autostart (not from a package): $f"; done
    find /home/*/.config/autostart /root/.config/autostart -type f 2>/dev/null | sed 's/^/  user autostart: /'
    find /etc/profile.d -type f 2>/dev/null | while read -r f; do dpkg -S "$f" >/dev/null 2>&1 || echo "  profile.d (custom): $f"; done
    hdr "SHELL STARTUP FILES vs /etc/skel (added lines = aliases/commands someone planted)"
    local h f
    for h in $(homes); do [[ $h == /root ]] && continue; for f in .bashrc .profile .bash_logout; do
        [[ -f $h/$f && -f /etc/skel/$f ]] && diff <(cat /etc/skel/$f) "$h/$f" | grep '^>' | sed "s|^>|  $h/$f:|" | head -10
    done; done
    hdr "SUDOERS ADDITIONS"; grep -rvhE '^\s*(#|$)' /etc/sudoers.d 2>/dev/null | sed 's/^/  /'
}

net() {
    hdr "LISTENING SOCKETS"; ss -tulnp 2>/dev/null | sed 's/^/  /'
    hdr "ESTABLISHED CONNECTIONS"; ss -tnp state established 2>/dev/null | sed 's/^/  /'
    hdr "HOSTS / RESOLV"; grep -vE '^\s*(#|$)' /etc/hosts /etc/resolv.conf 2>/dev/null | sed 's/^/  /'
    hdr "FIREWALL"; ufw status verbose 2>/dev/null | sed 's/^/  /'
}

browser() {
    hdr "BROWSER HISTORY / DOWNLOADS (on temp copies)"
    command -v sqlite3 >/dev/null || { note "sqlite3 not installed: apt install sqlite3 (changes the system), or copy the files elsewhere"; return; }
    local tmp; tmp=$(mktemp -d); local h db
    for h in $(homes); do
        for db in "$h/.config/chromium/Default/History" "$h/.config/google-chrome/Default/History"; do
            [[ -f $db ]] || continue; cp "$db" "$tmp/h.db" 2>/dev/null
            echo "  -- $db (urls)"; sqlite3 -readonly "$tmp/h.db" "select datetime(last_visit_time/1000000-11644473600,'unixepoch'), url from urls order by last_visit_time desc limit 25" 2>/dev/null | sed 's/^/    /'
            echo "  -- downloads"; sqlite3 -readonly "$tmp/h.db" "select target_path, tab_url from downloads order by start_time desc limit 15" 2>/dev/null | sed 's/^/    /'
        done
        for db in "$h"/.mozilla/firefox/*/places.sqlite; do
            [[ -f $db ]] || continue; cp "$db" "$tmp/p.db" 2>/dev/null
            echo "  -- $db"; sqlite3 -readonly "$tmp/p.db" "select datetime(last_visit_date/1000000,'unixepoch'), url from moz_places where last_visit_date is not null order by last_visit_date desc limit 25" 2>/dev/null | sed 's/^/    /'
        done
    done
    rm -rf "$tmp"
}

report() { questions; newest 30; hidden; media; users; persist; net; browser; }

menu() {
    local a t
    while :; do
        echo -e "\n${B}CyberPatriot forensics helper (read-only)${N}
  1) questions   2) newest files   3) hidden files   4) media/archives   5) search TERM
  6) info FILE   7) decode STRING  8) users          9) persistence     10) network
  11) browser    12) full report   q) quit"
        read -rp "> " a <&4 || return
        case $a in
            1) questions ;; 2) newest ;; 3) hidden ;; 4) media ;; 8) users ;; 9) persist ;; 10) net ;; 11) browser ;; 12) report ;;
            5) read -rp "term: " t <&4; search "$t" ;; 6) read -rp "file: " t <&4; info "$t" ;; 7) read -rp "string: " t <&4; decode "$t" ;;
            q|Q) return ;; *) echo "pick 1-12 or q" ;;
        esac
    done
}

case "${1:-menu}" in
    questions|newest|hidden|media|search|info|decode|users|persist|net|browser|report|menu) cmd=${1:-menu}; shift || true; start_report forensics; "$cmd" "$@"; end_report ;;
    -h|--help|help) sed -n '2,22p' "$0" ;;
    *) echo "unknown command '$1' (try: help)"; exit 1 ;;
esac
