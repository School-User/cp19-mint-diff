#!/usr/bin/env bash
# useraudit.sh — READ-ONLY user audit. Compares the accounts on this VM with the README's
# authorized users/administrators and PRINTS the commands you would run. It never runs them.
#   sudo bash useraudit.sh                       paste the README's user section when asked (Ctrl-D to finish)
#   sudo bash useraudit.sh --file readme.txt     read the README text from a file
#   sudo AUTH_ADMINS="benjamin" AUTH_USERS="alice bob" bash useraudit.sh    give the lists directly
# README format handled: lines under "Authorized Administrators" / "Authorized Users" headings; any word on a
# line that is an existing account counts (so "benjamin (you)" and "password: ..." lines are fine).

set -uo pipefail
R=$'\033[0;31m' G=$'\033[0;32m' Y=$'\033[1;33m' B=$'\033[1;34m' N=$'\033[0m'
bad()  { echo -e "  ${R}[!]${N} $*"; }
warn() { echo -e "  ${Y}[~]${N} $*"; }
ok()   { echo -e "  ${G}[+]${N} $*"; }
hdr()  { echo -e "\n${B}== $* ==${N}"; }
[[ $EUID -eq 0 ]] || echo -e "${Y}Not root: password status can't be read. Use sudo.${N}"
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
in_list() { local x=$1; shift; local i; for i in "$@"; do [[ $i == "$x" ]] && return 0; done; return 1; }

start_report useraudit
mapfile -t LOGIN < <(awk -F: '$3>=1000 && $3<65000{print $1}' /etc/passwd)
AUTOLOGIN=$(grep -rhE '^\s*autologin-user=' /etc/lightdm 2>/dev/null | tail -1 | cut -d= -f2)

# ---- get the authorized lists ------------------------------------------------------------------
ADM=(); USR=()
read -ra ADM <<<"${AUTH_ADMINS:-}"; read -ra USR <<<"${AUTH_USERS:-}"
if [[ ${#ADM[@]} -eq 0 && ${#USR[@]} -eq 0 ]]; then
    if [[ ${1:-} == --file && -r ${2:-} ]]; then mapfile -t LINES <"$2"
    else
        echo "Paste the README's 'Authorized Administrators' and 'Authorized Users' sections, then press Ctrl-D:"
        mapfile -t LINES <&4
    fi
    mode=""
    for line in "${LINES[@]}"; do
        shopt -s nocasematch
        if   [[ $line =~ authorized[[:space:]]+administrator ]]; then mode=adm; continue
        elif [[ $line =~ authorized[[:space:]]+user ]]; then mode=usr; continue; fi
        shopt -u nocasematch
        [[ -n $mode ]] || continue
        for w in $(tr -c 'A-Za-z0-9._-' ' ' <<<"$line"); do
            id "$w" >/dev/null 2>&1 || continue
            [[ $mode == adm ]] && ADM+=("$w") || USR+=("$w")
        done
    done
fi
ALLOWED=("${ADM[@]}" "${USR[@]}")
((${#ALLOWED[@]})) || { echo "No authorized accounts found in the input; nothing to compare."; end_report; exit 1; }
echo "Authorized administrators: ${ADM[*]:-none}"; echo "Authorized users:          ${USR[*]:-none}"

# ---- compare -----------------------------------------------------------------------------------
CMDS=(); note() { CMDS+=("$*"); }
hdr "ACCOUNT TABLE"
printf '  %-14s %-12s %-26s %s\n' USER ROLE ADMIN-GROUPS FINDING
for u in "${LOGIN[@]}"; do
    groups=$(id -nG "$u" | tr ' ' '\n' | grep -xE 'sudo|adm|lpadmin|admin' | tr '\n' ',' | sed 's/,$//')
    if in_list "$u" "${ADM[@]}"; then role=admin; elif in_list "$u" "${USR[@]}"; then role=user; else role=UNAUTHORIZED; fi
    finding=ok
    if [[ $role == UNAUTHORIZED ]]; then finding="not in README"; note "sudo deluser --remove-home $u     # unauthorized account (re-check the README first)"
    elif [[ $role == user && -n $groups ]]; then finding="standard user has admin rights"
        for g in ${groups//,/ }; do note "sudo gpasswd -d $u $g     # $u is not an authorized administrator"; done
    elif [[ $role == admin && $groups != *sudo* ]]; then finding="admin missing from sudo"; note "sudo usermod -aG sudo $u     # authorized admin without sudo"
    fi
    [[ $u == "$AUTOLOGIN" ]] && finding+=" (auto-login user: do NOT change its password)"
    printf '  %-14s %-12s %-26s %s\n' "$u" "$role" "${groups:--}" "$finding"
done

hdr "OTHER CHECKS"
for u in "${ALLOWED[@]}"; do id "$u" >/dev/null 2>&1 || { bad "authorized account '$u' does not exist"; note "sudo adduser $u"; }; done
x0=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd); [[ -n $x0 ]] && { bad "extra UID 0 account(s): $x0"; note "# investigate UID 0 accounts: $x0"; } || ok "no extra UID 0 accounts"
for u in "${LOGIN[@]}"; do
    s=$(passwd -S "$u" 2>/dev/null | awk '{print $2}')
    [[ $s == NP ]] && { bad "$u has NO password"; [[ $u == "$AUTOLOGIN" ]] || note "sudo passwd $u     # empty password"; }
done
sh_sys=$(awk -F: '$3<1000 && $3!=0 && $7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1" ("$7")"}' /etc/passwd | tr '\n' ' ')
[[ -n $sh_sys ]] && warn "system accounts with a login shell: $sh_sys" || ok "no system accounts with login shells"
sl=$(grep -rHvE '^\s*(#|$|Defaults)' /etc/sudoers.d 2>/dev/null | grep -vE '/(mintupdate|README|zfs|0pwfeedback):')
[[ -n $sl ]] && { warn "extra sudoers entries:"; echo "$sl" | sed 's/^/      /'; } || ok "no extra sudoers.d entries"

hdr "COMMANDS TO REVIEW — NOTHING WAS RUN"
if ((${#CMDS[@]})); then printf '  %s\n' "${CMDS[@]}"; else ok "accounts match the README"; fi
warn "Do not remove authorized users or their home directories. Do not change the auto-login user's password."
echo; end_report
