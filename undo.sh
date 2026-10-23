#!/usr/bin/env bash
# undo.sh — reverse what audit.sh / compare_live.sh did, using their backup folders in /root.
#   sudo bash undo.sh              pick a backup set from a list
#   sudo bash undo.sh last         the newest set
#   sudo bash undo.sh DIR          a specific backup folder
#   sudo DRY_RUN=1 bash undo.sh    show what would be reversed, change nothing
# Reverses: edited config files, files the tools created, permissions, disabled services,
#           removed packages (reinstalled), cleared SUID bits, UFW enable, moved media files.
# Can't reverse: libpam-pwquality being installed, the runtime sysctl values (reboot to reset).
# NEVER touches user accounts: passwd/shadow/group/gshadow/sudoers are skipped even if present.

set -uo pipefail
R=$'\033[0;31m' G=$'\033[0;32m' Y=$'\033[1;33m' B=$'\033[1;34m' N=$'\033[0m'
bad()  { echo -e "  ${R}[!]${N} $*"; }
warn() { echo -e "  ${Y}[~]${N} $*"; }
ok()   { echo -e "  ${G}[+]${N} $*"; }
hdr()  { echo -e "\n${B}== $* ==${N}"; }
[[ $EUID -eq 0 ]] || { echo -e "${R}Run with sudo.${N}"; exit 1; }
DRY_RUN=${DRY_RUN:-0}
if ( : </dev/tty ) 2>/dev/null; then exec 4</dev/tty; else exec 4<&0; fi

PROTECTED=(/etc/passwd* /etc/shadow* /etc/group* /etc/gshadow* /etc/subuid* /etc/subgid* /etc/sudoers /etc/sudoers.d/*
           /etc/security/opasswd /etc/lightdm/* /etc/fstab /etc/hostname /etc/machine-id /etc/localtime /etc/timezone)
protected() { local p; for p in "${PROTECTED[@]}"; do [[ $1 == $p ]] && return 0; done; return 1; }
user_state() { sha256sum /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/subuid /etc/subgid /etc/sudoers 2>/dev/null; getent group sudo adm lpadmin; }
USERS_BEFORE=$(user_state)

confirm() {   # confirm "question" -> 0 if yes (never in dry run)
    if [[ $DRY_RUN == 1 ]]; then warn "[dry-run] $1"; return 1; fi
    local a=""; read -rp "  $1 [y/N] " a <&4; [[ $a =~ ^[Yy]$ ]]
}

exec 5>&1
keep_users() {   # package scripts can touch system accounts; put them back exactly
    local d f rc; d=$(mktemp -d)
    for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/subuid /etc/subgid; do [[ -e $f ]] && cp -a "$f" "$d/"; done
    "$@"; rc=$?
    for f in "$d"/*; do cmp -s "$f" "/etc/${f##*/}" || { cp -a "$f" "/etc/${f##*/}"; warn "package scripts changed ${f##*/}; restored it exactly" >&5; }; done
    rm -rf "$d"; return $rc
}

# ---- choose the backup set ---------------------------------------------------------------------
mapfile -t SETS < <(for d in /root/cp-audit-backup-* /root/cp-compare-backup-*; do [[ -d $d ]] && echo "${d##*-backup-} $d"; done | sort | awk '{print $2}')
((${#SETS[@]})) || { echo "No backup folders found in /root (nothing to undo)."; exit 0; }
case "${1:-}" in
    "")   echo "Backup sets (oldest first):"
          i=0; for s in "${SETS[@]}"; do i=$((i+1)); n=$(find "$s" -type f -not -name actions.log -not -path "*/deleted-media/*" | wc -l)
              a=$([[ -f $s/actions.log ]] && wc -l <"$s/actions.log" || echo 0)
              printf '  %d) %s   (%s files, %s actions)%s\n' "$i" "$s" "$n" "$a" "$([[ -e $s/UNDONE ]] && echo '  [already undone]')"; done
          read -rp "  Undo which? [number, Enter = cancel] " pick <&4
          [[ $pick =~ ^[0-9]+$ ]] && ((pick>=1 && pick<=${#SETS[@]})) || exit 0
          S=${SETS[$((pick-1))]} ;;
    last) S=${SETS[-1]} ;;
    *)    S=${1%/}; [[ -d $S ]] || { echo "not a folder: $S"; exit 1; } ;;
esac
hdr "UNDOING: $S"

# ---- 1. config files ---------------------------------------------------------------------------
RESTORE=()
while IFS= read -r f; do
    rel=${f#"$S"}
    if protected "$rel"; then warn "$rel is protected (user/login file) — skipped"; continue; fi
    cmp -s "$f" "$rel" && continue
    RESTORE+=("$rel")
done < <(find "$S" -type f -not -name actions.log -not -name UNDONE -not -path "$S/deleted-media/*" | sort)
if ((${#RESTORE[@]})); then
    echo "  Files changed since the backup:"; printf '    %s\n' "${RESTORE[@]}"
    if confirm "Restore these ${#RESTORE[@]} file(s) from the backup?"; then
        for rel in "${RESTORE[@]}"; do cp -a "$S$rel" "$rel" && ok "restored $rel"; done
        if printf '%s\n' "${RESTORE[@]}" | grep -q '^/etc/ssh/'; then
            mkdir -p /run/sshd; sshd -t 2>/dev/null && systemctl restart ssh 2>/dev/null && ok "sshd config valid, ssh restarted" || warn "sshd -t failed: check /etc/ssh/sshd_config"
        fi
    fi
else ok "config files already match the backup"; fi

# ---- 2. logged actions -------------------------------------------------------------------------
LOG=$S/actions.log
if [[ -f $LOG ]]; then
    act() { awk -F'\t' -v t="$1" '$1==t' "$LOG"; }
    # files the tools created
    mapfile -t NEW < <(act NEWFILE | cut -f2)
    ex=(); for f in "${NEW[@]}"; do [[ -e $f ]] && ! protected "$f" && ex+=("$f"); done
    if ((${#ex[@]})); then echo "  Files the tools created:"; printf '    %s\n' "${ex[@]}"
        confirm "Remove them?" && for f in "${ex[@]}"; do rm -f -- "$f" && ok "removed $f"; done
        printf '%s\n' "${ex[@]}" | grep -q sysctl && warn "sysctl values stay in the running kernel until reboot"
    fi
    # permissions
    while IFS=$'\t' read -r _ f m; do [[ -e $f ]] && ! protected "$f" && confirm "chmod $m $f ?" && chmod "$m" "$f" && ok "mode of $f back to $m"; done < <(act MODE)
    # SUID bits
    mapfile -t SU < <(act SUID)
    if ((${#SU[@]})); then printf '    SUID restored on: %s\n' "$(printf '%s\n' "${SU[@]}" | cut -f2 | tr '\n' ' ')"
        if confirm "Restore the SUID/SGID bits?"; then for l in "${SU[@]}"; do IFS=$'\t' read -r _ f m <<<"$l"; chmod "$m" "$f" && ok "$f -> $m"; done; fi; fi
    # packages
    mapfile -t PK < <(act PKG | cut -f2-)
    if ((${#PK[@]})); then pk=$(printf '%s\n' "${PK[@]}" | tr '\t' ' ' | tr '\n' ' ')
        echo "    Packages removed by the tool: $pk"
        confirm "Reinstall them?" && keep_users env DEBIAN_FRONTEND=noninteractive apt-get install -y $pk >/dev/null 2>&1 && ok "reinstalled" || true; fi
    # services
    mapfile -t SV < <(act SVC)
    if ((${#SV[@]})); then printf '    Services disabled by the tool: %s\n' "$(printf '%s\n' "${SV[@]}" | cut -f2 | tr '\n' ' ')"
        if confirm "Re-enable/start them as they were?"; then
            for l in "${SV[@]}"; do IFS=$'\t' read -r _ s en act_ <<<"$l"
                [[ $en == 1 ]] && systemctl enable "$s" 2>/dev/null; [[ $act_ == 1 ]] && systemctl start "$s" 2>/dev/null; ok "$s restored (enabled=$en running=$act_)"; done; fi; fi
    # firewall
    if [[ -n $(act UFW_ENABLED) ]]; then confirm "Disable UFW again (it was off before)?" && ufw disable >/dev/null 2>&1 && ok "UFW disabled"; fi
    # media
    mapfile -t MD < <(act MEDIA | cut -f2)
    if ((${#MD[@]})); then echo "    Media files moved into the backup:"; printf '      %s\n' "${MD[@]}"
        if confirm "Put them back where they were?"; then
            for f in "${MD[@]}"; do [[ -e $S/deleted-media$f && ! -e $f ]] && mkdir -p "$(dirname "$f")" && mv -n "$S/deleted-media$f" "$f" && ok "restored $f"; done; fi; fi
else ok "no action log in this backup (only config files were backed up)"; fi

[[ $DRY_RUN == 1 ]] || touch "$S/UNDONE"
hdr "SUMMARY"
if [[ "$USERS_BEFORE" == "$(user_state)" ]]; then ok "USERS UNTOUCHED: passwd/shadow/group/sudoers identical to before this run"
else bad "user-related state changed during this run — investigate!"; fi
echo
