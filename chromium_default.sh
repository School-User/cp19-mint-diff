#!/usr/bin/env bash
# Makes Chromium the default browser on Linux Mint 21 and blocks pop-ups (competition rules:
# "Chromium is the default browser", "block pop-ups and redirects"). Runs as root.
#   sudo bash chromium_default.sh             apply (backs up every file it edits first)
#   sudo DRY_RUN=1 bash chromium_default.sh   report only, change nothing
#   sudo EXPIRE_OTHERS=1 bash chromium_default.sh   also expire every other human user's password
#                                             (they must change it at next login); the sudo user is kept
# Chromium has no separate "block redirects" policy; blocking pop-ups is the setting that applies here.

set -uo pipefail

R=$'\033[0;31m' G=$'\033[0;32m' Y=$'\033[1;33m' N=$'\033[0m'
bad()  { echo -e "  ${R}[!]${N} $*"; }
warn() { echo -e "  ${Y}[~]${N} $*"; }
ok()   { echo -e "  ${G}[+]${N} $*"; }

[[ $EUID -eq 0 ]] || { echo -e "${R}Run with sudo.${N}"; exit 1; }

DRY_RUN=${DRY_RUN:-0}
if ( : </dev/tty ) 2>/dev/null; then exec 4</dev/tty; else exec 4<&0; fi   # prompts also work under curl | sh
BK=/root/cp-chromium-backup-$(date +%Y%m%d-%H%M%S)
CHANGED=0

backup() {  # copy a file once before the first edit
    [[ -e $1 ]] || return 0
    mkdir -p "$BK/$(dirname "$1")"
    [[ -e $BK$1 ]] || cp -a "$1" "$BK$1"
}

# --- find the installed Chromium -------------------------------------------------------------
BIN=$(command -v chromium-browser || command -v chromium || true)
DESKTOP=""
for d in chromium-browser.desktop chromium.desktop; do
    [[ -f /usr/share/applications/$d ]] && { DESKTOP=$d; break; }
done
if [[ -z $BIN || -z $DESKTOP ]]; then
    bad "Chromium is not installed (no chromium binary or .desktop file). Install it first; nothing was changed."
    exit 1
fi
ok "Chromium found: $BIN ($DESKTOP)"

# --- default browser: system-wide mimeapps --------------------------------------------------
MIME=/etc/xdg/mimeapps.list
want_mime() {  # key=value lines that make Chromium the default for web content
    cat <<EOF
text/html=$DESKTOP
x-scheme-handler/http=$DESKTOP
x-scheme-handler/https=$DESKTOP
x-scheme-handler/about=$DESKTOP
EOF
}
if [[ $DRY_RUN == 1 ]]; then
    warn "[dry-run] would set $DESKTOP as the default for http, https, about and text/html in $MIME"
else
    backup "$MIME"
    tmp=$(mktemp)
    # keep the file's other entries, drop the keys we set, then add them under [Default Applications]
    if [[ -f $MIME ]]; then
        awk -F= '/^\[/{print; next} !($1 ~ /^(text\/html|x-scheme-handler\/(http|https|about))$/){print}' "$MIME" >"$tmp"
    fi
    grep -q '^\[Default Applications\]' "$tmp" 2>/dev/null || echo '[Default Applications]' >>"$tmp"
    awk -v add="$(want_mime)" '
        BEGIN { n = split(add, lines, "\n") }
        { print }
        /^\[Default Applications\]/ && !done { for (i = 1; i <= n; i++) if (lines[i] != "") print lines[i]; done = 1 }
    ' "$tmp" >"$tmp.2" && mv "$tmp.2" "$MIME"
    rm -f "$tmp"
    chmod 644 "$MIME"
    ok "default browser set in $MIME"
    CHANGED=1
fi

# --- alternatives used by terminal and launcher fallbacks ------------------------------------
for alt in x-www-browser gnome-www-browser; do
    if update-alternatives --list "$alt" 2>/dev/null | grep -q "$BIN"; then
        if [[ $DRY_RUN == 1 ]]; then warn "[dry-run] would point $alt at $BIN"
        else update-alternatives --set "$alt" "$BIN" >/dev/null 2>&1 && ok "$alt -> $BIN" && CHANGED=1 \
             || bad "could not set $alt"; fi
    else
        warn "no $alt alternative for $BIN (skipped)"
    fi
done

# --- pop-up blocking via managed policy (both packaging paths) ------------------------------
POLICY='{
  "DefaultPopupsSetting": 2
}'
for dir in /etc/chromium/policies/managed /etc/chromium-browser/policies/managed; do
    f=$dir/cp-block-popups.json
    if [[ $DRY_RUN == 1 ]]; then warn "[dry-run] would write $f (DefaultPopupsSetting=2)"; continue; fi
    backup "$f"
    mkdir -p "$dir"
    printf '%s\n' "$POLICY" >"$f" && chmod 644 "$f"
    ok "pop-ups blocked by policy: $f"
    CHANGED=1
done

# --- optional: expire every other human account's password (EXPIRE_OTHERS=1) -------------------
# chage -d 0 makes the password expired: that user must choose a new one at next login. Accounts are
# not locked and nothing is removed. The user who ran sudo is skipped, as are root and system accounts.
if [[ ${EXPIRE_OTHERS:-0} == 1 ]]; then
    me=${SUDO_USER:-}
    if [[ $DRY_RUN != 1 ]]; then
        read -rp "Which user's password should NOT be expired (kept until they next log in)? [${me:-none}] " ans <&4
        me=${ans:-$me}
    fi
    if [[ -z $me || $me == root ]] && ! id "$me" >/dev/null 2>&1; then
        bad "no valid user to keep; skipping the expiry step."
    else
        ok "keeping this user unchanged: $me"
        others=$(awk -F: -v me="$me" '$3>=1000 && $3<65534 && $1!="nobody" && $1!=me {print $1}' /etc/passwd)
        if [[ -z $others ]]; then
            warn "no other human accounts to expire"
        else
            for u in $others; do
                if [[ $DRY_RUN == 1 ]]; then warn "[dry-run] would expire the password of $u"; continue; fi
                backup /etc/shadow
                if chage -d 0 "$u" 2>/dev/null; then ok "password expired (must change at next login): $u"; CHANGED=1
                else bad "could not expire $u"; fi
            done
        fi
    fi
fi

# --- verify ------------------------------------------------------------------------------------
echo
if [[ $DRY_RUN == 1 ]]; then
    warn "dry run: nothing changed."
else
    default=$(xdg-settings get default-web-browser 2>/dev/null || true)
    [[ $default == "$DESKTOP" ]] && ok "xdg-settings default-web-browser: $default" \
        || warn "xdg-settings reports '${default:-none}' (a per-user mimeapps.list may override the system default)"
    echo "  Backups: $BK"
fi
