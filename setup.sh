#!/bin/sh
# CyberPatriot toolkit launcher (POSIX sh). Run from a normal user terminal on the VM:
#   curl -fsSL <raw_url>/setup.sh | sh                  menu
#   curl -fsSL <raw_url>/setup.sh | sh -s audit         find misconfigurations, offer to fix
#   curl -fsSL <raw_url>/setup.sh | sh -s compare       live VM vs clean Mint 21 base
#   curl -fsSL <raw_url>/setup.sh | sh -s forensics     read-only forensics helper (extra args allowed)
#   curl -fsSL <raw_url>/setup.sh | sh -s users         read-only: compare accounts to the README, print commands
#   curl -fsSL <raw_url>/setup.sh | sh -s undo          reverse a previous audit/compare run
#   curl -fsSL <raw_url>/setup.sh | DRY_RUN=1 sh        report only, change nothing
#   curl -fsSL <raw_url>/setup.sh | FIX_ONLY=Firewall sh -s audit   only fix one category (see audit.sh)
#   curl -fsSL <raw_url>/setup.sh | PW_POLICY=secure sh -s audit   apply the preconfigured secure password policy
# Users are never modified by any of these tools.

REPO="${REPO:-https://raw.githubusercontent.com/School-User/cp19-mint-diff/main}"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || die "curl not found"
command -v bash >/dev/null 2>&1 || die "bash not found"

TOOL=${1:-}; [ $# -gt 0 ] && shift
if [ -z "$TOOL" ]; then
    [ -r /dev/tty ] || die "no terminal for the menu; use:  curl ... | sh -s audit"
    printf '\n  CyberPatriot toolkit\n'
    printf '    1) audit      find misconfigurations and offer to fix them\n'
    printf '    2) compare    compare this VM to a clean Mint 21 base, offer to restore\n'
    printf '    3) forensics  read-only helper for forensics questions\n'
    printf '    4) users      compare accounts with the README (read-only, prints commands)\n'
    printf '    5) undo       reverse a previous audit/compare run\n'
    printf '    6) both       audit, then compare\n'
    printf '    q) quit\n  > '
    read -r ans </dev/tty || exit 0
    case $ans in 1) TOOL=audit ;; 2) TOOL=compare ;; 3) TOOL=forensics ;; 4) TOOL=users ;; 5) TOOL=undo ;; 6) TOOL=both ;; *) exit 0 ;; esac
fi

DEST=$(mktemp -d /tmp/cp-tools.XXXXXX) || die "mktemp failed"
trap 'rm -rf "$DEST"' EXIT INT TERM

fetch() { curl -fsSL "$REPO/$1" -o "$DEST/$1" || die "could not download $1 from $REPO"; }
SUDO=""; [ "$(id -u)" -ne 0 ] && { command -v sudo >/dev/null 2>&1 || die "run as root or install sudo"; SUDO=sudo; }
run() {  # run FILE [args...] as root; keep the options the tools understand
    f=$1; shift
    $SUDO env "DRY_RUN=${DRY_RUN:-0}" "AUTH_ADMINS=${AUTH_ADMINS:-}" "BASE_ROOT=${BASE_ROOT:-}" "FIX_ONLY=${FIX_ONLY:-}" "PW_POLICY=${PW_POLICY:-}" "AUTH_USERS=${AUTH_USERS:-}" "NO_REPORT=${NO_REPORT:-0}" "REPORT_DIR=${REPORT_DIR:-}" bash "$DEST/$f" "$@" </dev/tty
}

case $TOOL in
    audit)     fetch audit.sh;        run audit.sh ;;
    compare)   fetch compare_live.sh; run compare_live.sh ;;
    forensics) fetch forensics.sh;    run forensics.sh "$@" ;;
    users)     fetch useraudit.sh;    run useraudit.sh "$@" ;;
    undo)      fetch undo.sh;         run undo.sh "$@" ;;
    both)      fetch audit.sh; fetch compare_live.sh; run audit.sh; run compare_live.sh ;;
    *) die "unknown tool '$TOOL' (use: audit | compare | forensics | users | undo | both)" ;;
esac
