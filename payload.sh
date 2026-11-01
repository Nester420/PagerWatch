#!/bin/bash
# Title: PagerWatch
# Description: Wi-Fi/BLE awareness: Axon, Flock, trackers and related device signatures. Prototype; hardware validation required.
# Author: Nester project / Codex-assisted prototype; upstream research credited in NOTICE.md
# Version: 1.0.11
# Category: Reconnaissance

# The Pager may stage this script in /tmp. Its source path is not necessarily
# the installation path of the Python package and supporting files.
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CALLER_DIR="$PWD"
export PATH="/mmc/usr/bin:$PATH"
umask 077
command -v LOG >/dev/null 2>&1 || LOG() { echo "$*"; }
ERROR_LOG=/tmp/pagerwatch-startup.log
: > "$ERROR_LOG"
chmod 600 "$ERROR_LOG" 2>/dev/null
fail_visible() {
    local message="$1"
    local detail
    detail="$(tail -n 4 "$ERROR_LOG" 2>/dev/null | cut -c1-100)"
    LOG "red" "$message"
    [ -n "$detail" ] && LOG "red" "$detail"
    if command -v ERROR_DIALOG >/dev/null 2>&1; then
        ERROR_DIALOG "$message
$detail
Photo this message. Details: $ERROR_LOG" || true
    elif command -v PROMPT >/dev/null 2>&1; then
        PROMPT "$message
$detail
Photo this message. Details: $ERROR_LOG" || true
    elif command -v WAIT_FOR_INPUT >/dev/null 2>&1; then
        LOG "Press a button to close."
        WAIT_FOR_INPUT >/dev/null 2>&1 || true
    fi
    # The detailed dialog was handled here. Avoid the Pager's generic exit-error popup.
    exit 0
}
is_pagerwatch_directory() {
    [ -n "$1" ] && [ -f "$1/run.py" ] && [ -f "$1/rules.json" ] \
        && [ -f "$1/pagerwatch/app.py" ] && [ -f "$1/pagerwatch/__init__.py" ]
}
DIR=""
for candidate in "${PAGERWATCH_DIR:-}" "${PAYLOAD_DIR:-}" "$SOURCE_DIR" "$CALLER_DIR" \
    /root/payloads/user/reconnaissance/PagerWatch \
    /mmc/root/payloads/user/reconnaissance/PagerWatch \
    /root/payloads/user/general/PagerWatch \
    /mmc/root/payloads/user/general/PagerWatch; do
    if is_pagerwatch_directory "$candidate"; then
        DIR="$(cd "$candidate" && pwd -P)"
        break
    fi
done
if [ -z "$DIR" ]; then
    # Support a renamed payload folder/category without searching outside the
    # payload installation trees. Resolve /root and /mmc symlink aliases once.
    matches="$(
        for tree in /root/payloads /mmc/root/payloads; do
            [ -d "$tree" ] || continue
            find "$tree" -type f -name run.py 2>/dev/null
        done | while IFS= read -r file; do
            candidate="${file%/run.py}"
            if is_pagerwatch_directory "$candidate"; then
                (cd "$candidate" && pwd -P)
            fi
        done | sort -u
    )"
    count="$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l)"
    if [ "$count" -eq 1 ]; then
        DIR="$matches"
    elif [ "$count" -gt 1 ]; then
        printf 'Multiple installations found:\n%s\n' "$matches" >> "$ERROR_LOG"
        fail_visible "PagerWatch: multiple installed copies found."
    fi
fi
if [ -z "$DIR" ]; then
    printf 'Staged script: %s\nCaller folder: %s\nNo complete PagerWatch installation found in payloads.\n' "$SOURCE_DIR" "$CALLER_DIR" >> "$ERROR_LOG"
    fail_visible "PagerWatch: installed support files not found."
fi
export LD_LIBRARY_PATH="/mmc/usr/lib:/mmc/lib:$DIR/lib:${LD_LIBRARY_PATH:-}"
cd "$DIR" 2>>"$ERROR_LOG" || fail_visible "PagerWatch: cannot open its installed folder."
printf 'Installed folder: %s\n' "$DIR" >> "$ERROR_LOG"
LOCK=/tmp/pagerwatch.lock
if [ -d "$LOCK" ] && [ ! -L "$LOCK" ] && [ -f "$LOCK/pid" ]; then
    lock_pid="$(cat "$LOCK/pid" 2>/dev/null)"
    if [[ "$lock_pid" =~ ^[0-9]+$ ]] && ! kill -0 "$lock_pid" 2>/dev/null; then
        rm -f "$LOCK/pid"
        rmdir "$LOCK" 2>/dev/null || true
    fi
fi
if ! mkdir "$LOCK" 2>/dev/null; then
    fail_visible "PagerWatch: already running or a stale lock remains."
fi
echo "$$" > "$LOCK/pid"
RESTART=0
CHILD=""
ISOLATED=0
stop_worker_group() {
    if [ "$ISOLATED" = 1 ] && [[ "$CHILD" =~ ^[0-9]+$ ]];then
        kill -TERM -- "-$CHILD" 2>/dev/null || true
        sleep 1
        kill -KILL -- "-$CHILD" 2>/dev/null || true
    fi
}
cleanup() {
    trap - EXIT INT TERM
    if [ -n "$CHILD" ] && kill -0 "$CHILD" 2>/dev/null; then
        kill -TERM "$CHILD" 2>/dev/null
        wait "$CHILD" 2>/dev/null
    fi
    stop_worker_group
    [ "$RESTART" = 1 ] && /etc/init.d/pineapplepager start >/dev/null 2>&1
    rm -f "$LOCK/pid"
    rmdir "$LOCK" 2>/dev/null
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
[ -f "$DIR/bootstrap.sh" ] || fail_visible "PagerWatch: dependency helper missing; copy the whole folder."
source "$DIR/bootstrap.sh"
# Remove the retired feature module left by an overwrite update; keep all logs.
rm -f -- "$DIR/pagerwatch/handshake.py" >>"$ERROR_LOG" 2>&1 || fail_visible "PagerWatch: retired module cleanup failed."
for retired in "$DIR/pagerwatch"/__pycache__/handshake.*.pyc; do
    [ ! -e "$retired" ] || rm -f -- "$retired" >>"$ERROR_LOG" 2>&1
done
pw_bootstrap || fail_visible "PagerWatch: required dependencies unavailable. Connect to internet and relaunch."
PYTHON="$(command -v python3 2>/dev/null || true)"
[ -n "$PYTHON" ] || fail_visible "PagerWatch: Python 3 is not installed."
"$PYTHON" -c 'import sys; assert sys.version_info >= (3, 9), "Python 3.9+ required"; import ctypes, dataclasses, json, pty, threading, csv' >>"$ERROR_LOG" 2>&1 \
    || fail_visible "PagerWatch: Python support is missing."
"$PYTHON" -c 'from pagerwatch.app import load_pager; load_pager()' >>"$ERROR_LOG" 2>&1 \
    || fail_visible "PagerWatch: display library could not load."
if command -v CONFIRMATION_DIALOG >/dev/null 2>&1; then
    CONFIRMATION_DIALOG "Start PagerWatch? Wi-Fi/BLE discovery; alerts are signature matches. B finishes and saves logs." || exit 0
fi
cd "$DIR" || fail_visible "PagerWatch: payload folder disappeared."
# Native display ownership follows pagerctl's documented takeover procedure.
if /etc/init.d/pineapplepager running >/dev/null 2>&1; then
    RESTART=1
    /etc/init.d/pineapplepager stop >>"$ERROR_LOG" 2>&1 || fail_visible "PagerWatch: cannot release the display."
fi
if command -v setsid >/dev/null 2>&1;then
    ISOLATED=1
    PAGERWATCH_ISOLATED=1 setsid "$PYTHON" -u run.py >>"$ERROR_LOG" 2>&1 &
else
    LOG yellow 'setsid unavailable: heartbeat logs stalls; automatic display recovery is disabled.'
    "$PYTHON" -u run.py >>"$ERROR_LOG" 2>&1 &
fi
CHILD=$!
wait "$CHILD"
RESULT=$?
stop_worker_group
CHILD=""
if [ "$RESULT" -ne 0 ]; then
    if [ "$RESTART" = 1 ] || [ "$RESULT" = 70 ]; then
        /etc/init.d/pineapplepager start >>"$ERROR_LOG" 2>&1
        RESTART=0
        sleep 1
    fi
    fail_visible "PagerWatch stopped (code $RESULT)."
fi
exit 0
