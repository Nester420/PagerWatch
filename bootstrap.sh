#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Sourced before display takeover. Installs missing software from configured feeds.
pw_bootstrap() {
    local -a packages=() timer=() destination=() install_destination=()
    local pkg tool python available_kb storage=/ missing=0 required_missing=0 started=$SECONDS
    python="$(command -v python3 2>/dev/null || true)"
    if [ -z "$python" ] || ! "$python" -c 'import sys; assert sys.version_info >= (3,9); import ctypes, ssl, http.server, dataclasses, pty, csv, threading, email, json, subprocess' >/dev/null 2>&1; then
        packages+=(python3)
    fi
    command -v iw >/dev/null 2>&1 || packages+=(iw)
    command -v tcpdump >/dev/null 2>&1 || packages+=(tcpdump)
    command -v ip >/dev/null 2>&1 || packages+=(ip-full)
    command -v bluetoothctl >/dev/null 2>&1 || packages+=(bluez-daemon)
    if ! command -v hcitool >/dev/null 2>&1 || ! command -v hcidump >/dev/null 2>&1 || ! command -v hciconfig >/dev/null 2>&1; then packages+=(bluez-utils);fi
    # Driver dependencies are resolved by opkg, with its firmware/kernel ABI checks.
    # Do not force a kernel mismatch or download third-party driver binaries.
    local usb vendor product child bound
    for usb in /sys/bus/usb/devices/*; do
        [ -f "$usb/idVendor" ] && [ -f "$usb/idProduct" ] || continue
        vendor="$(cat "$usb/idVendor")";product="$(cat "$usb/idProduct")";bound=0
        for child in "$usb"/driver "$usb":*/driver;do [ -e "$child" ] && bound=1;done
        if [ "$bound" = 0 ] && [ "$vendor:$product" = '0e8d:7961' ];then packages+=(kmod-mt7921u);break;fi
    done
    if [ "${#packages[@]}" -eq 0 ]; then LOG green 'PagerWatch dependencies ready.';return 0;fi
    LOG yellow "PagerWatch: checking missing packages: ${packages[*]}"
    printf 'Missing packages: %s\n' "${packages[*]}" >> "$ERROR_LOG"
    if command -v timeout >/dev/null 2>&1; then timer=(timeout)
    elif command -v busybox >/dev/null 2>&1 && busybox --list 2>/dev/null | grep -qx timeout; then timer=(busybox timeout);fi
    if command -v opkg >/dev/null 2>&1 && [ "${#timer[@]}" -gt 0 ];then
        if grep -Eq '^[[:space:]]*dest[[:space:]]+mmc[[:space:]]+/mmc/?([[:space:]]|$)' /etc/opkg.conf /etc/opkg/*.conf 2>/dev/null;then destination=(-d mmc);storage=/mmc;fi
        available_kb="$(df -Pk "$storage" 2>/dev/null | awk 'NR==2 {print $4}')"
        if [[ "$available_kb" =~ ^[0-9]+$ ]] && [ "$available_kb" -ge 51200 ];then
            LOG yellow 'Refreshing package lists (internet required, up to 45 seconds)...'
            if "${timer[@]}" 45 opkg update >> "$ERROR_LOG" 2>&1;then
                # Each package gets a bounded attempt. No upgrades, --force or feed changes.
                for pkg in "${packages[@]}";do
                    if [ $((SECONDS-started)) -gt 180 ];then LOG yellow 'Dependency time limit reached; retry on next launch.';break;fi
                    LOG yellow "Installing $pkg (up to 60 seconds)..."
                    install_destination=("${destination[@]}")
                    if [[ "$pkg" = kmod-* ]];then
                        install_destination=()
                        available_kb="$(df -Pk / 2>/dev/null | awk 'NR==2 {print $4}')"
                        if ! [[ "$available_kb" =~ ^[0-9]+$ ]] || [ "$available_kb" -lt 8192 ];then LOG yellow 'Need 8 MB on system storage for USB kernel support.';continue;fi
                    fi
                    "${timer[@]}" 60 opkg "${install_destination[@]}" install "$pkg" >> "$ERROR_LOG" 2>&1 || LOG yellow "Could not install $pkg. See startup log."
                done
            else LOG yellow 'Package lists unavailable. Continuing with installed tools.';fi
        else LOG yellow 'Need 50 MB free to install packages. Continuing with installed tools.';fi
    else LOG yellow 'Automatic install unavailable: opkg or a bounded timeout runner is missing.';fi
    python="$(command -v python3 2>/dev/null || true)"
    if [ -z "$python" ] || ! "$python" -c 'import sys; assert sys.version_info >= (3,9); import ctypes, ssl, http.server, dataclasses, pty, csv, threading, email, json, subprocess' >/dev/null 2>&1;then
        LOG red 'Python support is still missing. Connect Pager to internet and relaunch.';return 1
    fi
    for tool in iw tcpdump ip bluetoothctl hcitool hcidump hciconfig;do
        if ! command -v "$tool" >/dev/null 2>&1;then LOG yellow "Unavailable: $tool — related features may be disabled.";missing=1;fi
    done
    [ "$missing" -eq 0 ] && LOG green 'PagerWatch dependencies ready.'
    return 0
}
