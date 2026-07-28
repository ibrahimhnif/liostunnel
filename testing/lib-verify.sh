#!/usr/bin/env bash
# shellcheck shell=bash
#
# Portability shims for the Phase 1a verification, sourced by the runner.
#
# One script runs on both platforms deliberately. Two scripts that each decide
# what "verified" means would drift, and a criterion that means something
# different per platform is worth less than one that means nothing.

case "$(uname -s)" in
  Darwin) LIOS_OS=macos ;;
  Linux)  LIOS_OS=linux ;;
  *)      echo "unsupported platform $(uname -s)"; exit 1 ;;
esac

# Every IPv4 route, one per line, in whatever the platform's native form is.
routes() {
  case $LIOS_OS in
    macos) netstat -rn -f inet 2>/dev/null ;;
    linux) ip -4 route show 2>/dev/null ;;
  esac
}

# Just the default route(s), for the "we never touched it" check.
default_route() {
  case $LIOS_OS in
    macos) netstat -rn -f inet 2>/dev/null | grep '^default' ;;
    linux) ip -4 route show default 2>/dev/null ;;
  esac
}

# Interface names, space separated and stable in order.
iface_list() {
  case $LIOS_OS in
    macos) ifconfig -l 2>/dev/null | tr ' ' '\n' | sort | tr '\n' ' ' ;;
    linux) ip -br link 2>/dev/null | awk '{print $1}' | sed 's/@.*//' | sort | tr '\n' ' ' ;;
  esac
}

# The tunnel interface this platform will have created.
tun_iface() {
  case $LIOS_OS in
    macos) ifconfig -l | tr ' ' '\n' | grep '^utun' | tail -1 ;;
    linux) ip -br link | awk '{print $1}' | sed 's/@.*//' | grep -E '^(tun|utun)' | tail -1 ;;
  esac
}

# Pattern matching any tunnel interface, for leftover detection.
tun_pattern() {
  case $LIOS_OS in
    macos) echo 'utun' ;;
    linux) echo 'tun' ;;
  esac
}

# NOT `stat -f ... || stat -c ...`: on Linux `-f` means "filesystem status",
# succeeds, and the fallback never runs — which reported a wall of filesystem
# stats as the file's owner.
file_owner() {
  case $LIOS_OS in
    macos) stat -f '%u' "$1" ;;
    linux) stat -c '%u' "$1" ;;
  esac
}
file_mode() {
  case $LIOS_OS in
    macos) stat -f '%Lp' "$1" ;;
    linux) stat -c '%a' "$1" ;;
  esac
}

# An unprivileged account that exists on both platforms, for the P1a-5 check.
other_user() {
  case $LIOS_OS in
    macos) echo nobody ;;
    linux) id -u nobody >/dev/null 2>&1 && echo nobody || echo daemon ;;
  esac
}
