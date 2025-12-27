#!/usr/bin/bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_NAME="$(basename "$0")"
LOG_FILE=""

# ---------- Helpers ----------

# Print error message to stderr
error() {
  printf "ERROR: %s\n" "$1" >&2
}

# Print info message
info() {
  printf "%s\n" "$1"
}

# Pause so output is readable in interactive mode
pause() {
  printf "\nPress Enter to continue..."
  read -r _
}

# Ensure required dependency exists
require_cmd() {
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || {
      error "Missing dependency: $cmd"
      exit 127
    }
  done
}

# Validate log file exists, is readable, and non-empty
require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    error "File '$path' does not exist or is not a regular file."
    return 1
  fi
  if [[ ! -r "$path" ]]; then
    error "File '$path' is not readable."
    return 1
  fi
  if [[ ! -s "$path" ]]; then
    error "File '$path' is empty."
    return 1
  fi
  return 0
}

# Select log file interactively if not passed as argument
select_log_file() {
  while true; do
    printf "Enter path to log file (or 'q' to quit): "
    read -r candidate
    [[ "$candidate" == "q" ]] && exit 0
    if require_file "$candidate"; then
      LOG_FILE="$candidate"
      info "Using log file: $LOG_FILE"
      break
    fi
  done
}

# Print usage instructions
print_usage() {
  cat <<EOF
Usage:
  $SCRIPT_NAME LOG_FILE
  $SCRIPT_NAME       # interactive selection

Description:
  Log anomaly detector (blue-team focused):
    - Parses and extracts IPv4 addresses
    - Shows top N IP addresses by event count
    - Detects SSH/HTTP brute-force indicators
    - Matches suspicious payloads (SQLi/XSS/path traversal)
    - Exports suspicious lines to a file

Flags:
  --stats            Show basic statistics and exit
  --ips              List unique IPs and exit
  --top N            Show top N IPs and exit (default 10)
  --bruteforce N     Show brute-force sources >= threshold N and exit (default 5)
  --export FILE      Export suspicious lines to FILE and exit (default suspicious.log)
  --no-clear         Disable terminal clearing (useful for CI/Windows)
EOF
}

# ---------- Dependencies ----------

require_cmd gawk sort

# ---------- Core Operations ----------

run_stats() {
  gawk '
  BEGIN {
    total = 0
    ip_re = "([0-9]{1,3}\\.){3}[0-9]{1,3}"
    ssh_re = "Failed password|Invalid user|authentication failure"
    http_re = "(^| )40[134]( |$)"
    sus_re = "(select.+from|union.+select|<script| onerror=|\\bor 1=1\\b|/etc/passwd|cmd=|\\.\\.\\/|%27|%3cscript)"
    IGNORECASE = 1
  }
  {
    total++
    if (match($0, ip_re)) {
      ip = substr($0, RSTART, RLENGTH)
      uniq[ip] = 1
    }
    if ($0 ~ ssh_re) ssh++
    if ($0 ~ http_re) http++
    if ($0 ~ sus_re) sus++
  }
  END {
    u = 0
    for (i in uniq) u++
    printf "Total lines: %d\nUnique IPs: %d\nSSH brute-force indicators: %d\nHTTP suspicious codes: %d\nSuspicious payload matches: %d\n",
           total, u, ssh + 0, http + 0, sus + 0
  }' "$LOG_FILE"
}

run_ips() {
  gawk '{
    ip_re="([0-9]{1,3}\\.){3}[0-9]{1,3}"
    while(match($0,ip_re)){
      ip=substr($0,RSTART,RLENGTH)
      print ip
      $0=substr($0,RSTART+RLENGTH)
    }
  }' "$LOG_FILE" | sort -u
}

run_top() {
  local N="$1"
  gawk -v N="$N" '{
    ip_re="([0-9]{1,3}\\.){3}[0-9]{1,3}"
    if(match($0,ip_re)){
      ip=substr($0,RSTART,RLENGTH)
      c[ip]++
    }
  }
  END{
    n=asorti(c,i,"@val_num_desc")
    limit=(N<n?N:n)
    printf "%-18s %s\n","IP","Events"
    printf "-------------------------\n"
    for(x=1;x<=limit;x++) printf "%-18s %d\n",i[x],c[i[x]]
  }' "$LOG_FILE"
}

run_bruteforce() {
  local T="$1"
  gawk -v THRESH="$T" '{
    ip_re="([0-9]{1,3}\\.){3}[0-9]{1,3}"
    ssh_re="Failed password|Invalid user|authentication failure"
    http_re="( |^)40[134]( |$)"
    IGNORECASE=1
    if($0 ~ ssh_re || $0 ~ http_re){
      if(match($0,ip_re)){
        ip=substr($0,RSTART,RLENGTH)
        a[ip]++
      }
    }
  }
  END{
    printf "%-18s %s\n","IP","Suspicious events"
    printf "-----------------------------\n"
    for(ip in a) if(a[ip]>=THRESH) printf "%-18s %d\n",ip,a[ip]
  }' "$LOG_FILE"
}

run_export() {
  local OUT="$1"
  gawk 'BEGIN{
    IGNORECASE=1
    sus="(select.+from|union.+select|<script| onerror=|\\bor 1=1\\b|/etc/passwd|cmd=|\\.\\.\\/|%27|%3cscript)"
  }
  $0 ~ sus {print}' "$LOG_FILE" > "$OUT"
  printf "source=%s\ncreated_utc=%s\npattern=%s\n" \
    "$LOG_FILE" \
    "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    "(select.+from|union.+select|<script| onerror=|\\bor 1=1\\b|/etc/passwd|cmd=|\\.\\.\\/|%27|%3cscript)" \
    > "$OUT.meta"
}

# ---------- Flags ----------

NO_CLEAR=0
if [[ "${1:-}" == "--no-clear" ]]; then
  NO_CLEAR=1
  shift
fi

# Parse flags that may still require a log file argument
case "${1:-}" in
  --stats|--ips|--top|--bruteforce|--export)
    if [[ $# -lt 2 ]]; then
      print_usage
      exit 1
    fi
    LOG_FILE="$2"
    if ! require_file "$LOG_FILE"; then
      exit 1
    fi
    ;;
esac

case "${1:-}" in
  --stats)
    run_stats
    exit 0
    ;;
  --ips)
    run_ips
    exit 0
    ;;
  --top)
    n="${3:-10}"
    [[ "$n" =~ ^[0-9]+$ ]] || { error "N must be an integer."; exit 1; }
    run_top "$n"
    exit 0
    ;;
  --bruteforce)
    t="${3:-5}"
    [[ "$t" =~ ^[0-9]+$ ]] || { error "Threshold must be an integer."; exit 1; }
    run_bruteforce "$t"
    exit 0
    ;;
  --export)
    out="${3:-suspicious.log}"
    run_export "$out"
    info "Wrote: $out"
    info "Meta:  $out.meta"
    exit 0
    ;;
esac

# ---------- Entry Point (interactive) ----------

if [[ $# -ge 1 ]]; then
  if require_file "$1"; then
    LOG_FILE="$1"
  else
    print_usage
    exit 1
  fi
else
  print_usage
  select_log_file
fi

main_menu() {
  while true; do
    [[ $NO_CLEAR -eq 0 ]] && clear
    cat <<EOF
===== Log Anomaly Detector =====
Log file: ${LOG_FILE}

1) Show basic statistics
2) List unique IP addresses
3) Show top N IPs
4) Detect brute-force sources
5) Export suspicious lines
0) Exit
EOF
    printf "Choice: "
    read -r ch

    case "$ch" in
      1)
        run_stats
        pause
        ;;
      2)
        run_ips
        pause
        ;;
      3)
        printf "N (default 10): "
        read -r n
        [[ -z "${n:-}" ]] && n=10
        [[ "$n" =~ ^[0-9]+$ ]] || { error "N must be an integer."; pause; continue; }
        run_top "$n"
        pause
        ;;
      4)
        printf "Threshold (default 5): "
        read -r t
        [[ -z "${t:-}" ]] && t=5
        [[ "$t" =~ ^[0-9]+$ ]] || { error "Threshold must be an integer."; pause; continue; }
        run_bruteforce "$t"
        pause
        ;;
      5)
        printf "Output file (default suspicious.log): "
        read -r o
        [[ -z "${o:-}" ]] && o="suspicious.log"
        run_export "$o"
        info "Wrote: $o"
        info "Meta:  $o.meta"
        pause
        ;;
      0) exit 0 ;;
      *) error "Invalid choice"; pause ;;
    esac
  done
}

main_menu
