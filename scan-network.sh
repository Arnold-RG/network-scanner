#!/usr/bin/env bash
# =============================================================================
# scan-network.sh - Discover live hosts on a local IPv4 subnet
# -----------------------------------------------------------------------------
# Purpose : Ping-sweep a CIDR range, resolve reverse-DNS hostnames and run a
#           quick TCP check of common ports on every live host.
# Usage   : ./scan-network.sh -t 192.168.1.0/24 [-p 22,80,443] [-j 64]
#                             [-w 1] [-o hosts.csv] [-n] [-N]
#           ./scan-network.sh -h
# Requires: bash 4.3+, coreutils `timeout`. Optional: `ping` (iputils),
#           `getent`/`host` for hostnames, `nmap` (used only with -N).
#           No root needed. Without `ping`, liveness falls back to TCP probes
#           (a "connection refused" answer still proves the host is up).
# Author  : Arnold Rurangwa - MIT License
# Legal   : Only scan networks you own or are explicitly authorised to test.
# =============================================================================
set -uo pipefail

# ---- defaults ---------------------------------------------------------------
TARGET=""
PORTS="22,53,80,135,139,443,445,3389,8080"
JOBS=64
TIMEOUT=1
CSV=""
SKIP_PORTS=0
USE_NMAP=0
ASSUME_ALIVE=0    # set when nmap already did host discovery
MAX_HOSTS=65536   # refuse anything larger than a /16

usage() {
    cat <<USAGE
Usage: $(basename "$0") -t <CIDR> [options]

Discover live hosts on an IPv4 subnet (ping sweep + reverse DNS + port check).

  -t CIDR    Target network, e.g. 192.168.1.0/24 or a single IP (10.0.0.5)
  -p PORTS   Comma-separated ports to check on live hosts
             (default: $PORTS)
  -j N       Parallel probes (default: $JOBS, max 256)
  -w SEC     Per-probe timeout in seconds (default: $TIMEOUT)
  -o FILE    Also write results to a CSV file
  -n         Skip the port check (discovery only)
  -N         Use nmap for discovery if it is installed (nmap -sn)
  -h         Show this help

Examples:
  $(basename "$0") -t 192.168.1.0/24
  $(basename "$0") -t 10.0.0.0/28 -p 22,80 -j 32 -o lan.csv

Only scan networks you own or are authorised to test.
USAGE
}

die() { echo "Error: $*" >&2; exit 2; }

# ---- argument parsing ----------------------------------------------------------
while getopts ":t:p:j:w:o:nNh" opt; do
    case "$opt" in
        t) TARGET="$OPTARG" ;;
        p) PORTS="$OPTARG" ;;
        j) JOBS="$OPTARG" ;;
        w) TIMEOUT="$OPTARG" ;;
        o) CSV="$OPTARG" ;;
        n) SKIP_PORTS=1 ;;
        N) USE_NMAP=1 ;;
        h) usage; exit 0 ;;
        :) die "option -$OPTARG needs a value (see -h)" ;;
        *) die "unknown option -$OPTARG (see -h)" ;;
    esac
done
[[ -z "$TARGET" && $# -ge $OPTIND ]] && TARGET="${!OPTIND}"
[[ -n "$TARGET" ]] || { usage >&2; exit 2; }

# ---- input validation --------------------------------------------------------
# is_int_between VALUE MIN MAX -> success if VALUE is an integer in [MIN, MAX]
is_int_between() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= $2 && 10#$1 <= $3 )); }
is_int_between "$JOBS" 1 256 || die "-j must be 1-256"
is_int_between "$TIMEOUT" 1 30 || die "-w must be 1-30 seconds"
[[ "$PORTS" =~ ^[0-9]+(,[0-9]+)*$ ]] || die "-p must look like 22,80,443"
IFS=',' read -r -a PORT_LIST <<< "$PORTS"
for p in "${PORT_LIST[@]}"; do
    (( p >= 1 && p <= 65535 )) || die "port $p out of range 1-65535"
done

# Convert dotted quad <-> 32-bit integer.
ip_to_int() {
    local a b c d
    IFS=. read -r a b c d <<< "$1"
    echo $(( (a << 24) | (b << 16) | (c << 8) | d ))
}
int_to_ip() {
    local n=$1
    echo "$(( (n >> 24) & 255 )).$(( (n >> 16) & 255 )).$(( (n >> 8) & 255 )).$(( n & 255 ))"
}
valid_ip() {
    local ip=$1 o
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r -a o <<< "$ip"
    for x in "${o[@]}"; do (( 10#$x <= 255 )) || return 1; done
}

# Split CIDR into network address and prefix length.
if [[ "$TARGET" == */* ]]; then
    BASE="${TARGET%/*}"; PREFIX="${TARGET#*/}"
else
    BASE="$TARGET"; PREFIX=32
fi
valid_ip "$BASE" || die "invalid IPv4 address: $BASE"
is_int_between "$PREFIX" 16 32 || die "prefix must be /16 - /32"

BASE_INT=$(ip_to_int "$BASE")
MASK=$(( (0xFFFFFFFF << (32 - PREFIX)) & 0xFFFFFFFF ))
NET=$(( BASE_INT & MASK ))
BCAST=$(( NET | (~MASK & 0xFFFFFFFF) ))
if (( PREFIX >= 31 )); then
    FIRST=$NET; LAST=$BCAST          # /31 and /32 have no network/broadcast
else
    FIRST=$(( NET + 1 )); LAST=$(( BCAST - 1 ))
fi
COUNT=$(( LAST - FIRST + 1 ))
(( COUNT <= MAX_HOSTS )) || die "range too large ($COUNT hosts)"

# ---- probe helpers -------------------------------------------------------------
HAVE_PING=0; command -v ping >/dev/null 2>&1 && HAVE_PING=1

# tcp_state IP PORT -> prints open|closed|filtered
# Uses bash's /dev/tcp. "closed" (RST) still proves the host is alive.
tcp_state() {
    local out rc
    out=$(timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/$1/$2" 2>&1); rc=$?
    if (( rc == 0 )); then echo open
    elif (( rc == 124 )); then echo filtered
    elif [[ "$out" == *"refused"* ]]; then echo closed
    else echo filtered
    fi
}

# is_alive IP -> 0 if the host answers ICMP echo or any TCP probe.
is_alive() {
    local ip=$1 p
    if (( HAVE_PING )); then
        ping -c 1 -W "$TIMEOUT" "$ip" >/dev/null 2>&1 && return 0
    fi
    # Fallback / second chance: a TCP answer (open or refused) means "up".
    for p in 80 443 22 445; do
        [[ "$(tcp_state "$ip" "$p")" != filtered ]] && return 0
    done
    return 1
}

resolve_name() {
    local name=""
    if command -v getent >/dev/null 2>&1; then
        name=$(getent hosts "$1" 2>/dev/null | awk '{print $2; exit}')
    fi
    if [[ -z "$name" ]] && command -v host >/dev/null 2>&1; then
        name=$(host -W 1 "$1" 2>/dev/null | awk '/pointer/ {sub(/\.$/,"",$NF); print $NF; exit}')
    fi
    echo "${name:--}"
}

# probe_host IP -> writes "ip|hostname|open_ports" into the results dir.
probe_host() {
    local ip=$1 open=() p
    (( ASSUME_ALIVE )) || is_alive "$ip" || return 0
    if (( ! SKIP_PORTS )); then
        for p in "${PORT_LIST[@]}"; do
            [[ "$(tcp_state "$ip" "$p")" == open ]] && open+=("$p")
        done
    fi
    local joined; joined=$(IFS=';'; echo "${open[*]:-}")
    printf '%s|%s|%s\n' "$ip" "$(resolve_name "$ip")" "${joined:--}" > "$TMP/$ip"
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
trap 'echo; echo "Interrupted." >&2; exit 130' INT

echo "Scanning $(int_to_ip "$FIRST") - $(int_to_ip "$LAST") ($COUNT hosts, $JOBS parallel, timeout ${TIMEOUT}s)"
(( HAVE_PING )) || echo "Note: 'ping' not found - using TCP probes for liveness."
START=$(date +%s)

if (( USE_NMAP )) && command -v nmap >/dev/null 2>&1; then
    # nmap does discovery; we still do our own hostname + port step.
    mapfile -t LIVE < <(nmap -sn -n "$TARGET" -oG - 2>/dev/null | awk '/Status: Up/ {print $2}')
    ASSUME_ALIVE=1
    for ip in "${LIVE[@]}"; do
        probe_host "$ip" &
        while (( $(jobs -rp | wc -l) >= JOBS )); do wait -n; done
    done
else
    (( USE_NMAP )) && echo "Note: nmap not installed - using built-in sweep."
    for (( i = FIRST; i <= LAST; i++ )); do
        probe_host "$(int_to_ip "$i")" &
        # Simple job semaphore: never run more than $JOBS probes at once.
        while (( $(jobs -rp | wc -l) >= JOBS )); do wait -n; done
    done
fi
wait

# ---- output --------------------------------------------------------------------
mapfile -t ROWS < <(cat "$TMP"/* 2>/dev/null | sort -t . -k1,1n -k2,2n -k3,3n -k4,4n)
printf '\n%-16s %-32s %s\n' "IP" "HOSTNAME" "OPEN PORTS"
printf '%-16s %-32s %s\n' "----------------" "--------------------------------" "----------"
for r in "${ROWS[@]}"; do
    IFS='|' read -r ip name ports <<< "$r"
    printf '%-16s %-32s %s\n' "$ip" "$name" "${ports//;/,}"
done
echo
echo "${#ROWS[@]} live host(s) found in $(( $(date +%s) - START ))s."

if [[ -n "$CSV" ]]; then
    {
        echo "ip,hostname,open_ports"
        for r in "${ROWS[@]}"; do
            IFS='|' read -r ip name ports <<< "$r"
            echo "$ip,$name,$ports"
        done
    } > "$CSV" || die "cannot write $CSV"
    echo "CSV written to $CSV"
fi
