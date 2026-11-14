#!/usr/bin/env bash
# =============================================================================
# arp-spoof-detector.sh - Detect ARP spoofing / man-in-the-middle signs
# -----------------------------------------------------------------------------
# Reads the kernel ARP (neighbour) table and flags:
#   HIGH   gateway MAC changed since the baseline (classic ARP-poisoning sign)
#   HIGH   the gateway's MAC also answers for other IPs (someone claims it)
#   MEDIUM one MAC address answering for several IPs
#   MEDIUM a known host's MAC changed since the baseline
#   INFO   hosts that are not in the baseline yet / gateway missing from table
# Run once, or with --watch to re-check every N seconds and alert on new
# findings (console + log file + syslog via `logger` when available).
# Exit code: 0 = clean, 1 = at least one HIGH finding, 2 = usage error.
# Read-only: it never sends ARP packets or changes the table.
# Author: Arnold Rurangwa - MIT License
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
. "$HERE/lib/common.sh"
# shellcheck source=lib/net.sh
. "$HERE/lib/net.sh"
TOOL_NAME="arp-spoof-detector.sh"

ARP_BASELINE="arp-baseline.txt"; ARP_INTERVAL=30
INIT=0; WATCH=0; COUNT=0; NEIGH_FILE=""; GATEWAY=""; OUTPUTS=()
OUI_FILE="data/oui-subset.csv"

usage() {
    cat <<USAGE
Usage: $(basename "$0") [options]

Detect ARP spoofing: duplicate MACs, gateway MAC changes, changed host MACs.

  -i, --init             Save the current ARP table as the trusted baseline
  -b, --baseline FILE    Baseline file (default: $ARP_BASELINE)
  -g, --gateway IP       Gateway to protect (default: the default route)
  -W, --watch SEC        Keep checking every SEC seconds (Ctrl+C to stop)
  -n, --count N          With --watch, stop after N checks
  -o, --output FILE      Report of the last check (.csv .json .html)
  -c, --config FILE      KEY=VALUE config file
      --neigh-file FILE  Analyse a saved 'ip neigh' / 'arp -an' dump
  -l, --log FILE         Append log lines to FILE
  -v, --verbose          Debug logging      -q, --quiet   Warnings only
  -h, --help             Show this help

Examples:
  $(basename "$0") --init                 # on a network you trust
  $(basename "$0")                        # one check against the baseline
  $(basename "$0") --watch 15 -l arp.log  # continuous monitoring
USAGE
}

CFG=$(find_config_arg "$@")
if [[ -n "$CFG" ]]; then load_config "$CFG"; fi
while (( $# )); do
    case "$1" in
        -i|--init) INIT=1 ;;
        -b|--baseline) ARP_BASELINE="${2:-}"; shift ;;
        -g|--gateway) GATEWAY="${2:-}"; shift ;;
        -W|--watch) WATCH=1; ARP_INTERVAL="${2:-}"; shift ;;
        -n|--count) COUNT="${2:-}"; shift ;;
        -o|--output) OUTPUTS+=("${2:-}"); shift ;;
        -c|--config) shift ;;
        --neigh-file) NEIGH_FILE="${2:-}"; shift ;;
        -l|--log) LOG_FILE="${2:-}"; shift ;;
        -v|--verbose) LOG_LEVEL=DEBUG ;;
        -q|--quiet) QUIET=1 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option $1 (see -h)" ;;
    esac
    shift
done
is_int_between "$ARP_INTERVAL" 1 86400 || die "--watch needs 1-86400 seconds"
is_int_between "$COUNT" 0 1000000 || die "--count must be a number"
[[ -z "$GATEWAY" ]] || valid_ipv4 "$GATEWAY" || die "invalid gateway IP: $GATEWAY"
[[ -z "$NEIGH_FILE" || -r "$NEIGH_FILE" ]] || die "cannot read $NEIGH_FILE"
[[ "$OUI_FILE" == /* ]] || OUI_FILE="$HERE/$OUI_FILE"

# ---- baseline -------------------------------------------------------------------
if (( INIT )); then
    [[ -n "$GATEWAY" ]] || GATEWAY=$(default_gateway)
    {
        echo "# arp-spoof-detector baseline - $(date '+%Y-%m-%d %H:%M:%S %z')"
        echo "# gateway ${GATEWAY:--}"
        read_neighbors "$NEIGH_FILE" | awk '{print $1, $2}' | sort -u
    } > "$ARP_BASELINE" || die "cannot write $ARP_BASELINE"
    log INFO "baseline saved to $ARP_BASELINE ($(grep -vc '^#' "$ARP_BASELINE") entries, gateway ${GATEWAY:-unknown})"
    exit 0
fi

declare -A BASE=()
if [[ -r "$ARP_BASELINE" ]]; then
    while read -r bip bmac; do
        [[ "$bip" == "#" || -z "$bip" ]] && continue
        BASE[$bip]="$bmac"
    done < "$ARP_BASELINE"
    if [[ -z "$GATEWAY" ]]; then GATEWAY=$(awk '/^# gateway/ {print $3}' "$ARP_BASELINE"); fi
    [[ "$GATEWAY" == "-" ]] && GATEWAY=""
else
    log WARN "no baseline at $ARP_BASELINE - only duplicate-MAC checks run (create one with --init)"
fi
# Gateway precedence: --gateway > baseline > this machine's default route.
if [[ -z "$GATEWAY" && -z "$NEIGH_FILE" ]]; then GATEWAY=$(default_gateway); fi

# ---- one check: prints TSV findings (severity check ip mac detail) ---------------
check_once() {
    local -A ips_of=() mac_of=()
    local ip mac
    while read -r ip mac _; do
        [[ -n "$ip" ]] || continue
        mac_of[$ip]="$mac"
        ips_of[$mac]+="$ip "
    done < <(read_neighbors "$NEIGH_FILE")

    local gwmac="${mac_of[$GATEWAY]:-}"
    for mac in "${!ips_of[@]}"; do
        local list; list=$(echo "${ips_of[$mac]}" | xargs -n1 | sort -t . -k4,4n | xargs)
        if (( $(wc -w <<< "$list") > 1 )); then
            if [[ -n "$gwmac" && "$mac" == "$gwmac" ]]; then
                printf 'HIGH\tGATEWAY_MAC_CLAIMED\t%s\t%s\tgateway MAC also used by: %s (%s)\n' "$GATEWAY" "$mac" "$list" "$(vendor_for "$mac")"
            else
                printf 'MEDIUM\tDUPLICATE_MAC\t%s\t%s\tone MAC answers for several IPs (%s)\n' "${list// /,}" "$mac" "$(vendor_for "$mac")"
            fi
        fi
    done
    if [[ -n "$GATEWAY" ]]; then
        if [[ -z "$gwmac" ]]; then
            printf 'INFO\tGATEWAY_NOT_IN_TABLE\t%s\t-\tgateway has no ARP entry yet (no recent traffic)\n' "$GATEWAY"
        elif [[ -n "${BASE[$GATEWAY]:-}" && "${BASE[$GATEWAY]}" != "$gwmac" ]]; then
            printf 'HIGH\tGATEWAY_MAC_CHANGED\t%s\t%s\twas %s (%s), now %s (%s)\n' "$GATEWAY" "$gwmac" \
                "${BASE[$GATEWAY]}" "$(vendor_for "${BASE[$GATEWAY]}")" "$gwmac" "$(vendor_for "$gwmac")"
        fi
    fi
    for ip in "${!mac_of[@]}"; do
        [[ "$ip" == "$GATEWAY" ]] && continue
        if [[ -z "${BASE[$ip]:-}" ]]; then
            (( ${#BASE[@]} )) && printf 'INFO\tNEW_HOST\t%s\t%s\tnot in baseline (%s)\n' "$ip" "${mac_of[$ip]}" "$(vendor_for "${mac_of[$ip]}")"
        elif [[ "${BASE[$ip]}" != "${mac_of[$ip]}" ]]; then
            printf 'MEDIUM\tMAC_CHANGED\t%s\t%s\twas %s\n' "$ip" "${mac_of[$ip]}" "${BASE[$ip]}"
        fi
    done
    return 0
}

alert() {   # alert SEVERITY MESSAGE
    local lvl=WARN; [[ "$1" == INFO ]] && lvl=INFO
    log "$lvl" "[$1] $2"
    if [[ "$1" == HIGH ]] && need_cmd logger; then logger -t arp-spoof-detector -p auth.warning -- "$2" 2>/dev/null || true; fi
}

declare -A SEEN=()
run=0; last=""; high=0
trap 'echo >&2; log INFO "stopped after $run check(s)"; exit $(( high ? 1 : 0 ))' INT TERM
log INFO "checking ARP table (gateway ${GATEWAY:-unknown}, baseline ${#BASE[@]} entries)"
while :; do
    run=$((run + 1))
    last=$(check_once | awk -F'\t' '{r = ($1 == "HIGH") ? 1 : ($1 == "MEDIUM") ? 2 : 3; print r "\t" $0}' | sort -k1,1n -k2 | cut -f2-)
    found=0
    while IFS=$'\t' read -r sev chk ip mac detail; do
        [[ -n "$sev" ]] || continue
        found=$((found + 1)); [[ "$sev" == HIGH ]] && high=1
        key="$chk|$ip|$mac"
        [[ -n "${SEEN[$key]:-}" ]] && continue
        SEEN[$key]=1
        alert "$sev" "$chk $ip $mac - $detail"
    done <<< "$last"
    (( found )) || log INFO "check $run: no ARP anomalies"
    (( WATCH )) || break
    (( COUNT && run >= COUNT )) && break
    sleep "$ARP_INTERVAL"
done

for out in "${OUTPUTS[@]}"; do
    nh=$(grep -c '^HIGH' <<< "$last"); nm=$(grep -c '^MEDIUM' <<< "$last")
    { printf 'severity\tcheck\tip\tmac\tdetail\n'; [[ -n "$last" ]] && printf '%s\n' "$last"; } |
        write_report auto "$out" "ARP spoofing check" "High=$nh|Medium=$nm|Gateway=${GATEWAY:--}|Baseline entries=${#BASE[@]}"
done
exit $(( high ? 1 : 0 ))
