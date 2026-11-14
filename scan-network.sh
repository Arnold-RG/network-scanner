#!/usr/bin/env bash
# =============================================================================
# scan-network.sh - Discover live hosts on a local IPv4 subnet (v2)
# -----------------------------------------------------------------------------
# Discovery : ICMP echo, TCP connect (open OR refused = alive) and the ARP /
#             neighbour table (any host that answered ARP is on the segment).
# Enrichment: MAC address + OUI vendor, hostname via DNS, NetBIOS (nmblookup)
#             and mDNS (avahi-resolve) when those tools exist, top-port check.
# Reports   : console table + CSV / JSON / self-contained HTML (-o, repeatable).
# Requires  : bash 4.3+, coreutils `timeout`. Optional: ping, ip, getent/host,
#             nmblookup, avahi-resolve, nmap (-N). No root needed.
# Author    : Arnold Rurangwa - MIT License
# Legal     : Only scan networks you own or are explicitly authorised to test.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
. "$HERE/lib/common.sh"
# shellcheck source=lib/net.sh
. "$HERE/lib/net.sh"
TOOL_NAME="scan-network.sh"

# ---- defaults (overridable by -c config, then by options) --------------------
PORTS="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
JOBS=64; TIMEOUT=1; METHODS="icmp,tcp,arp"; TCP_DISCOVERY_PORTS="80,443,22,445,139,3389"
OUI_FILE="data/oui-subset.csv"; RESOLVE_NETBIOS=1; RESOLVE_MDNS=1
TARGET=""; SKIP_PORTS=0; USE_NMAP=0; NEIGH_FILE=""; OUTPUTS=()
MAX_HOSTS=65536

usage() {
    cat <<USAGE
Usage: $(basename "$0") -t <CIDR|IP> [options]

Discover live hosts (ICMP + TCP + ARP), show MAC, vendor, hostname and open ports.

  -t, --target CIDR      Network (192.168.1.0/24, /16 to /32) or one IP
  -p, --ports LIST       Ports to check on live hosts (default: top 20)
  -n, --no-ports         Discovery only, skip the port check
  -m, --methods LIST     Discovery methods: icmp,tcp,arp (default: $METHODS)
  -j, --jobs N           Parallel probes, 1-256 (default: $JOBS)
  -w, --timeout SEC      Per-probe timeout, 1-30 s (default: $TIMEOUT)
  -o, --output FILE      Write a report; format from extension .csv .json .html
                         (repeat -o for several formats)
  -c, --config FILE      KEY=VALUE config file (see config/network-scanner.conf)
  -N, --nmap             Use nmap -sn for discovery if installed
      --neigh-file FILE  Read the ARP/neighbour table from a saved dump
  -l, --log FILE         Append log lines to FILE
  -v, --verbose          Debug logging      -q, --quiet   Warnings only
  -h, --help             Show this help

Examples:
  $(basename "$0") -t 192.168.1.0/24
  $(basename "$0") -t 192.168.1.0/24 -o lan.html -o lan.json
  $(basename "$0") -t 10.0.0.0/28 -p 22,80,443 -j 32 -w 2 -l scan.log

Only scan networks you own or are authorised to test.
USAGE
}

# ---- options -----------------------------------------------------------------
CFG=$(find_config_arg "$@")
if [[ -n "$CFG" ]]; then load_config "$CFG"; fi
while (( $# )); do
    case "$1" in
        -t|--target) TARGET="${2:-}"; shift ;;
        -p|--ports) PORTS="${2:-}"; shift ;;
        -n|--no-ports) SKIP_PORTS=1 ;;
        -m|--methods) METHODS="${2:-}"; shift ;;
        -j|--jobs) JOBS="${2:-}"; shift ;;
        -w|--timeout) TIMEOUT="${2:-}"; shift ;;
        -o|--output) OUTPUTS+=("${2:-}"); shift ;;
        -c|--config) shift ;;
        -N|--nmap) USE_NMAP=1 ;;
        --neigh-file) NEIGH_FILE="${2:-}"; shift ;;
        -l|--log) LOG_FILE="${2:-}"; shift ;;
        -v|--verbose) LOG_LEVEL=DEBUG ;;
        -q|--quiet) QUIET=1 ;;
        -h|--help) usage; exit 0 ;;
        -*) die "unknown option $1 (see -h)" ;;
        *) TARGET="$1" ;;
    esac
    shift
done
[[ -n "$TARGET" ]] || { usage >&2; exit 2; }
[[ "$OUI_FILE" == /* ]] || OUI_FILE="$HERE/$OUI_FILE"

# ---- validation ----------------------------------------------------------------
is_int_between "$JOBS" 1 256 || die "--jobs must be 1-256"
is_int_between "$TIMEOUT" 1 30 || die "--timeout must be 1-30 seconds"
[[ "$PORTS" =~ ^[0-9]+(,[0-9]+)*$ ]] || die "--ports must look like 22,80,443"
IFS=',' read -r -a PORT_LIST <<< "$PORTS"
for p in "${PORT_LIST[@]}"; do (( p >= 1 && p <= 65535 )) || die "port $p out of range 1-65535"; done
IFS=',' read -r -a DISC_PORTS <<< "$TCP_DISCOVERY_PORTS"
[[ "$METHODS" =~ ^(icmp|tcp|arp)(,(icmp|tcp|arp))*$ ]] || die "--methods must be a list of icmp,tcp,arp"
has_method() { [[ ",$METHODS," == *",$1,"* ]]; }
[[ -z "$NEIGH_FILE" || -r "$NEIGH_FILE" ]] || die "cannot read $NEIGH_FILE"

if [[ "$TARGET" == */* ]]; then BASE="${TARGET%/*}"; PREFIX="${TARGET#*/}"; else BASE="$TARGET"; PREFIX=32; fi
valid_ipv4 "$BASE" || die "invalid IPv4 address: $BASE"
is_int_between "$PREFIX" 16 32 || die "prefix must be /16 - /32"
BASE_INT=$(ip_to_int "$BASE")
MASK=$(( (0xFFFFFFFF << (32 - PREFIX)) & 0xFFFFFFFF ))
NET=$(( BASE_INT & MASK )); BCAST=$(( NET | (~MASK & 0xFFFFFFFF) ))
if (( PREFIX >= 31 )); then FIRST=$NET; LAST=$BCAST; else FIRST=$(( NET + 1 )); LAST=$(( BCAST - 1 )); fi
COUNT=$(( LAST - FIRST + 1 ))
(( COUNT <= MAX_HOSTS )) || die "range too large ($COUNT hosts)"
in_range() { local n; n=$(ip_to_int "$1"); (( n >= FIRST && n <= LAST )); }

# ---- probes ----------------------------------------------------------------------
HAVE_PING=0; need_cmd ping && HAVE_PING=1

# tcp_state IP PORT -> open | closed (RST, host is up) | filtered
tcp_state() {
    local out rc
    out=$(timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/$1/$2" 2>&1); rc=$?
    if (( rc == 0 )); then echo open
    elif (( rc != 124 )) && [[ "$out" == *refused* ]]; then echo closed
    else echo filtered
    fi
}

# discover IP -> prints the method that proved the host alive, or nothing
discover() {
    local ip=$1 p
    if has_method icmp && (( HAVE_PING )); then
        ping -c 1 -W "$TIMEOUT" "$ip" >/dev/null 2>&1 && { echo icmp; return; }
    fi
    if has_method tcp; then
        for p in "${DISC_PORTS[@]}"; do
            [[ "$(tcp_state "$ip" "$p")" != filtered ]] && { echo "tcp/$p"; return; }
        done
    fi
}

# hostname IP -> "name<TAB>source" (dns | netbios | mdns | -)
lookup_name() {
    local ip=$1 name=""
    if need_cmd getent; then name=$(getent hosts "$ip" 2>/dev/null | awk '{print $2; exit}'); fi
    if [[ -z "$name" ]] && need_cmd host; then
        name=$(host -W 1 "$ip" 2>/dev/null | awk '/pointer/ {sub(/\.$/, "", $NF); print $NF; exit}')
    fi
    [[ -n "$name" ]] && { printf '%s\tdns' "$name"; return; }
    if (( RESOLVE_NETBIOS )) && need_cmd nmblookup; then
        name=$(timeout 3 nmblookup -A "$ip" 2>/dev/null | awk '/<00>/ && !/<GROUP>/ {print $1; exit}')
        [[ -n "$name" ]] && { printf '%s\tnetbios' "$name"; return; }
    fi
    if (( RESOLVE_MDNS )) && need_cmd avahi-resolve; then
        name=$(timeout 3 avahi-resolve -a "$ip" 2>/dev/null | awk '{print $2; exit}')
        [[ -n "$name" ]] && { printf '%s\tmdns' "$name"; return; }
    fi
    printf -- '-\t-'
}

# probe_host IP [KNOWN_METHOD] -> writes one TSV row into $TMP
probe_host() {
    local ip=$1 method="${2:-}" open=() p name src
    [[ -n "$method" ]] || method=$(discover "$ip")
    [[ -n "$method" ]] || return 0
    if (( ! SKIP_PORTS )); then
        for p in "${PORT_LIST[@]}"; do [[ "$(tcp_state "$ip" "$p")" == open ]] && open+=("$p"); done
    fi
    IFS=$'\t' read -r name src <<< "$(lookup_name "$ip")"
    local joined; joined=$(IFS=';'; echo "${open[*]:-}")
    printf '%s\t%s\t%s\t%s\n' "$ip" "$method" "$name|$src" "${joined:--}" > "$TMP/hosts/$ip"
    log DEBUG "$ip alive via $method"
}

TMP=$(mktemp -d)
mkdir -p "$TMP/hosts"
trap 'rm -rf "$TMP"' EXIT
trap 'echo >&2; log WARN "interrupted"; exit 130' INT

log INFO "scanning $(int_to_ip "$FIRST") - $(int_to_ip "$LAST") ($COUNT hosts, methods $METHODS, $JOBS parallel, timeout ${TIMEOUT}s)"
(( HAVE_PING )) || ! has_method icmp || log WARN "'ping' not found - ICMP discovery skipped"
START=$(date +%s)

if (( USE_NMAP )) && need_cmd nmap; then
    mapfile -t LIVE < <(nmap -sn -n "$TARGET" -oG - 2>/dev/null | awk '/Status: Up/ {print $2}')
    for ip in "${LIVE[@]}"; do probe_host "$ip" nmap & throttle "$JOBS"; done
else
    (( USE_NMAP )) && log WARN "nmap not installed - using the built-in sweep"
    for (( i = FIRST; i <= LAST; i++ )); do probe_host "$(int_to_ip "$i")" & throttle "$JOBS"; done
fi
wait

# ---- ARP / neighbour table: MACs, plus hosts that only answered ARP --------------
declare -A MAC_OF=()
if has_method arp || [[ -n "$NEIGH_FILE" ]]; then
    while read -r nip nmac _; do
        if [[ -z "$nip" ]] || ! in_range "$nip"; then continue; fi
        MAC_OF[$nip]=$(normalise_mac "$nmac")
        if [[ ! -e "$TMP/hosts/$nip" ]]; then probe_host "$nip" arp & throttle "$JOBS"; fi
    done < <(read_neighbors "$NEIGH_FILE")
    wait
fi

# ---- assemble rows ------------------------------------------------------------------
ROWS="$TMP/rows.tsv"
{
    printf 'ip\tmac\tvendor\thostname\tname_source\tdiscovered_by\topen_ports\n'
    for f in "$TMP"/hosts/*; do
        [[ -f "$f" ]] || continue
        IFS=$'\t' read -r ip method namesrc ports < "$f"
        mac="${MAC_OF[$ip]:--}"
        vendor="-"; [[ "$mac" != "-" ]] && vendor=$(vendor_for "$mac")
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$ip" "$mac" "$vendor" "${namesrc%|*}" "${namesrc#*|}" "$method" "$ports"
    done | sort -t . -k1,1n -k2,2n -k3,3n -k4,4n
} > "$ROWS.tmp"
mv "$ROWS.tmp" "$ROWS"
LIVE_COUNT=$(( $(wc -l < "$ROWS") - 1 ))
ELAPSED=$(( $(date +%s) - START ))

printf '\n%-15s %-17s %-22s %-26s %-8s %s\n' IP MAC VENDOR HOSTNAME VIA "OPEN PORTS"
printf '%-15s %-17s %-22s %-26s %-8s %s\n' --------------- ----------------- ---------------------- -------------------------- -------- ----------
tail -n +2 "$ROWS" | while IFS=$'\t' read -r ip mac vendor name _ via ports; do
    printf '%-15s %-17s %-22.22s %-26.26s %-8s %s\n' "$ip" "$mac" "$vendor" "$name" "$via" "${ports//;/,}"
done
echo
echo "$LIVE_COUNT live host(s) out of $COUNT scanned in ${ELAPSED}s."

for out in "${OUTPUTS[@]}"; do
    write_report auto "$out" "Network scan: $TARGET" \
        "Live hosts=$LIVE_COUNT|Addresses scanned=$COUNT|Duration=${ELAPSED}s|Methods=$METHODS" < "$ROWS"
done
