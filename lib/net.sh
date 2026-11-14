# shellcheck shell=bash
# =============================================================================
# lib/net.sh - network helpers shared by scan-network.sh, arp-spoof-detector.sh
# and dns-analyzer.sh. Source lib/common.sh first.
# Author: Arnold Rurangwa - MIT License
# =============================================================================

# normalise_mac MAC -> upper-case, colon separated (aa-bb-.. / aabb.cc.. accepted)
normalise_mac() {
    local m="${1^^}"
    m="${m//-/:}"
    if [[ "$m" =~ ^[0-9A-F]{4}\.[0-9A-F]{4}\.[0-9A-F]{4}$ ]]; then   # Cisco dotted form
        m="${m//./}"; m="${m:0:2}:${m:2:2}:${m:4:2}:${m:6:2}:${m:8:2}:${m:10:2}"
    fi
    printf '%s' "$m"
}

# is_local_mac MAC -> success for locally administered (often randomised) MACs
is_local_mac() {
    local second="${1:1:1}"
    [[ "${second^^}" =~ ^[26AE]$ ]]
}

# vendor_for MAC -> vendor name from $OUI_FILE ("-" if unknown)
vendor_for() {
    local mac prefix v
    mac=$(normalise_mac "$1")
    [[ "$mac" =~ ^([0-9A-F]{2}:){5}[0-9A-F]{2}$ ]] || { echo "-"; return; }
    if is_local_mac "$mac"; then echo "random/local MAC"; return; fi
    prefix="${mac:0:8}"
    if [[ -r "${OUI_FILE:-}" ]]; then
        v=$(grep -m1 -i "^$prefix," "$OUI_FILE" 2>/dev/null | cut -d, -f2- | tr -d '"')
    fi
    echo "${v:--}"
}

# read_neighbors [FILE] -> "ip mac state" lines from the kernel neighbour table.
# FILE (optional) is a saved `ip neigh`, /proc/net/arp or `arp -an` dump, which
# lets you analyse another machine's table offline (and makes tests possible).
read_neighbors() {
    local src="${1:-}" text
    if [[ -n "$src" ]]; then
        text=$(cat "$src") || return 1
    elif need_cmd ip; then
        text=$(ip -4 neigh show 2>/dev/null)
    elif [[ -r /proc/net/arp ]]; then
        text=$(cat /proc/net/arp)
    elif need_cmd arp; then
        text=$(arp -an 2>/dev/null)
    fi
    awk '
        # ip neigh: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        $2 == "dev" && $0 ~ / lladdr / { for (i = 1; i <= NF; i++) if ($i == "lladdr") print $1, toupper($(i+1)), $NF; next }
        # /proc/net/arp: IP HWtype Flags HWaddress Mask Device (flags 0x0 = incomplete)
        $1 ~ /^[0-9.]+$/ && $3 ~ /^0x/ { if ($3 != "0x0" && $4 != "00:00:00:00:00:00") print $1, toupper($4), "ARP"; next }
        # arp -an: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
        $3 == "at" && $4 ~ /:/ { gsub(/[()]/, "", $2); print $2, toupper($4), "ARP"; next }
    ' <<< "$text" | grep -Ev ' (FAILED|INCOMPLETE)$' || true
}

# default_gateway -> IPv4 of the default route (empty if none)
default_gateway() {
    if need_cmd ip; then
        ip -4 route show default 2>/dev/null | awk '/^default/ {print $3; exit}'
    elif need_cmd netstat; then
        netstat -rn 2>/dev/null | awk '$1 == "0.0.0.0" || $1 == "default" {print $2; exit}'
    fi
}

# is_private_or_bogon IP -> success for RFC1918, loopback, link-local, CGNAT,
# 0.0.0.0/8, documentation and multicast/reserved ranges
is_private_or_bogon() {
    local a b
    IFS=. read -r a b _ _ <<< "$1"
    (( a == 0 || a == 10 || a == 127 || a >= 224 )) && return 0
    (( a == 169 && b == 254 )) && return 0
    (( a == 172 && b >= 16 && b <= 31 )) && return 0
    (( a == 192 && b == 168 )) && return 0
    (( a == 100 && b >= 64 && b <= 127 )) && return 0
    [[ "$1" == 192.0.2.* || "$1" == 198.51.100.* || "$1" == 203.0.113.* ]] && return 0
    (( a == 198 && (b == 18 || b == 19) )) && return 0
    return 1
}
