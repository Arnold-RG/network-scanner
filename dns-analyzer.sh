#!/usr/bin/env bash
# =============================================================================
# dns-analyzer.sh - Spot DNS hijacking, poisoning and risky resolver settings
# -----------------------------------------------------------------------------
# For every domain in the list it compares the answer of the system resolver
# with several independent public resolvers and flags:
#   HIGH   PRIVATE_ANSWER      a public domain resolves to a private/reserved IP
#   MEDIUM ANSWER_MISMATCH     system answer shares no IP with any public resolver
#   MEDIUM NXDOMAIN_REDIRECT   a random, non-existent name resolves (ad/hijack)
#   MEDIUM UNKNOWN_RESOLVER    a configured nameserver is a public IP that is not
#                              a well-known resolver (DNS-changer malware sign)
#   INFO   NO_DNSSEC           system resolver does not validate DNSSEC (dig)
#   LOW    QUERY_FAILED        a resolver did not answer
# CDNs legitimately return different IPs per location, so ANSWER_MISMATCH is
# a heuristic: confirm before acting. Read-only: it only sends DNS queries.
# Requires: bash 4.3+; dig (best), host or nslookup for per-server queries;
# without them only the system resolver is checked (getent).
# Author: Arnold Rurangwa - MIT License
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
. "$HERE/lib/common.sh"
# shellcheck source=lib/net.sh
. "$HERE/lib/net.sh"
TOOL_NAME="dns-analyzer.sh"

DNS_RESOLVERS="1.1.1.1,8.8.8.8,9.9.9.9"; DNS_DOMAINS_FILE="data/dns-check-domains.txt"
DOMAINS=""; ANSWERS_FILE=""; RESOLV_FILE="/etc/resolv.conf"; NX_TEST=1; OUTPUTS=()
KNOWN_RESOLVERS="1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 149.112.112.112 208.67.222.222 208.67.220.220 94.140.14.14 94.140.15.15 76.76.2.0 76.76.10.0"

usage() {
    cat <<USAGE
Usage: $(basename "$0") [options]

Compare DNS answers across resolvers to detect hijacking / poisoning.

  -d, --domains LIST     Comma-separated domains (default: $DNS_DOMAINS_FILE)
  -f, --domains-file F   File with one domain per line
  -r, --resolvers LIST   Public resolvers to compare with (default: $DNS_RESOLVERS)
      --no-nx-test       Skip the NXDOMAIN-redirection test
      --resolv-file F    Resolver config to audit (default: /etc/resolv.conf)
      --answers-file F   Analyse saved answers (domain<TAB>resolver<TAB>ips|NXDOMAIN)
  -o, --output FILE      Report: .csv .json .html (repeatable)
  -c, --config FILE      KEY=VALUE config file
  -l, --log FILE         Append log lines to FILE
  -v, --verbose          Debug logging      -q, --quiet   Warnings only
  -h, --help             Show this help

Examples:
  $(basename "$0")
  $(basename "$0") -d mybank.example,github.com -o dns.html
USAGE
}

CFG=$(find_config_arg "$@")
if [[ -n "$CFG" ]]; then load_config "$CFG"; fi
while (( $# )); do
    case "$1" in
        -d|--domains) DOMAINS="${2:-}"; shift ;;
        -f|--domains-file) DNS_DOMAINS_FILE="${2:-}"; shift ;;
        -r|--resolvers) DNS_RESOLVERS="${2:-}"; shift ;;
        --no-nx-test) NX_TEST=0 ;;
        --resolv-file) RESOLV_FILE="${2:-}"; shift ;;
        --answers-file) ANSWERS_FILE="${2:-}"; shift ;;
        -o|--output) OUTPUTS+=("${2:-}"); shift ;;
        -c|--config) shift ;;
        -l|--log) LOG_FILE="${2:-}"; shift ;;
        -v|--verbose) LOG_LEVEL=DEBUG ;;
        -q|--quiet) QUIET=1 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option $1 (see -h)" ;;
    esac
    shift
done
[[ "$DNS_DOMAINS_FILE" == /* || -r "$DNS_DOMAINS_FILE" ]] || DNS_DOMAINS_FILE="$HERE/$DNS_DOMAINS_FILE"
IFS=',' read -r -a RESOLVERS <<< "$DNS_RESOLVERS"
for r in "${RESOLVERS[@]:-}"; do valid_ipv4 "$r" || die "invalid resolver IP: $r"; done
if [[ -n "$DOMAINS" ]]; then
    IFS=',' read -r -a DOMAIN_LIST <<< "$DOMAINS"
elif [[ -z "$ANSWERS_FILE" ]]; then
    [[ -r "$DNS_DOMAINS_FILE" ]] || die "cannot read $DNS_DOMAINS_FILE"
    mapfile -t DOMAIN_LIST < <(grep -Ev '^[[:space:]]*(#|$)' "$DNS_DOMAINS_FILE" | tr -d '\r ')
fi
for d in "${DOMAIN_LIST[@]:-}"; do
    [[ -z "$d" || "$d" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]] || die "invalid domain: $d"
done

# ---- resolution ------------------------------------------------------------------
QUERY_TOOL=""
for t in dig host nslookup; do need_cmd "$t" && { QUERY_TOOL=$t; break; }; done
if [[ -z "$QUERY_TOOL" && -z "$ANSWERS_FILE" ]]; then
    log WARN "dig/host/nslookup not found - only the system resolver can be checked (install dnsutils/bind-utils)"
    RESOLVERS=()
fi

# dns_query NAME [SERVER] -> "ip1,ip2" sorted | NXDOMAIN | ERROR
dns_query() {
    local name="$1" server="${2:-}" out ips rc
    if [[ -n "$ANSWERS_FILE" ]]; then
        out=$(awk -F'\t' -v d="$name" -v s="${server:-system}" '$1 == d && $2 == s {print $3; exit}' "$ANSWERS_FILE")
        echo "${out:-ERROR}"; return
    fi
    case "${server:+$QUERY_TOOL}" in
        dig)
            out=$(dig +time=2 +tries=1 +noall +answer +comments A "$name" "@$server" 2>&1); rc=$?
            (( rc == 0 )) || { echo ERROR; return; }
            [[ "$out" == *"status: NXDOMAIN"* ]] && { echo NXDOMAIN; return; }
            ips=$(awk '$4 == "A" {print $5}' <<< "$out") ;;
        host)
            out=$(host -W 2 -t A "$name" "$server" 2>&1); rc=$?
            [[ "$out" == *NXDOMAIN* ]] && { echo NXDOMAIN; return; }
            (( rc == 0 )) || { echo ERROR; return; }
            ips=$(awk '/has address/ {print $NF}' <<< "$out") ;;
        nslookup)
            out=$(timeout 4 nslookup -type=A "$name" "$server" 2>&1)
            [[ "$out" == *NXDOMAIN* ]] && { echo NXDOMAIN; return; }
            ips=$(awk '/^Name:/ {f=1} f && /^Address/ {print $2}' <<< "$out") ;;
        *)  # system resolver through libc (honours /etc/hosts and nsswitch)
            [[ -n "$server" ]] && { echo ERROR; return; }
            ips=$(timeout 4 getent ahostsv4 "$name" 2>/dev/null | awk '{print $1}')
            [[ -n "$ips" ]] || { echo NXDOMAIN; return; } ;;
    esac
    ips=$(grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' <<< "$ips" | sort -u -t . -k1,1n -k2,2n -k3,3n -k4,4n | paste -sd, -)
    echo "${ips:-ERROR}"
}

FIND="$(mktemp)"; trap 'rm -f "$FIND"' EXIT
add() { printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$@" >> "$FIND"; }   # sev check domain resolver answer detail

# ---- 1. resolver configuration ------------------------------------------------------
if [[ -r "$RESOLV_FILE" ]]; then
    mapfile -t NS < <(awk '$1 == "nameserver" {print $2}' "$RESOLV_FILE")
    log INFO "configured nameservers: ${NS[*]:-none}"
    for ns in "${NS[@]:-}"; do
        if [[ -z "$ns" ]] || ! valid_ipv4 "$ns"; then continue; fi
        if is_private_or_bogon "$ns"; then
            add PASS NAMESERVER - "$ns" - "local/private resolver (router, systemd-resolved or corporate DNS)"
        elif [[ " $KNOWN_RESOLVERS " == *" $ns "* ]]; then
            add PASS NAMESERVER - "$ns" - "well-known public resolver"
        else
            add MEDIUM UNKNOWN_RESOLVER - "$ns" - "public resolver that is not on the well-known list: confirm it is your ISP's (DNS-changer malware sets rogue resolvers)"
        fi
    done
fi

# ---- 2. per-domain comparison --------------------------------------------------------
for d in "${DOMAIN_LIST[@]:-}"; do
    [[ -n "$d" ]] || continue
    sys=$(dns_query "$d")
    log DEBUG "$d system -> $sys"
    if [[ "$sys" == ERROR || "$sys" == NXDOMAIN ]]; then
        add LOW QUERY_FAILED "$d" system "$sys" "system resolver gave no A record"; continue
    fi
    pub_all=""; answered=0
    for r in "${RESOLVERS[@]:-}"; do
        [[ -n "$r" ]] || continue
        a=$(dns_query "$d" "$r")
        log DEBUG "$d @$r -> $a"
        if [[ "$a" == ERROR || "$a" == NXDOMAIN ]]; then
            add LOW QUERY_FAILED "$d" "$r" "$a" "no answer (UDP/53 to public resolvers may be blocked)"
        else
            answered=$((answered + 1)); pub_all+="${a},"
        fi
    done
    bad=""
    IFS=',' read -r -a sys_ips <<< "$sys"
    for ip in "${sys_ips[@]}"; do is_private_or_bogon "$ip" && bad+="$ip "; done
    if [[ -n "$bad" ]]; then
        add HIGH PRIVATE_ANSWER "$d" system "$sys" "public domain resolves to private/reserved ${bad% } (hijack, DNS rebinding or a filtering proxy)"
    elif (( answered )); then
        overlap=0
        for ip in "${sys_ips[@]}"; do [[ ",$pub_all" == *",$ip,"* ]] && overlap=1; done
        if (( overlap )); then add PASS CONSISTENT "$d" system "$sys" "matches $answered public resolver(s)"
        else add MEDIUM ANSWER_MISMATCH "$d" system "$sys" "no IP in common with public resolvers ($(tr ',' '\n' <<< "${pub_all%,}" | sort -u | paste -sd, -)); CDNs can explain this - verify"
        fi
    else
        add INFO UNVERIFIED "$d" system "$sys" "no public resolver answered, nothing to compare with"
    fi
done

# ---- 3. NXDOMAIN redirection -------------------------------------------------------------
if (( NX_TEST )); then
    nxname="nx-$(date +%s)-$RANDOM.example.com"
    [[ -n "$ANSWERS_FILE" ]] && nxname="NXTEST"
    a=$(dns_query "$nxname")
    if [[ "$a" == NXDOMAIN || "$a" == ERROR ]]; then add PASS NXDOMAIN_OK "$nxname" system "$a" "non-existent names are not redirected"
    else add MEDIUM NXDOMAIN_REDIRECT "$nxname" system "$a" "a random non-existent name resolved: the resolver rewrites NXDOMAIN"
    fi
fi

# ---- 4. DNSSEC validation (needs dig) -----------------------------------------------------
if [[ -z "$ANSWERS_FILE" && "$QUERY_TOOL" == dig ]]; then
    if dig +time=2 +tries=1 +dnssec isc.org A 2>/dev/null | grep -Eq 'flags:[^;]* ad[ ;]'; then
        add PASS DNSSEC system - - "system resolver validates DNSSEC (AD flag set)"
    else
        add INFO NO_DNSSEC system - - "system resolver did not set the AD flag; it may not validate DNSSEC"
    fi
fi

# ---- output ------------------------------------------------------------------------------
SORTED=$(awk -F'\t' '{r = ($1=="HIGH")?1:($1=="MEDIUM")?2:($1=="LOW")?3:($1=="INFO")?4:5; print r "\t" $0}' "$FIND" | sort -s -k1,1n | cut -f2-)
printf '\n%-7s %-18s %-22s %-15s %s\n' SEV CHECK DOMAIN RESOLVER ANSWER
while IFS=$'\t' read -r sev chk dom res ans det; do
    [[ -n "$sev" ]] || continue
    c=""; case "$sev" in HIGH) c=$C_RED ;; MEDIUM) c=$C_YEL ;; PASS) c=$C_GRN ;; esac
    printf '%s%-7s%s %-18s %-22.22s %-15s %s\n' "$c" "$sev" "$C_RST" "$chk" "$dom" "$res" "$ans"
done <<< "$SORTED"
echo
while IFS=$'\t' read -r sev chk dom res _ det; do
    if [[ "$sev" == HIGH || "$sev" == MEDIUM ]]; then log WARN "$chk $dom @$res: $det"; fi
done <<< "$SORTED"
NH=$(grep -c '^HIGH' "$FIND"); NM=$(grep -c '^MEDIUM' "$FIND")
echo "Findings: $NH high, $NM medium (${#DOMAIN_LIST[@]} domains, resolvers: ${RESOLVERS[*]:-none})"
for out in "${OUTPUTS[@]}"; do
    { printf 'severity\tcheck\tdomain\tresolver\tanswer\tdetail\n'; printf '%s\n' "$SORTED"; } |
        write_report auto "$out" "DNS analysis" "High=$NH|Medium=$NM|Domains=${#DOMAIN_LIST[@]}|Resolvers=${#RESOLVERS[@]}"
done
(( NH == 0 ))
