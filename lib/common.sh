# shellcheck shell=bash
# =============================================================================
# lib/common.sh - shared helpers for the bash tools in this repository
# -----------------------------------------------------------------------------
# Provides: levelled logging (console + optional log file), a safe KEY=VALUE
# config loader (no eval), CSV/JSON/HTML escaping, a self-contained HTML report
# writer and a small job semaphore for parallel work.
# Source it from a tool:  . "$(dirname "$0")/lib/common.sh"
# Author: Arnold Rurangwa - MIT License
# =============================================================================

LOG_LEVEL="${LOG_LEVEL:-INFO}"   # DEBUG | INFO | WARN | ERROR
LOG_FILE="${LOG_FILE:-}"         # empty = console only
QUIET="${QUIET:-0}"              # 1 = only WARN/ERROR on the console

# Colours only when stderr is a terminal and NO_COLOR is not set.
if [[ -t 2 && -z "${NO_COLOR:-}" ]]; then
    C_RED=$'\e[31m'; C_YEL=$'\e[33m'; C_GRN=$'\e[32m'; C_CYN=$'\e[36m'; C_DIM=$'\e[2m'; C_RST=$'\e[0m'
else
    C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""; C_DIM=""; C_RST=""
fi
export C_RED C_YEL C_GRN C_CYN C_DIM C_RST

_lvl_num() { case "$1" in DEBUG) echo 10 ;; INFO) echo 20 ;; WARN) echo 30 ;; ERROR) echo 40 ;; *) echo 20 ;; esac; }

# log LEVEL message... -> stderr (so stdout stays clean for data) + LOG_FILE
log() {
    local lvl="$1"; shift
    (( $(_lvl_num "$lvl") >= $(_lvl_num "$LOG_LEVEL") )) || return 0
    local ts line colour=""
    ts=$(date '+%Y-%m-%dT%H:%M:%S%z')
    line="$ts [$lvl] $*"
    if [[ -n "$LOG_FILE" ]]; then printf '%s\n' "$line" >> "$LOG_FILE" 2>/dev/null || true; fi
    case "$lvl" in ERROR) colour=$C_RED ;; WARN) colour=$C_YEL ;; DEBUG) colour=$C_DIM ;; esac
    [[ "$*" == "[HIGH]"* || "$*" == "[FAIL]"* ]] && colour=$C_RED   # findings stand out
    if [[ "$lvl" == WARN || "$lvl" == ERROR || "$QUIET" != 1 ]]; then
        printf '%s%s%s\n' "$colour" "$line" "$C_RST" >&2
    fi
}

die() { log ERROR "$*"; exit 2; }

# need_cmd NAME -> success if the command exists
need_cmd() { command -v "$1" >/dev/null 2>&1; }

# load_config FILE -> sets KEY=VALUE pairs as shell variables.
# Only UPPER_CASE keys are accepted, values are taken literally (no eval,
# no command substitution), surrounding quotes are stripped, and # starts a
# comment (whole line, or after whitespace at the end of an unquoted value).
load_config() {
    local file="$1" line key val n=0
    [[ -r "$file" ]] || die "config file not readable: $file"
    while IFS= read -r line || [[ -n "$line" ]]; do
        n=$((n + 1))
        line="${line%$'\r'}"
        [[ "$line" =~ ^[[:space:]]*(#|;|$) ]] && continue
        if [[ "$line" =~ ^[[:space:]]*([A-Z_][A-Z0-9_]*)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            key="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[2]}"
            if [[ "$val" =~ ^\"([^\"]*)\" || "$val" =~ ^\'([^\']*)\' ]]; then
                val="${BASH_REMATCH[1]}"                    # quoted: keep as is
            else
                val="${val%%[[:space:]]#*}"                 # strip "  # comment"
                [[ "$val" == \#* ]] && val=""
                val="${val%"${val##*[![:space:]]}"}"        # trim right
            fi
            printf -v "$key" '%s' "$val"
        else
            log WARN "$file:$n: ignored line (expected KEY=VALUE)"
        fi
    done < "$file"
    log DEBUG "loaded config $file"
}

# find_config_arg "$@" -> prints the value given to -c/--config, if any
find_config_arg() {
    while (( $# )); do
        case "$1" in -c|--config) printf '%s' "${2:-}"; return 0 ;; esac
        shift
    done
}

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/}"; s="${s//$'\n'/\\n}"
    printf '%s' "$s"
}
csv_escape() {
    local s="$1"
    if [[ "$s" == *[,\"$'\n']* ]]; then s="\"${s//\"/\"\"}\""; fi
    printf '%s' "$s"
}
html_escape() {
    local s="$1"
    s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"; s="${s//\"/&quot;}"
    printf '%s' "$s"
}

# tsv_to_csv < TSV -> CSV on stdout (first line is the header)
tsv_to_csv() {
    local line out f
    while IFS= read -r line; do
        out=""
        IFS=$'\t' read -r -a f <<< "$line"
        for x in "${f[@]}"; do out+="$(csv_escape "$x"),"; done
        printf '%s\n' "${out%,}"
    done
}

# tsv_to_json < TSV -> JSON array of objects keyed by the header line
tsv_to_json() {
    local header line first=1 i obj
    IFS=$'\t' read -r -a header
    printf '['
    while IFS= read -r line; do
        local -a f=()
        IFS=$'\t' read -r -a f <<< "$line"
        obj=""
        for (( i = 0; i < ${#header[@]}; i++ )); do
            obj+="\"$(json_escape "${header[$i]}")\":\"$(json_escape "${f[$i]:-}")\","
        done
        (( first )) || printf ','
        first=0
        printf '\n  {%s}' "${obj%,}"
    done
    printf '\n]\n'
}

# write_report FORMAT FILE TITLE SUMMARY < TSV
#   FORMAT : csv | json | html (or "auto" = from the file extension)
#   SUMMARY: "Label=Value|Label=Value" pairs shown as cards in the HTML report
write_report() {
    local fmt="$1" file="$2" title="$3" summary="${4:-}"
    [[ "$fmt" == auto ]] && fmt="${file##*.}"
    case "$fmt" in
        csv)  tsv_to_csv  > "$file" ;;
        json) tsv_to_json > "$file" ;;
        html|htm) html_report "$title" "$summary" > "$file" ;;
        *) die "unknown report format: $fmt (use csv, json or html)" ;;
    esac || die "cannot write $file"
    log INFO "report written: $file"
}

# html_report TITLE SUMMARY < TSV -> self-contained HTML page (no JS, no CDN)
# Columns named severity/status/level get a coloured pill per value.
html_report() {
    local title="$1" summary="$2" line i sevcol=-1 host gen
    local -a header cells pairs
    host="${REPORT_HOSTNAME:-$(hostname 2>/dev/null || echo unknown)}"; gen=$(date '+%Y-%m-%d %H:%M:%S %Z')
    cat <<HTML
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$(html_escape "$title")</title>
<style>
:root{--bg:#0f172a;--panel:#111827;--card:#1f2937;--text:#e5e7eb;--muted:#9ca3af;--line:#374151;--accent:#38bdf8}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;background:var(--bg);color:var(--text)}
header{padding:24px 32px;border-bottom:1px solid var(--line);background:var(--panel)}
h1{margin:0 0 4px;font-size:22px}header p{margin:0;color:var(--muted)}
main{padding:24px 32px}.cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:140px}
.card b{display:block;font-size:22px;color:var(--accent)}.card span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--card);color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:0}td{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px;overflow-wrap:break-word}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600}
.p-high,.p-fail,.p-critical,.p-alert,.p-error{background:#7f1d1d;color:#fecaca}.p-medium,.p-warn,.p-warning,.p-changed{background:#78350f;color:#fde68a}
.p-low,.p-info,.p-new{background:#1e3a8a;color:#bfdbfe}.p-pass,.p-ok,.p-open{background:#14532d;color:#bbf7d0}
footer{padding:16px 32px;color:var(--muted);font-size:12px}
</style></head><body>
<header><h1>$(html_escape "$title")</h1><p>Host $(html_escape "$host") &middot; generated $(html_escape "$gen")</p></header>
<main>
HTML
    if [[ -n "$summary" ]]; then
        printf '<div class="cards">\n'
        IFS='|' read -r -a pairs <<< "$summary"
        for p in "${pairs[@]}"; do
            printf '<div class="card"><b>%s</b><span>%s</span></div>\n' "$(html_escape "${p#*=}")" "$(html_escape "${p%%=*}")"
        done
        printf '</div>\n'
    fi
    printf '<table>\n<thead><tr>'
    IFS=$'\t' read -r -a header
    for (( i = 0; i < ${#header[@]}; i++ )); do
        case "${header[$i],,}" in severity|status|level|state) (( sevcol < 0 )) && sevcol=$i ;; esac
        printf '<th>%s</th>' "$(html_escape "${header[$i]}")"
    done
    printf '</tr></thead>\n<tbody>\n'
    while IFS= read -r line; do
        IFS=$'\t' read -r -a cells <<< "$line"
        printf '<tr>'
        for (( i = 0; i < ${#header[@]}; i++ )); do
            if (( i == sevcol )); then
                printf '<td><span class="pill p-%s">%s</span></td>' "$(html_escape "${cells[$i],,}")" "$(html_escape "${cells[$i]:-}")"
            else
                printf '<td>%s</td>' "$(html_escape "${cells[$i]:-}")"
            fi
        done
        printf '</tr>\n'
    done
    printf '</tbody></table>\n</main>\n<footer>Generated by %s &middot; read-only report &middot; MIT License</footer>\n</body></html>\n' "$(html_escape "${TOOL_NAME:-$(basename "$0")}")"
}

# throttle N -> block until fewer than N background jobs are running
throttle() { while (( $(jobs -rp | wc -l) >= $1 )); do wait -n 2>/dev/null || true; done; }

# valid_ipv4 IP -> success for a dotted quad with octets 0-255
valid_ipv4() {
    local ip="$1" o x
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r -a o <<< "$ip"
    for x in "${o[@]}"; do (( 10#$x <= 255 )) || return 1; done
}
ip_to_int() { local a b c d; IFS=. read -r a b c d <<< "$1"; echo $(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d )); }
int_to_ip() { local n=$1; echo "$(( (n >> 24) & 255 )).$(( (n >> 16) & 255 )).$(( (n >> 8) & 255 )).$(( n & 255 ))"; }
is_int_between() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= $2 && 10#$1 <= $3 )); }

# is_root -> success when running with UID 0
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
