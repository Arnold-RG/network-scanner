#!/usr/bin/env bash
# Tests for network-scanner: localhost scans + offline fixtures, bash and
# (when pwsh is installed) PowerShell. Nothing leaves 127.0.0.1.
set -euo pipefail
cd "$(dirname "$0")/.."
PORT=18080; DNSPORT=15353
T=$(mktemp -d)
python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 & HTTP=$!
python3 tests/dns_server.py "$DNSPORT" & DNS=$!
trap 'kill $HTTP $DNS 2>/dev/null || true; rm -rf "$T"' EXIT
sleep 1
pass=0
ok() { pass=$((pass + 1)); echo "  ok - $*"; }
fail() { echo "FAIL: $*"; exit 1; }
F=tests/fixtures

echo "== bash: scan-network"
out=$(./scan-network.sh -t 127.0.0.1 -p "22,$PORT" --neigh-file $F/ip-neigh.txt -o "$T/s.csv" -o "$T/s.json" -o "$T/s.html" 2>&1)
echo "$out"
grep -Eq "^127\.0\.0\.1,B8:27:EB:12:34:56,Raspberry Pi Foundation,[^,]*,[^,]*,[^,]*,([0-9]+;)*$PORT(;|$)" "$T/s.csv" || fail "CSV row (MAC, vendor, port) wrong"; ok "CSV has MAC, OUI vendor and open port"
python3 -c "import json,sys; d=json.load(open('$T/s.json')); assert d[0]['ip']=='127.0.0.1'" || fail "JSON invalid"; ok "JSON parses"
grep -q '<table>' "$T/s.html" || fail "HTML table"; grep -q 'Live hosts' "$T/s.html" || fail "HTML summary"; ok "HTML report"
./scan-network.sh -t 999.1.1.1/24 >/dev/null 2>&1 && fail "bad IP accepted"; ok "rejects bad IP"
./scan-network.sh -t 10.0.0.0/8 >/dev/null 2>&1 && fail "/8 accepted"; ok "rejects /8"
./scan-network.sh -t 127.0.0.1 -p 70000 >/dev/null 2>&1 && fail "bad port accepted"; ok "rejects port 70000"
./scan-network.sh -t 127.0.0.1 -m smoke >/dev/null 2>&1 && fail "bad method accepted"; ok "rejects unknown method"
./scan-network.sh -h | grep -q Usage || fail "help"; ok "help"
./scan-network.sh -c config/network-scanner.conf -t 127.0.0.1 -n -q >/dev/null || fail "config file"; ok "config file loads"

echo "== bash: arp-spoof-detector"
./arp-spoof-detector.sh --init -b "$T/base.txt" -g 192.168.50.1 --neigh-file $F/arp-baseline-neigh.txt -q
[[ $(grep -vc '^#' "$T/base.txt") -eq 3 ]] || fail "baseline size"; ok "baseline written"
./arp-spoof-detector.sh -b "$T/base.txt" --neigh-file $F/arp-baseline-neigh.txt -q -o "$T/a0.csv" || fail "clean table flagged"; ok "clean table -> exit 0"
set +e; ./arp-spoof-detector.sh -b "$T/base.txt" --neigh-file $F/arp-poisoned-neigh.txt -q -o "$T/a.csv" -o "$T/a.html" 2>/dev/null; rc=$?; set -e
(( rc == 1 )) || fail "poisoned table exit $rc"; ok "poisoned table -> exit 1"
grep -q '^HIGH,GATEWAY_MAC_CHANGED,192.168.50.1' "$T/a.csv" || fail "gateway change missed"; ok "gateway MAC change"
grep -q '^HIGH,GATEWAY_MAC_CLAIMED' "$T/a.csv" || fail "claimed gateway MAC missed"; ok "gateway MAC claimed by another IP"
grep -q 'NEW_HOST,192.168.50.77,3A:11:22:33:44:55,not in baseline (random/local MAC)' "$T/a.csv" || fail "random MAC"; ok "random MAC labelled"
./arp-spoof-detector.sh -b "$T/base.txt" --neigh-file $F/arp-baseline-neigh.txt -W 1 -n 2 -q || fail "watch mode"; ok "watch mode stops after --count"

echo "== bash: dns-analyzer"
set +e; ./dns-analyzer.sh -d example.com,mybank.example,shop.example --answers-file $F/dns-answers.tsv --resolv-file $F/resolv.conf -q -o "$T/d.csv" >/dev/null 2>&1; rc=$?; set -e
(( rc == 1 )) || fail "dns exit $rc"; ok "HIGH finding -> exit 1"
grep -q '^HIGH,PRIVATE_ANSWER,mybank.example' "$T/d.csv" || fail "private answer"; ok "private answer for public domain"
grep -q '^MEDIUM,ANSWER_MISMATCH,shop.example' "$T/d.csv" || fail "mismatch"; ok "answer mismatch"
grep -q '^MEDIUM,UNKNOWN_RESOLVER,-,85.255.112.10' "$T/d.csv" || fail "rogue resolver"; ok "unknown public resolver"
grep -q '^MEDIUM,NXDOMAIN_REDIRECT' "$T/d.csv" || fail "nx redirect"; ok "NXDOMAIN redirection"
grep -q '^PASS,CONSISTENT,example.com' "$T/d.csv" || fail "consistent"; ok "consistent answer passes"
./dns-analyzer.sh -d 'bad_domain!' >/dev/null 2>&1 && fail "bad domain accepted"; ok "rejects bad domain"

if command -v pwsh >/dev/null 2>&1; then
    echo "== pwsh"
    pwsh -NoProfile -NonInteractive -Command "
        \$ErrorActionPreference = 'Stop'
        \$r = ./scan-network.ps1 -Target 127.0.0.1 -Ports 22,$PORT -NeighborFile $F/ip-neigh.txt -OutputPath '$T/p.csv','$T/p.html' 6>\$null
        if (-not (\$r | Where-Object { \$_.OpenPorts -match '$PORT' -and \$_.Vendor -eq 'Raspberry Pi Foundation' })) { throw 'scan-network.ps1 result' }
        Import-Module ./lib/NetTools.psm1
        \$w = @(ConvertFrom-NeighborText (Get-Content $F/arp-windows.txt))
        if (\$w.Count -ne 2 -or \$w[0].MAC -ne '74:AC:B9:11:22:33') { throw 'Windows arp -a parsing' }
        \$q = Invoke-RawDnsQuery www.example.com 127.0.0.1 -Port $DNSPORT
        if (\$q.Status -ne 'NOERROR' -or (\$q.Addresses -join ',') -ne '203.0.113.7,203.0.113.8' -or -not \$q.AD) { throw 'raw DNS parse' }
        if ((Invoke-RawDnsQuery nx-x.example.com 127.0.0.1 -Port $DNSPORT).Status -ne 'NXDOMAIN') { throw 'raw DNS NXDOMAIN' }
        if ((Get-CidrRange 192.168.1.77/24).Count -ne 254) { throw 'CIDR maths' }
    " || fail "pwsh scan / parsers"
    ok "scan-network.ps1, Windows arp -a parser, raw DNS parser (CNAME + compression + AD), CIDR"
    pwsh -NoProfile -NonInteractive -Command "./arp-spoof-detector.ps1 -InitBaseline -BaselinePath '$T/pb.txt' -Gateway 192.168.50.1 -NeighborFile $F/arp-baseline-neigh.txt 6>\$null" >/dev/null
    diff <(grep -v '^#' "$T/base.txt") <(grep -v '^#' "$T/pb.txt") >/dev/null || fail "baseline formats differ"; ok "bash and PowerShell baselines identical"
    set +e; pwsh -NoProfile -NonInteractive -Command "./arp-spoof-detector.ps1 -BaselinePath '$T/pb.txt' -NeighborFile $F/arp-poisoned-neigh.txt -OutputPath '$T/pa.csv' 6>\$null | Out-Null; exit \$LASTEXITCODE" >/dev/null; rc=$?; set -e
    (( rc == 1 )) || fail "pwsh arp exit $rc"
    diff <(cut -d, -f1-4 "$T/a.csv" | tail -n +2) <(tr -d '"' < "$T/pa.csv" | cut -d, -f1-4 | tail -n +2) || fail "arp findings differ between bash and PowerShell"; ok "arp-spoof-detector.ps1 matches bash"
    set +e; pwsh -NoProfile -NonInteractive -Command "./dns-analyzer.ps1 -Domains example.com,mybank.example,shop.example -AnswersFile $F/dns-answers.tsv -ResolvFile $F/resolv.conf -OutputPath '$T/pd.csv' 6>\$null | Out-Null; exit \$LASTEXITCODE" >/dev/null; rc=$?; set -e
    (( rc == 1 )) || fail "pwsh dns exit $rc"
    diff <(cut -d, -f1-5 "$T/d.csv" | tail -n +2) <(tr -d '"' < "$T/pd.csv" | cut -d, -f1-5 | tail -n +2) || fail "dns findings differ"; ok "dns-analyzer.ps1 matches bash"
else
    echo "(pwsh not installed - PowerShell tests skipped)"
fi
echo "All $pass tests passed."
