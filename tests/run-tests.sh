#!/usr/bin/env bash
# Smoke tests for scan-network.sh / scan-network.ps1 against localhost only.
set -euo pipefail
cd "$(dirname "$0")/.."
PORT=18080
python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true; rm -f /tmp/ns-test.csv' EXIT
sleep 1
fail() { echo "FAIL: $*"; exit 1; }

echo "== bash: localhost scan"
out=$(./scan-network.sh -t 127.0.0.1 -p "22,$PORT" -o /tmp/ns-test.csv)
echo "$out"
grep -q "127.0.0.1" <<< "$out" || fail "127.0.0.1 not reported live"
grep -Eq "^127\.0\.0\.1,[^,]*,([0-9]+;)*$PORT(;|$)" /tmp/ns-test.csv || fail "open port $PORT missing from CSV"

echo "== bash: input validation"
./scan-network.sh -t 999.1.1.1/24 >/dev/null 2>&1 && fail "bad IP accepted"
./scan-network.sh -t 10.0.0.0/8 >/dev/null 2>&1 && fail "/8 accepted"
./scan-network.sh -t 127.0.0.1 -p 70000 >/dev/null 2>&1 && fail "bad port accepted"
grep -q Usage <<< "$(./scan-network.sh -h)" || fail "help missing"

if command -v pwsh >/dev/null 2>&1; then
    echo "== pwsh: localhost scan"
    pwsh -NoProfile -Command "\$r = ./scan-network.ps1 -Target 127.0.0.1 -Ports 22,$PORT; if (-not (\$r | Where-Object { \$_.OpenPorts -match '$PORT' })) { exit 1 }" \
        || fail "pwsh scan did not find port $PORT"
fi
echo "All tests passed."
