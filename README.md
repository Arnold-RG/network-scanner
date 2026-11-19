# network-scanner

Discover live hosts on a local IPv4 subnet from the command line, on Windows
(PowerShell) or Linux (bash). For every live host it shows the IP address, the
reverse-DNS hostname (when one exists) and which common TCP ports are open.

Also includes a text-based **Cisco Packet Tracer lab** (VLANs, DHCP,
router-on-a-stick) in [`packet-tracer-lab/`](packet-tracer-lab/README.md).

| Script | Platform |
|--------|----------|
| `scan-network.ps1` | Windows PowerShell 5.1+ / PowerShell 7+ (Windows, Linux, macOS) |
| `scan-network.sh`  | bash 4.3+ (Linux, WSL, macOS with a newer bash) |

## How it works

1. Expands the CIDR range (`/16` to `/32`) into host addresses.
2. Probes hosts in parallel (runspace pool in PowerShell, background jobs in bash).
3. A host is **live** if it answers ICMP echo **or** any TCP probe on 80/443/22/445.
   An actively refused TCP connection still proves the host is up, so hosts
   that block ping are often still found.
4. Resolves a hostname by reverse DNS (`getent`/`host` in bash, `System.Net.Dns` in PowerShell).
5. Runs a TCP connect check on a short list of common ports.

No admin/root rights and no third-party tools are needed. If `nmap` is
installed, the bash version can use it for discovery with `-N`.

## Requirements

- **PowerShell:** Windows PowerShell 5.1 or PowerShell 7+. Nothing else.
- **bash:** bash 4.3+, coreutils `timeout`. Optional: `ping` (iputils),
  `getent` or `host` for hostnames, `nmap`.

## Usage

### PowerShell

```powershell
Get-Help .\scan-network.ps1 -Full

.\scan-network.ps1 -Target 192.168.1.0/24
.\scan-network.ps1 -Target 192.168.1.0/24 -Ports 22,80,443 -Threads 128 -TimeoutMs 500
.\scan-network.ps1 -Target 10.0.0.0/28 -CsvPath lan.csv -NoPortScan

# Results are objects, so you can filter them:
.\scan-network.ps1 192.168.1.0/24 | Where-Object OpenPorts -match '3389'
```

If script execution is blocked, run it for the current session only:
`powershell -ExecutionPolicy Bypass -File .\scan-network.ps1 -Target 192.168.1.0/24`

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `-Target` | (required) | CIDR (`192.168.1.0/24`) or single IP |
| `-Ports` | 22,53,80,135,139,443,445,3389,8080 | Ports checked on live hosts |
| `-Threads` | 64 | Parallel probes (1-256) |
| `-TimeoutMs` | 1000 | Per-probe timeout (100-30000 ms) |
| `-CsvPath` | - | Write results to CSV |
| `-NoPortScan` | off | Discovery only |

### bash

```bash
chmod +x scan-network.sh
./scan-network.sh -h

./scan-network.sh -t 192.168.1.0/24
./scan-network.sh -t 192.168.1.0/24 -p 22,80,443 -j 128 -w 1 -o lan.csv
./scan-network.sh -t 10.0.0.0/28 -n        # discovery only
./scan-network.sh -t 192.168.1.0/24 -N     # use nmap -sn for discovery if installed
```

| Option | Default | Meaning |
|--------|---------|---------|
| `-t CIDR` | (required) | CIDR or single IP |
| `-p PORTS` | 22,53,80,135,139,443,445,3389,8080 | Ports checked on live hosts |
| `-j N` | 64 | Parallel probes (1-256) |
| `-w SEC` | 1 | Per-probe timeout (1-30 s) |
| `-o FILE` | - | Write results to CSV |
| `-n` | off | Skip port check |
| `-N` | off | Use nmap for discovery if present |

## Example output

Real run of the bash version against the loopback range on a Linux test box
(a local web server was listening on 8080; `ping` was not installed, so the
TCP fallback was used):

```
$ ./scan-network.sh -t 127.0.0.0/30 -p 22,80,8080
Scanning 127.0.0.1 - 127.0.0.2 (2 hosts, 64 parallel, timeout 1s)
Note: 'ping' not found - using TCP probes for liveness.

IP               HOSTNAME                         OPEN PORTS
---------------- -------------------------------- ----------
127.0.0.1        localhost                        8080
127.0.0.2        -                                -

2 live host(s) found in 0s.
```

PowerShell 7 on the same box:

```
PS> ./scan-network.ps1 -Target 127.0.0.0/30 -CsvPath hosts.csv
Scanning 127.0.0.1 - 127.0.0.2 (2 hosts, 64 threads, timeout 1000 ms)

IP        Hostname  OpenPorts
--        --------  ---------
127.0.0.1 localhost 8080
127.0.0.2 -         -

2 live host(s) found in 0s.
CSV written to hosts.csv
```

CSV format: `ip,hostname,open_ports` (multiple ports separated by `;`).

## Tests

```bash
bash tests/run-tests.sh      # scans 127.0.0.1 only; runs the pwsh test too if pwsh is installed
```

CI (GitHub Actions) runs ShellCheck, PSScriptAnalyzer and the smoke tests on every push.

## Limitations

- IPv4 only; ranges larger than a /16 are refused on purpose.
- A host that drops ICMP **and** all probed TCP ports silently will not be found.
- Hostnames depend on your DNS server having PTR records (many home routers do for DHCP clients).
- TCP connect checks are visible in the target's logs; this is not a stealth tool.

## Legal and ethical use

Only scan networks you own or are explicitly authorised to test. Unauthorised
scanning may break your ISP's or employer's rules and, in many countries, the law.

## License

[MIT](LICENSE) - Copyright (c) 2026 Arnold Rurangwa

---

## Maintainer release checklist

This tool makes active network probes. Run it **only against networks you own or are explicitly authorized to assess**. Do not confuse a ping response with proof that a host or service is secure.

- **Windows:** validate the documented PowerShell entry point and CSV output against a controlled test subnet.
- **Linux/macOS:** test bash requirements, timeouts, host detection and graceful behavior when optional utilities are unavailable.
- **Reliability:** bound concurrency, handle unreachable addresses and document false negatives from filtering or offline hosts.
- **CI/DevSecOps:** syntax checks, deterministic fixture tests and dependency/permissions review; report exact job results rather than claiming universal OS support.
- **Documentation:** retain this README's real command examples and update them whenever flags or defaults change.

No Kubernetes or cloud deployment is necessary for the command-line scanner.
