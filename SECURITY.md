# Security Policy — Network Scanner

## Supported code and private reports
Security updates apply to the default branch. Submit vulnerability reports privately through GitHub's private advisory feature if available or contact the maintainer privately. Never share live scan output, credentials, or vulnerable targets publicly.

## Security and acceptable-use boundaries
- **Scope:** Scan only devices, subnets, and environments you own or have explicit permission to assess. Confirm the target CIDR before running; avoid expansive ranges on production networks.
- **Reliability / network safety:** Respect the existing bounded host ranges, concurrency, and timeouts. Keep discovery and optional port probing non-destructive; do not add credential guessing or stealth/bypass techniques.
- **Data handling:** IP addresses, hostnames, open ports, and exported CSV reports can expose private network topology. Store reports locally with appropriate permissions and retention; anonymize examples.
- **IAM / secrets:** Scripts should not request or persist credentials; use standard account/network permissions and least privilege. Avoid embedding tokens into scripts.
- **GRC:** Obtain assessment authorization and document scope and retention where required.
- **Cloud / AI / OT:** Not inherent to this local CLI tool. If integrated with a cloud console, AI analyst, or industrial network, design separate access controls, data boundaries and safety review first.

## Release gate
Keep ShellCheck, PSScriptAnalyzer and smoke tests passing. Review changes that expand scan scope, rate, destinations, export formats or privileges before release.
