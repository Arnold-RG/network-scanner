# Data files

| File | What it is | Source |
|------|------------|--------|
| `oui-subset.csv` | MAC prefix (OUI, first 3 bytes) to vendor name, about 12,700 entries for common network, PC, phone, IoT and virtualisation vendors | Subset of the IEEE MA-L registry, taken from Wireshark's `manuf` file (generated from the IEEE listings). **Partial**: unknown prefixes show as `-`. |
| `dns-check-domains.txt` | Domains that `dns-analyzer` resolves through every resolver | Hand-picked; edit freely |

To use the complete registry, download `oui.csv` from the IEEE
(https://standards-oui.ieee.org/oui/oui.csv), convert it to `prefix,vendor`
lines such as `B8:27:EB,Raspberry Pi Foundation`, and point `OUI_FILE` at it.

MAC addresses whose second hex digit is 2, 6, A or E are *locally
administered* (for example randomised Wi-Fi MACs on phones). They have no
vendor, and the tools label them `random/local MAC`.
