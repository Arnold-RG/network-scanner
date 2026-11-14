<#
.SYNOPSIS
    Discover live hosts on a local IPv4 subnet (v2): IP, MAC, vendor, hostname, open ports.

.DESCRIPTION
    scan-network.ps1 sweeps a CIDR range on a runspace pool (Windows PowerShell
    5.1 and PowerShell 7+, no extra modules) and combines three discovery methods:
      * ICMP echo
      * TCP connect - an open OR actively refused port proves the host is up
      * ARP / neighbour table - every host that answered ARP is on the segment
    Live hosts are enriched with MAC address + OUI vendor, a hostname from DNS
    (and NetBIOS via nbtstat on Windows) and a quick check of the top ports.
    Results go to the console, the pipeline and optional CSV/JSON/HTML reports.

    Author : Arnold Rurangwa - MIT License
    Legal  : Only scan networks you own or are explicitly authorised to test.

.PARAMETER Target
    Network in CIDR notation (192.168.1.0/24, /16 to /32) or a single IPv4 address.
.PARAMETER Ports
    Ports checked on live hosts. Default: top 20 TCP ports.
.PARAMETER NoPortScan
    Discovery only.
.PARAMETER Methods
    Discovery methods: icmp, tcp, arp (default all three).
.PARAMETER Threads
    Parallel probes, 1-256. Default 64.
.PARAMETER TimeoutMs
    Per-probe timeout in milliseconds, 100-30000. Default 1000.
.PARAMETER OutputPath
    One or more report files; format from the extension (.csv, .json, .html).
.PARAMETER ConfigPath
    KEY=VALUE config file (config/network-scanner.conf). Parameters override it.
.PARAMETER NeighborFile
    Read the ARP table from a saved `arp -a` / `ip neigh` dump instead of the live one.
.PARAMETER LogPath
    Append log lines to this file.
.PARAMETER LogLevel
    DEBUG, INFO, WARN or ERROR. Default INFO.

.EXAMPLE
    .\scan-network.ps1 -Target 192.168.1.0/24
.EXAMPLE
    .\scan-network.ps1 -Target 192.168.1.0/24 -OutputPath lan.html, lan.csv
.EXAMPLE
    .\scan-network.ps1 192.168.1.0/24 | Where-Object Vendor -match 'Raspberry'

.NOTES
    Requirements: Windows PowerShell 5.1+ or PowerShell 7+. No admin rights needed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)][string]$Target,
    [ValidateRange(1, 65535)][int[]]$Ports,
    [switch]$NoPortScan,
    [ValidateSet('icmp', 'tcp', 'arp')][string[]]$Methods,
    [ValidateRange(1, 256)][int]$Threads,
    [ValidateRange(100, 30000)][int]$TimeoutMs,
    [string[]]$OutputPath = @(),
    [string]$ConfigPath,
    [string]$NeighborFile,
    [string]$LogPath,
    [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')][string]$LogLevel
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib/Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'lib/NetTools.psm1') -Force

# ---- configuration: defaults < config file < parameters -----------------------
$cfg = @{}
if ($ConfigPath) { $cfg = Import-ToolConfig -Path $ConfigPath }
if (-not $LogLevel) { $LogLevel = Get-ConfigValue $cfg 'LOG_LEVEL' 'INFO' }
if (-not $LogPath) { $LogPath = Get-ConfigValue $cfg 'LOG_FILE' '' }
Set-ToolLogging -Level $LogLevel -Path $LogPath
if (-not $Ports) { $Ports = @((Get-ConfigValue $cfg 'PORTS' '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080').Split(',') | ForEach-Object { [int]$_ }) }
if (-not $Methods) { $Methods = @((Get-ConfigValue $cfg 'METHODS' 'icmp,tcp,arp').Split(',')) }
if (-not $Threads) { $Threads = [int](Get-ConfigValue $cfg 'JOBS' 64) }
if (-not $TimeoutMs) { $TimeoutMs = 1000 * [int](Get-ConfigValue $cfg 'TIMEOUT' 1) }
$discPorts = @((Get-ConfigValue $cfg 'TCP_DISCOVERY_PORTS' '80,443,22,445,139,3389').Split(',') | ForEach-Object { [int]$_ })
$ouiPath = Get-ConfigValue $cfg 'OUI_FILE' 'data/oui-subset.csv'
if (-not [System.IO.Path]::IsPathRooted($ouiPath)) { $ouiPath = Join-Path $PSScriptRoot $ouiPath }
$useNetbios = (Get-ConfigValue $cfg 'RESOLVE_NETBIOS' '1') -eq '1'

$range = Get-CidrRange $Target
if ($range.Count -gt 65536) { throw "Range too large ($($range.Count) hosts)." }

# ---- per-host probe (self-contained: runs in its own runspace) -----------------
$probe = {
    param([string]$Ip, $A)
    function Test-Tcp([string]$HostIp, [int]$Port, [int]$Ms) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $async = $client.BeginConnect($HostIp, $Port, $null, $null)
            if (-not $async.AsyncWaitHandle.WaitOne($Ms)) { return 'filtered' }
            try { $client.EndConnect($async); return 'open' }
            catch {
                $e = $_.Exception
                while ($e -and -not ($e -is [System.Net.Sockets.SocketException])) { $e = $e.InnerException }
                if ($e -and $e.SocketErrorCode -eq 'ConnectionRefused') { return 'closed' }
                return 'filtered'
            }
        } finally { $client.Close() }
    }
    $via = $A.KnownVia
    if (-not $via -and $A.Methods -contains 'icmp') {
        try { if ((New-Object System.Net.NetworkInformation.Ping).Send($Ip, $A.TimeoutMs).Status -eq 'Success') { $via = 'icmp' } } catch { $via = $null }
    }
    if (-not $via -and $A.Methods -contains 'tcp') {
        foreach ($p in $A.DiscPorts) { if ((Test-Tcp $Ip $p $A.TimeoutMs) -ne 'filtered') { $via = "tcp/$p"; break } }
    }
    if (-not $via) { return }
    $name = '-'; $src = '-'
    try { $n = [System.Net.Dns]::GetHostEntry($Ip).HostName; if ($n -and $n -ne $Ip) { $name = $n; $src = 'dns' } } catch { $name = '-' }
    if ($name -eq '-' -and $A.NetBios -and $A.IsWindows) {
        $nb = & nbtstat -A $Ip 2>$null | Select-String '<00>\s+UNIQUE' | Select-Object -First 1
        if ($nb) { $name = ($nb.Line.Trim() -split '\s+')[0]; $src = 'netbios' }
    }
    $open = @()
    if (-not $A.NoPortScan) { foreach ($p in $A.Ports) { if ((Test-Tcp $Ip $p $A.TimeoutMs) -eq 'open') { $open += $p } } }
    [pscustomobject]@{ IP = $Ip; Hostname = $name; NameSource = $src; DiscoveredBy = $via; OpenPorts = ($open -join ';') }
}

$common = @{ Methods = $Methods; DiscPorts = $discPorts; TimeoutMs = $TimeoutMs; Ports = $Ports
    NoPortScan = [bool]$NoPortScan; NetBios = $useNetbios; IsWindows = (Test-ToolIsWindows); KnownVia = $null }

Write-ToolLog INFO ("scanning {0} - {1} ({2} hosts, methods {3}, {4} threads, timeout {5} ms)" -f `
    (ConvertTo-IpString ([uint32]$range.First)), (ConvertTo-IpString ([uint32]$range.Last)), $range.Count, ($Methods -join ','), $Threads, $TimeoutMs)
$started = Get-Date
$ips = for ($i = $range.First; $i -le $range.Last; $i++) { ConvertTo-IpString ([uint32]$i) }
$results = @(Invoke-ToolParallel -InputObject @($ips) -ScriptBlock $probe -ArgumentList $common -Throttle $Threads -Activity 'Sweeping')

# ---- ARP table: MAC addresses + hosts that only answered ARP ----------------------
$macOf = @{}
if ($Methods -contains 'arp' -or $NeighborFile) {
    $seen = @{}; foreach ($r in $results) { $seen[$r.IP] = $true }
    $arpOnly = @()
    foreach ($n in (Get-NeighborTable -Path $NeighborFile)) {
        $v = ConvertTo-UInt32 $n.IP
        if ($v -lt $range.First -or $v -gt $range.Last) { continue }
        $macOf[$n.IP] = $n.MAC
        if (-not $seen.ContainsKey($n.IP)) { $arpOnly += $n.IP }
    }
    if ($arpOnly) {
        $arpArgs = $common.Clone(); $arpArgs.KnownVia = 'arp'
        $results += @(Invoke-ToolParallel -InputObject $arpOnly -ScriptBlock $probe -ArgumentList $arpArgs -Throttle $Threads -Activity 'ARP hosts')
    }
}

$oui = Import-OuiTable $ouiPath
$rows = @($results | Sort-Object { ConvertTo-UInt32 $_.IP } | ForEach-Object {
        $mac = if ($macOf.ContainsKey($_.IP)) { $macOf[$_.IP] } else { '-' }
        [pscustomobject]@{
            IP = $_.IP; MAC = $mac; Vendor = (Get-MacVendor $mac $oui); Hostname = $_.Hostname; NameSource = $_.NameSource
            DiscoveredBy = $_.DiscoveredBy; OpenPorts = $(if ($_.OpenPorts) { $_.OpenPorts } else { '-' })
        }
    })
$elapsed = [int]((Get-Date) - $started).TotalSeconds
$rows | Format-Table IP, MAC, Vendor, Hostname, DiscoveredBy, OpenPorts -AutoSize | Out-String -Width 200 | Write-Host
Write-Host ("{0} live host(s) out of {1} scanned in {2}s." -f $rows.Count, $range.Count, $elapsed)

$summary = [ordered]@{ 'Live hosts' = $rows.Count; 'Addresses scanned' = $range.Count; 'Duration' = "${elapsed}s"; 'Methods' = ($Methods -join ',') }
foreach ($out in $OutputPath) { Export-ToolReport -Path $out -Rows $rows -Title "Network scan: $Target" -Summary $summary -ToolName 'scan-network.ps1' }

# Objects go to the pipeline: .\scan-network.ps1 10.0.0.0/24 | Where-Object OpenPorts -match 22
$rows
