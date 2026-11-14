<#
.SYNOPSIS
    Detect ARP spoofing / man-in-the-middle signs in the local ARP table.

.DESCRIPTION
    Reads the IPv4 neighbour (ARP) table and compares it with a trusted baseline:
      HIGH   gateway MAC changed since the baseline (classic ARP-poisoning sign)
      HIGH   the gateway's MAC also answers for other IPs (someone claims it)
      MEDIUM one MAC address answering for several IPs
      MEDIUM a known host's MAC changed since the baseline
      INFO   hosts not in the baseline / gateway missing from the table
    Runs once or, with -WatchSeconds, keeps checking and alerts only on new
    findings. Read-only: it never sends ARP packets or changes the table.
    Exit code 1 when a HIGH finding exists (handy for scheduled tasks).

    Author : Arnold Rurangwa - MIT License

.PARAMETER InitBaseline
    Save the current table as the trusted baseline (do this on a network you trust).
.PARAMETER BaselinePath
    Baseline file. Default arp-baseline.txt (same format as the bash version).
.PARAMETER Gateway
    Gateway IP to protect. Default: from the baseline, else the default route.
.PARAMETER WatchSeconds
    Re-check every N seconds until Ctrl+C (or -Count checks).
.PARAMETER Count
    With -WatchSeconds, stop after this many checks.
.PARAMETER OutputPath
    Report(s) of the last check: .csv, .json or .html.
.PARAMETER NeighborFile
    Analyse a saved `arp -a` / `ip neigh` dump instead of the live table.
.PARAMETER ConfigPath
    KEY=VALUE config file.
.PARAMETER LogPath
    Append log lines to this file.

.EXAMPLE
    .\arp-spoof-detector.ps1 -InitBaseline
.EXAMPLE
    .\arp-spoof-detector.ps1 -WatchSeconds 15 -LogPath arp.log
.EXAMPLE
    .\arp-spoof-detector.ps1 -OutputPath arp-report.html
#>
[CmdletBinding()]
param(
    [switch]$InitBaseline,
    [string]$BaselinePath,
    [string]$Gateway,
    [ValidateRange(1, 86400)][int]$WatchSeconds,
    [ValidateRange(0, 1000000)][int]$Count = 0,
    [string[]]$OutputPath = @(),
    [string]$NeighborFile,
    [string]$ConfigPath,
    [string]$LogPath,
    [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')][string]$LogLevel
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib/Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'lib/NetTools.psm1') -Force

$cfg = @{}
if ($ConfigPath) { $cfg = Import-ToolConfig -Path $ConfigPath }
if (-not $LogLevel) { $LogLevel = Get-ConfigValue $cfg 'LOG_LEVEL' 'INFO' }
if (-not $LogPath) { $LogPath = Get-ConfigValue $cfg 'LOG_FILE' '' }
Set-ToolLogging -Level $LogLevel -Path $LogPath
if (-not $BaselinePath) { $BaselinePath = Get-ConfigValue $cfg 'ARP_BASELINE' 'arp-baseline.txt' }
if ($Gateway -and $Gateway -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { throw "Invalid gateway IP: $Gateway" }
$ouiPath = Get-ConfigValue $cfg 'OUI_FILE' 'data/oui-subset.csv'
if (-not [System.IO.Path]::IsPathRooted($ouiPath)) { $ouiPath = Join-Path $PSScriptRoot $ouiPath }
$oui = Import-OuiTable $ouiPath

if ($InitBaseline) {
    if (-not $Gateway) { $Gateway = Get-DefaultGateway }
    $lines = @("# arp-spoof-detector baseline - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')", "# gateway $(if ($Gateway) { $Gateway } else { '-' })")
    $lines += Get-NeighborTable -Path $NeighborFile | Sort-Object IP -Unique | ForEach-Object { "$($_.IP) $($_.MAC)" }
    Set-Content -LiteralPath $BaselinePath -Value $lines -Encoding ASCII
    Write-ToolLog INFO "baseline saved to $BaselinePath ($($lines.Count - 2) entries, gateway $Gateway)"
    exit 0
}

$base = @{}
if (Test-Path -LiteralPath $BaselinePath) {
    foreach ($l in Get-Content -LiteralPath $BaselinePath) {
        if ($l -match '^# gateway (\S+)' -and -not $Gateway -and $Matches[1] -ne '-') { $Gateway = $Matches[1]; continue }
        if ($l -match '^(\d{1,3}(?:\.\d{1,3}){3}) ([0-9A-F:]{17})$') { $base[$Matches[1]] = $Matches[2] }
    }
} else { Write-ToolLog WARN "no baseline at $BaselinePath - only duplicate-MAC checks run (create one with -InitBaseline)" }
if (-not $Gateway -and -not $NeighborFile) { $Gateway = Get-DefaultGateway }

function ConvertTo-ArpFinding($Severity, $Check, $Ip, $Mac, $Detail) {
    [pscustomobject]@{ Severity = $Severity; Check = $Check; IP = $Ip; MAC = $Mac; Detail = $Detail }
}

function Invoke-ArpCheck {
    $table = @(Get-NeighborTable -Path $NeighborFile)
    $macOf = @{}; $ipsOf = @{}
    foreach ($n in $table) { $macOf[$n.IP] = $n.MAC; if (-not $ipsOf.ContainsKey($n.MAC)) { $ipsOf[$n.MAC] = @() }; $ipsOf[$n.MAC] += $n.IP }
    $gwMac = if ($Gateway -and $macOf.ContainsKey($Gateway)) { $macOf[$Gateway] } else { '' }
    $out = @()
    foreach ($mac in $ipsOf.Keys) {
        $ips = @($ipsOf[$mac] | Sort-Object { ConvertTo-UInt32 $_ })
        if ($ips.Count -gt 1) {
            if ($gwMac -and $mac -eq $gwMac) { $out += ConvertTo-ArpFinding 'HIGH' 'GATEWAY_MAC_CLAIMED' $Gateway $mac "gateway MAC also used by: $($ips -join ' ') ($(Get-MacVendor $mac $oui))" }
            else { $out += ConvertTo-ArpFinding 'MEDIUM' 'DUPLICATE_MAC' ($ips -join ',') $mac "one MAC answers for several IPs ($(Get-MacVendor $mac $oui))" }
        }
    }
    if ($Gateway) {
        if (-not $gwMac) { $out += ConvertTo-ArpFinding 'INFO' 'GATEWAY_NOT_IN_TABLE' $Gateway '-' 'gateway has no ARP entry yet (no recent traffic)' }
        elseif ($base.ContainsKey($Gateway) -and $base[$Gateway] -ne $gwMac) {
            $out += ConvertTo-ArpFinding 'HIGH' 'GATEWAY_MAC_CHANGED' $Gateway $gwMac "was $($base[$Gateway]) ($(Get-MacVendor $base[$Gateway] $oui)), now $gwMac ($(Get-MacVendor $gwMac $oui))"
        }
    }
    foreach ($ip in $macOf.Keys) {
        if ($ip -eq $Gateway) { continue }
        if (-not $base.ContainsKey($ip)) { if ($base.Count) { $out += ConvertTo-ArpFinding 'INFO' 'NEW_HOST' $ip $macOf[$ip] "not in baseline ($(Get-MacVendor $macOf[$ip] $oui))" } }
        elseif ($base[$ip] -ne $macOf[$ip]) { $out += ConvertTo-ArpFinding 'MEDIUM' 'MAC_CHANGED' $ip $macOf[$ip] "was $($base[$ip])" }
    }
    $rank = @{ HIGH = 1; MEDIUM = 2; INFO = 3 }
    return @($out | Sort-Object { $rank[$_.Severity] }, Check, IP)
}

Write-ToolLog INFO "checking ARP table (gateway $(if ($Gateway) { $Gateway } else { 'unknown' }), baseline $($base.Count) entries)"
$seen = @{}; $run = 0; $last = @(); $high = $false
while ($true) {
    $run++
    $last = Invoke-ArpCheck
    foreach ($f in $last) {
        if ($f.Severity -eq 'HIGH') { $high = $true }
        $key = "$($f.Check)|$($f.IP)|$($f.MAC)"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $lvl = if ($f.Severity -eq 'INFO') { 'INFO' } else { 'WARN' }
        Write-ToolLog $lvl "[$($f.Severity)] $($f.Check) $($f.IP) $($f.MAC) - $($f.Detail)"
    }
    if (-not $last.Count) { Write-ToolLog INFO "check ${run}: no ARP anomalies" }
    if (-not $WatchSeconds) { break }
    if ($Count -and $run -ge $Count) { break }
    Start-Sleep -Seconds $WatchSeconds
}

$summary = [ordered]@{ High = @($last | Where-Object Severity -eq 'HIGH').Count; Medium = @($last | Where-Object Severity -eq 'MEDIUM').Count
    Gateway = $(if ($Gateway) { $Gateway } else { '-' }); 'Baseline entries' = $base.Count }
foreach ($o in $OutputPath) { Export-ToolReport -Path $o -Rows $last -Title 'ARP spoofing check' -Summary $summary -ToolName 'arp-spoof-detector.ps1' }
$last
if ($high) { exit 1 }
