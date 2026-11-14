<#
.SYNOPSIS
    Discover live hosts on a local IPv4 subnet.

.DESCRIPTION
    scan-network.ps1 ping-sweeps a CIDR range, resolves reverse-DNS hostnames
    and runs a quick TCP connect check of common ports on every live host.
    Probes run in parallel through a runspace pool, so the script works on
    Windows PowerShell 5.1 and PowerShell 7+ without extra modules.

    A host counts as "live" when it answers ICMP echo OR any TCP probe
    (an actively refused connection still proves the host is up).

    Author : Arnold Rurangwa - MIT License
    Legal  : Only scan networks you own or are explicitly authorised to test.

.PARAMETER Target
    Network in CIDR notation (192.168.1.0/24) or a single IPv4 address.
    Prefixes from /16 to /32 are accepted.

.PARAMETER Ports
    Ports to check on live hosts. Default: 22,53,80,135,139,443,445,3389,8080.

.PARAMETER Threads
    Number of parallel probes (1-256). Default: 64.

.PARAMETER TimeoutMs
    Per-probe timeout in milliseconds (100-30000). Default: 1000.

.PARAMETER CsvPath
    Optional path of a CSV file to write the results to.

.PARAMETER NoPortScan
    Discovery only; skip the port check.

.EXAMPLE
    .\scan-network.ps1 -Target 192.168.1.0/24

.EXAMPLE
    .\scan-network.ps1 -Target 10.0.0.0/28 -Ports 22,80 -Threads 32 -CsvPath lan.csv

.NOTES
    Requirements: Windows PowerShell 5.1+ or PowerShell 7+. No admin rights needed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$')]
    [string]$Target,

    [ValidateRange(1, 65535)]
    [int[]]$Ports = @(22, 53, 80, 135, 139, 443, 445, 3389, 8080),

    [ValidateRange(1, 256)]
    [int]$Threads = 64,

    [ValidateRange(100, 30000)]
    [int]$TimeoutMs = 1000,

    [string]$CsvPath,

    [switch]$NoPortScan
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---- CIDR helpers ------------------------------------------------------------
function ConvertTo-UInt32 {
    param([string]$Ip)
    $bytes = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes()
    [Array]::Reverse($bytes)                       # network -> host byte order
    return [BitConverter]::ToUInt32($bytes, 0)
}

function ConvertTo-IpString {
    param([uint32]$Value)
    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

$parts  = $Target.Split('/')
$base   = $parts[0]
$prefix = 32
if ($parts.Count -eq 2) { $prefix = [int]$parts[1] }

foreach ($octet in $base.Split('.')) {
    if ([int]$octet -gt 255) { throw "Invalid IPv4 address: $base" }
}
if ($prefix -lt 16 -or $prefix -gt 32) { throw 'Prefix must be between /16 and /32.' }

$baseInt = ConvertTo-UInt32 $base
# Plain integer maths avoids signed-literal pitfalls (0xFFFFFFFF is -1 in PS).
$block   = [uint64][math]::Pow(2, 32 - $prefix)     # addresses in the block
$network = [uint64]$baseInt - ([uint64]$baseInt % $block)
$bcast   = $network + $block - 1
if ($prefix -ge 31) { $first = $network; $last = $bcast }
else { $first = $network + 1; $last = $bcast - 1 }
$count = [int]($last - $first + 1)
if ($count -gt 65536) { throw "Range too large ($count hosts)." }

# ---- per-host probe (runs inside a runspace) ----------------------------------
$probe = {
    param([string]$Ip, [int[]]$Ports, [int]$TimeoutMs, [bool]$NoPortScan)

    # Returns 'open', 'closed' (refused => host is up) or 'filtered'.
    function Test-Tcp([string]$HostIp, [int]$Port, [int]$Ms) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $async = $client.BeginConnect($HostIp, $Port, $null, $null)
            if (-not $async.AsyncWaitHandle.WaitOne($Ms)) { return 'filtered' }
            try { $client.EndConnect($async); return 'open' }
            catch {
                $inner = $_.Exception.InnerException
                if ($inner -is [System.Net.Sockets.SocketException] -and
                    $inner.SocketErrorCode -eq 'ConnectionRefused') { return 'closed' }
                return 'filtered'
            }
        }
        finally { $client.Close() }
    }

    $alive = $false
    try {
        $reply = (New-Object System.Net.NetworkInformation.Ping).Send($Ip, $TimeoutMs)
        $alive = ($reply.Status -eq 'Success')
    } catch { $alive = $false }   # ICMP may need privileges on some OSes

    if (-not $alive) {
        foreach ($p in 80, 443, 22, 445) {
            if ((Test-Tcp $Ip $p $TimeoutMs) -ne 'filtered') { $alive = $true; break }
        }
    }
    if (-not $alive) { return }

    $name = '-'
    try { $name = [System.Net.Dns]::GetHostEntry($Ip).HostName } catch { $name = '-' }
    if ($name -eq $Ip) { $name = '-' }

    $open = @()
    if (-not $NoPortScan) {
        foreach ($p in $Ports) { if ((Test-Tcp $Ip $p $TimeoutMs) -eq 'open') { $open += $p } }
    }
    [pscustomobject]@{
        IP        = $Ip
        Hostname  = $name
        OpenPorts = ($open -join ';')
        SortKey   = [uint32]0
    }
}

# ---- run the sweep -------------------------------------------------------------
Write-Host ("Scanning {0} - {1} ({2} hosts, {3} threads, timeout {4} ms)" -f `
    (ConvertTo-IpString $first), (ConvertTo-IpString $last), $count, $Threads, $TimeoutMs)
$started = Get-Date

$pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads)
$pool.Open()
$jobs = New-Object System.Collections.Generic.List[object]
try {
    for ($i = [uint64]$first; $i -le $last; $i++) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($probe).AddArgument((ConvertTo-IpString ([uint32]$i))).AddArgument($Ports).AddArgument($TimeoutMs).AddArgument([bool]$NoPortScan)
        $jobs.Add([pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() })
    }

    $results = New-Object System.Collections.Generic.List[object]
    $done = 0
    foreach ($job in $jobs) {
        foreach ($r in $job.PS.EndInvoke($job.Handle)) {
            $r.SortKey = ConvertTo-UInt32 $r.IP
            $results.Add($r)
        }
        $job.PS.Dispose()
        $done++
        if ($count -gt 1) {
            Write-Progress -Activity 'Scanning' -Status "$done / $count" -PercentComplete ($done * 100 / $count)
        }
    }
    Write-Progress -Activity 'Scanning' -Completed
}
finally {
    $pool.Close(); $pool.Dispose()
}

$sorted = @($results | Sort-Object SortKey | Select-Object IP, Hostname, @{ n = 'OpenPorts'; e = { if ($_.OpenPorts) { $_.OpenPorts } else { '-' } } })
$sorted | Format-Table -AutoSize | Out-String | Write-Host
$elapsed = [int]((Get-Date) - $started).TotalSeconds
Write-Host ("{0} live host(s) found in {1}s." -f $sorted.Count, $elapsed)

if ($CsvPath) {
    $sorted | Export-Csv -Path $CsvPath -NoTypeInformation
    Write-Host "CSV written to $CsvPath"
}

# Emit objects so the output can be piped (e.g. | Where-Object OpenPorts -match 22).
$sorted
