<#
    lib/NetTools.psm1 - network helpers shared by scan-network.ps1,
    arp-spoof-detector.ps1 and dns-analyzer.ps1.
    Windows PowerShell 5.1 and PowerShell 7+ (Windows, Linux, macOS).
    Author: Arnold Rurangwa - MIT License
#>
Set-StrictMode -Version 2.0

function ConvertTo-UInt32 {
    [OutputType([uint32])]
    param([Parameter(Mandatory)][string]$Ip)
    $bytes = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes()
    [Array]::Reverse($bytes)                         # network -> host byte order
    return [BitConverter]::ToUInt32($bytes, 0)
}

function ConvertTo-IpString {
    [OutputType([string])]
    param([Parameter(Mandatory)][uint32]$Value)
    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

function Get-CidrRange {
    <# .SYNOPSIS Expand "a.b.c.d/nn" (/16-/32) into First/Last/Count (host order integers). #>
    param([Parameter(Mandatory)][string]$Cidr)
    if ($Cidr -notmatch '^(\d{1,3}(\.\d{1,3}){3})(/(\d{1,2}))?$') { throw "Invalid target '$Cidr' (expected 192.168.1.0/24 or one IPv4)" }
    $base = $Matches[1]
    $prefix = if ($Matches[4]) { [int]$Matches[4] } else { 32 }
    foreach ($o in $base.Split('.')) { if ([int]$o -gt 255) { throw "Invalid IPv4 address: $base" } }
    if ($prefix -lt 16 -or $prefix -gt 32) { throw 'Prefix must be between /16 and /32.' }
    $baseInt = ConvertTo-UInt32 $base
    $block = [uint64][math]::Pow(2, 32 - $prefix)    # integer maths: 0xFFFFFFFF is -1 in PS
    $network = [uint64]$baseInt - ([uint64]$baseInt % $block)
    $bcast = $network + $block - 1
    if ($prefix -ge 31) { $first = $network; $last = $bcast } else { $first = $network + 1; $last = $bcast - 1 }
    [pscustomobject]@{ First = [uint64]$first; Last = [uint64]$last; Count = [int]($last - $first + 1) }
}

function ConvertTo-NormalMac {
    [OutputType([string])]
    param([string]$Mac)
    if (-not $Mac) { return '' }
    $m = $Mac.ToUpper().Replace('-', ':')
    if ($m -match '^[0-9A-F]{4}\.[0-9A-F]{4}\.[0-9A-F]{4}$') {
        $h = $m.Replace('.', ''); $m = ($h -split '(..)' | Where-Object { $_ }) -join ':'
    }
    return $m
}

function ConvertFrom-NeighborText {
    <#
    .SYNOPSIS Parse `arp -a` (Windows/Linux), `ip neigh` or /proc/net/arp text into IP/MAC objects.
    #>
    param([string[]]$Lines)
    foreach ($line in $Lines) {
        $ip = $null; $mac = $null
        if ($line -match '^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\w+)') {
            $ip = $Matches[1]; $mac = $Matches[2]                        # Windows arp -a
        } elseif ($line -match '^(\d{1,3}(?:\.\d{1,3}){3})\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{17})\s+(\S+)') {
            if ($Matches[3] -notin 'FAILED', 'INCOMPLETE') { $ip = $Matches[1]; $mac = $Matches[2] }   # ip neigh
        } elseif ($line -match '^(\d{1,3}(?:\.\d{1,3}){3})\s+0x\w+\s+(0x\w+)\s+([0-9a-fA-F:]{17})') {
            if ($Matches[2] -ne '0x0') { $ip = $Matches[1]; $mac = $Matches[3] }   # /proc/net/arp
        } elseif ($line -match '\((\d{1,3}(?:\.\d{1,3}){3})\) at ([0-9a-fA-F:]{17})') {
            $ip = $Matches[1]; $mac = $Matches[2]                        # BSD/Linux arp -an
        }
        if ($ip -and $mac) {
            $n = ConvertTo-NormalMac $mac
            # skip broadcast / multicast entries that Windows lists as "static"
            if ($n -ne 'FF:FF:FF:FF:FF:FF' -and $n -notmatch '^01:00:5E') { [pscustomobject]@{ IP = $ip; MAC = $n } }
        }
    }
}

function Get-NeighborTable {
    <# .SYNOPSIS Current IPv4 neighbour (ARP) table, or the parsed content of a saved dump. #>
    param([string]$Path)
    if ($Path) { return @(ConvertFrom-NeighborText (Get-Content -LiteralPath $Path)) }
    if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
        return @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.State -in 'Reachable', 'Stale', 'Delay', 'Probe', 'Permanent' -and $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' } |
                ForEach-Object { [pscustomobject]@{ IP = $_.IPAddress; MAC = (ConvertTo-NormalMac $_.LinkLayerAddress) } } |
                Where-Object { $_.MAC -ne 'FF:FF:FF:FF:FF:FF' -and $_.MAC -notmatch '^01:00:5E' })
    }
    if (Get-Command ip -ErrorAction SilentlyContinue) { return @(ConvertFrom-NeighborText (& ip -4 neigh show 2>$null)) }
    if (Test-Path /proc/net/arp) { return @(ConvertFrom-NeighborText (Get-Content /proc/net/arp)) }
    if (Get-Command arp -ErrorAction SilentlyContinue) { return @(ConvertFrom-NeighborText (& arp -a 2>$null)) }
    return @()
}

function Get-DefaultGateway {
    [OutputType([string])]
    param()
    if (Get-Command Get-NetRoute -ErrorAction SilentlyContinue) {
        $r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
        if ($r) { return $r.NextHop }
    }
    if (Get-Command ip -ErrorAction SilentlyContinue) {
        $line = & ip -4 route show default 2>$null | Select-Object -First 1
        if ($line -match 'via (\d{1,3}(\.\d{1,3}){3})') { return $Matches[1] }
    }
    return ''
}

function Import-OuiTable {
    <# .SYNOPSIS Load a prefix,vendor CSV into a hashtable keyed by "AA:BB:CC". #>
    [OutputType([hashtable])]
    param([string]$Path)
    $t = @{}
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        foreach ($row in Import-Csv -LiteralPath $Path) { $t[$row.prefix.ToUpper()] = $row.vendor }
    }
    return $t
}

function Get-MacVendor {
    [OutputType([string])]
    param([string]$Mac, [hashtable]$Oui)
    $m = ConvertTo-NormalMac $Mac
    if ($m -notmatch '^([0-9A-F]{2}:){5}[0-9A-F]{2}$') { return '-' }
    if ($m.Substring(1, 1) -match '[26AE]') { return 'random/local MAC' }   # locally administered bit
    $p = $m.Substring(0, 8)
    if ($Oui -and $Oui.ContainsKey($p)) { return $Oui[$p] }
    return '-'
}

function Test-PrivateOrBogon {
    <# .SYNOPSIS True for RFC1918, loopback, link-local, CGNAT, documentation, benchmark and multicast/reserved IPv4. #>
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Ip)
    $o = $Ip.Split('.') | ForEach-Object { [int]$_ }
    if ($o[0] -in 0, 10, 127 -or $o[0] -ge 224) { return $true }
    if ($o[0] -eq 169 -and $o[1] -eq 254) { return $true }
    if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return $true }
    if ($o[0] -eq 192 -and $o[1] -eq 168) { return $true }
    if ($o[0] -eq 100 -and $o[1] -ge 64 -and $o[1] -le 127) { return $true }
    if ($Ip -like '192.0.2.*' -or $Ip -like '198.51.100.*' -or $Ip -like '203.0.113.*') { return $true }
    if ($o[0] -eq 198 -and $o[1] -in 18, 19) { return $true }
    return $false
}

function Invoke-RawDnsQuery {
    <#
    .SYNOPSIS Send one DNS A query over UDP to a specific server (pure .NET, any OS).
    .DESCRIPTION Builds the RFC 1035 packet by hand with the RD and AD bits set, so
                 the reply also tells whether the server validated DNSSEC.
    .OUTPUTS Object with Status (NOERROR/NXDOMAIN/SERVFAIL/.../ERROR), Addresses and AD.
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Server, [int]$TimeoutMs = 2000, [ValidateRange(1, 65535)][int]$Port = 53)
    $id = Get-Random -Minimum 1 -Maximum 65535
    $q = New-Object System.Collections.Generic.List[byte]
    $hi = [byte](($id -shr 8) -band 255); $lo = [byte]($id -band 255)
    $q.AddRange([byte[]]@($hi, $lo, 0x01, 0x20, 0, 1, 0, 0, 0, 0, 0, 0))  # RD + AD flags, 1 question
    foreach ($label in $Name.TrimEnd('.').Split('.')) {
        $b = [System.Text.Encoding]::ASCII.GetBytes($label)
        $q.Add([byte]$b.Length); $q.AddRange($b)
    }
    $q.AddRange([byte[]](0, 0, 1, 0, 1))                                 # end of name, QTYPE A, QCLASS IN
    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Connect($Server, $Port)
        [void]$udp.Send($q.ToArray(), $q.Count)
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $r = $udp.Receive([ref]$remote)
    } catch {
        return [pscustomobject]@{ Status = 'ERROR'; Addresses = @(); AD = $false }
    } finally { $udp.Close() }
    if ($r.Length -lt 12 -or (($r[0] * 256) + $r[1]) -ne $id) { return [pscustomobject]@{ Status = 'ERROR'; Addresses = @(); AD = $false } }
    $rcodes = @{ 0 = 'NOERROR'; 1 = 'FORMERR'; 2 = 'SERVFAIL'; 3 = 'NXDOMAIN'; 4 = 'NOTIMP'; 5 = 'REFUSED' }
    $rc = $r[3] -band 0x0F
    $status = if ($rcodes.ContainsKey([int]$rc)) { $rcodes[[int]$rc] } else { "RCODE$rc" }
    $ad = [bool]($r[3] -band 0x20)
    $qd = $r[4] * 256 + $r[5]; $an = $r[6] * 256 + $r[7]
    $pos = 12
    # skip_name: labels end with 0, or a 2-byte compression pointer (top bits 11)
    $skipName = { param($buf, $p) while ($p -lt $buf.Length) { $len = $buf[$p]; if ($len -eq 0) { return $p + 1 }; if (($len -band 0xC0) -eq 0xC0) { return $p + 2 }; $p += $len + 1 }; return $p }
    for ($i = 0; $i -lt $qd; $i++) { $pos = (& $skipName $r $pos) + 4 }
    $ips = @()
    for ($i = 0; $i -lt $an -and $pos -lt $r.Length; $i++) {
        $pos = & $skipName $r $pos
        if ($pos + 10 -gt $r.Length) { break }
        $type = $r[$pos] * 256 + $r[$pos + 1]
        $rdlen = $r[$pos + 8] * 256 + $r[$pos + 9]
        $pos += 10
        if ($type -eq 1 -and $rdlen -eq 4) { $ips += ('{0}.{1}.{2}.{3}' -f $r[$pos], $r[$pos + 1], $r[$pos + 2], $r[$pos + 3]) }
        $pos += $rdlen
    }
    [pscustomobject]@{ Status = $status; Addresses = @($ips | Sort-Object { ConvertTo-UInt32 $_ } -Unique); AD = $ad }
}

function Get-SystemDnsServer {
    <# .SYNOPSIS IPv4 DNS servers configured on this machine. #>
    [OutputType([string[]])]
    param([string]$ResolvFile = '/etc/resolv.conf')
    if (Get-Command Get-DnsClientServerAddress -ErrorAction SilentlyContinue) {
        return @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } | Select-Object -Unique)
    }
    if (Test-Path -LiteralPath $ResolvFile) {
        return @(Get-Content -LiteralPath $ResolvFile | Where-Object { $_ -match '^\s*nameserver\s+(\d{1,3}(\.\d{1,3}){3})' } | ForEach-Object { ($_ -split '\s+')[1] })
    }
    return @()
}

Export-ModuleMember -Function ConvertTo-UInt32, ConvertTo-IpString, Get-CidrRange, ConvertTo-NormalMac, ConvertFrom-NeighborText,
Get-NeighborTable, Get-DefaultGateway, Import-OuiTable, Get-MacVendor, Test-PrivateOrBogon, Invoke-RawDnsQuery, Get-SystemDnsServer
