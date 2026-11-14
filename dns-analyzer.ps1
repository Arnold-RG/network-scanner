<#
.SYNOPSIS
    Spot DNS hijacking, poisoning and risky resolver settings.

.DESCRIPTION
    Compares the answer of the system's DNS server with several independent
    public resolvers for each domain, using hand-built DNS queries over UDP
    (pure .NET, so it works on Windows PowerShell 5.1 and PowerShell 7 on any OS):
      HIGH   PRIVATE_ANSWER     a public domain resolves to a private/reserved IP
      MEDIUM ANSWER_MISMATCH    system answer shares no IP with any public resolver
      MEDIUM NXDOMAIN_REDIRECT  a random, non-existent name resolves
      MEDIUM UNKNOWN_RESOLVER   a configured DNS server is a public IP that is not
                                a well-known resolver (DNS-changer malware sign)
      INFO   NO_DNSSEC          the system's server did not set the AD flag
      LOW    QUERY_FAILED       a resolver did not answer
    CDNs legitimately answer differently per location: ANSWER_MISMATCH is a
    heuristic to verify, not proof. Read-only: it only sends DNS queries.

    Author : Arnold Rurangwa - MIT License

.PARAMETER Domains
    Domains to check. Default: data/dns-check-domains.txt.
.PARAMETER Resolvers
    Public resolvers to compare with. Default 1.1.1.1, 8.8.8.8, 9.9.9.9.
.PARAMETER NoNxTest
    Skip the NXDOMAIN-redirection test.
.PARAMETER AnswersFile
    Analyse saved answers (domain<TAB>resolver<TAB>ips|NXDOMAIN) instead of querying.
.PARAMETER ResolvFile
    On Linux/macOS, the resolver config to audit. Default /etc/resolv.conf.
.PARAMETER OutputPath
    Report(s): .csv, .json or .html.

.EXAMPLE
    .\dns-analyzer.ps1
.EXAMPLE
    .\dns-analyzer.ps1 -Domains mybank.example, github.com -OutputPath dns.html
#>
[CmdletBinding()]
param(
    [string[]]$Domains,
    [string]$DomainsFile,
    [string[]]$Resolvers,
    [switch]$NoNxTest,
    [string]$AnswersFile,
    [string]$ResolvFile = '/etc/resolv.conf',
    [string[]]$OutputPath = @(),
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
if (-not $Resolvers) { $Resolvers = @((Get-ConfigValue $cfg 'DNS_RESOLVERS' '1.1.1.1,8.8.8.8,9.9.9.9').Split(',')) }
foreach ($r in $Resolvers) { if ($r -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { throw "Invalid resolver IP: $r" } }
if (-not $Domains -and -not $AnswersFile) {
    if (-not $DomainsFile) { $DomainsFile = Get-ConfigValue $cfg 'DNS_DOMAINS_FILE' 'data/dns-check-domains.txt' }
    if (-not [System.IO.Path]::IsPathRooted($DomainsFile) -and -not (Test-Path $DomainsFile)) { $DomainsFile = Join-Path $PSScriptRoot $DomainsFile }
    $Domains = @(Get-Content -LiteralPath $DomainsFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
}
if (-not $Domains) { $Domains = @() }
foreach ($d in $Domains) { if ($d -notmatch '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$') { throw "Invalid domain: $d" } }
$known = '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220', '94.140.14.14', '94.140.15.15', '76.76.2.0', '76.76.10.0'

# ---- configured servers ----------------------------------------------------------
if ($AnswersFile -or -not (Test-ToolIsWindows)) {
    $servers = @(if (Test-Path -LiteralPath $ResolvFile) { Get-Content -LiteralPath $ResolvFile | Where-Object { $_ -match '^\s*nameserver\s+\d' } | ForEach-Object { ($_ -split '\s+')[1] } })
} else { $servers = @(Get-SystemDnsServer) }
$systemServer = $servers | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1
Write-ToolLog INFO "configured DNS servers: $(if ($servers) { $servers -join ' ' } else { 'none' })"

$saved = @{}
if ($AnswersFile) {
    foreach ($l in Get-Content -LiteralPath $AnswersFile) {
        if ($l.StartsWith('#')) { continue }
        $p = $l.Split("`t"); if ($p.Count -ge 3) { $saved["$($p[0])|$($p[1])"] = $p[2] }
    }
}

# Resolve NAME via SERVER ('system' = first configured server): 'ip,ip' | NXDOMAIN | ERROR
function Get-Answer([string]$Name, [string]$Server) {
    if ($AnswersFile) { $k = "$Name|$Server"; if ($saved.ContainsKey($k)) { return $saved[$k] } else { return 'ERROR' } }
    $target = if ($Server -eq 'system') { $systemServer } else { $Server }
    if (-not $target) { return 'ERROR' }
    $res = Invoke-RawDnsQuery -Name $Name -Server $target
    if ($res.Status -eq 'NXDOMAIN') { return 'NXDOMAIN' }
    if ($res.Status -ne 'NOERROR' -or -not $res.Addresses.Count) { return 'ERROR' }
    return ($res.Addresses -join ',')
}

$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding($Severity, $Check, $Domain, $Resolver, $Answer, $Detail) {
    $findings.Add([pscustomobject]@{ Severity = $Severity; Check = $Check; Domain = $Domain; Resolver = $Resolver; Answer = $Answer; Detail = $Detail })
}

foreach ($ns in $servers) {
    if ($ns -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { continue }
    if (Test-PrivateOrBogon $ns) { Add-Finding 'PASS' 'NAMESERVER' '-' $ns '-' 'local/private resolver (router or corporate DNS)' }
    elseif ($known -contains $ns) { Add-Finding 'PASS' 'NAMESERVER' '-' $ns '-' 'well-known public resolver' }
    else { Add-Finding 'MEDIUM' 'UNKNOWN_RESOLVER' '-' $ns '-' 'public resolver that is not on the well-known list: confirm it is your ISP''s (DNS-changer malware sets rogue resolvers)' }
}

foreach ($d in $Domains) {
    $sys = Get-Answer $d 'system'
    Write-ToolLog DEBUG "$d system -> $sys"
    if ($sys -in 'ERROR', 'NXDOMAIN') { Add-Finding 'LOW' 'QUERY_FAILED' $d 'system' $sys 'system resolver gave no A record'; continue }
    $public = @(); $answered = 0
    foreach ($r in $Resolvers) {
        $a = Get-Answer $d $r
        if ($a -in 'ERROR', 'NXDOMAIN') { Add-Finding 'LOW' 'QUERY_FAILED' $d $r $a 'no answer (UDP/53 to public resolvers may be blocked)' }
        else { $answered++; $public += $a.Split(',') }
    }
    $sysIps = $sys.Split(',')
    $bad = @($sysIps | Where-Object { Test-PrivateOrBogon $_ })
    if ($bad.Count) { Add-Finding 'HIGH' 'PRIVATE_ANSWER' $d 'system' $sys "public domain resolves to private/reserved $($bad -join ' ') (hijack, DNS rebinding or a filtering proxy)" }
    elseif ($answered) {
        if (@($sysIps | Where-Object { $public -contains $_ }).Count) { Add-Finding 'PASS' 'CONSISTENT' $d 'system' $sys "matches $answered public resolver(s)" }
        else { Add-Finding 'MEDIUM' 'ANSWER_MISMATCH' $d 'system' $sys "no IP in common with public resolvers ($((@($public | Sort-Object -Unique)) -join ',')); CDNs can explain this - verify" }
    } else { Add-Finding 'INFO' 'UNVERIFIED' $d 'system' $sys 'no public resolver answered, nothing to compare with' }
}

if (-not $NoNxTest) {
    $nx = if ($AnswersFile) { 'NXTEST' } else { "nx-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())-$(Get-Random -Maximum 99999).example.com" }
    $a = Get-Answer $nx 'system'
    if ($a -in 'NXDOMAIN', 'ERROR') { Add-Finding 'PASS' 'NXDOMAIN_OK' $nx 'system' $a 'non-existent names are not redirected' }
    else { Add-Finding 'MEDIUM' 'NXDOMAIN_REDIRECT' $nx 'system' $a 'a random non-existent name resolved: the resolver rewrites NXDOMAIN' }
}

if (-not $AnswersFile -and $systemServer) {
    $sec = Invoke-RawDnsQuery -Name 'isc.org' -Server $systemServer
    if ($sec.AD) { Add-Finding 'PASS' 'DNSSEC' 'isc.org' $systemServer '-' 'system resolver validates DNSSEC (AD flag set)' }
    else { Add-Finding 'INFO' 'NO_DNSSEC' 'isc.org' $systemServer '-' 'system resolver did not set the AD flag; it may not validate DNSSEC' }
}

$rank = @{ HIGH = 1; MEDIUM = 2; LOW = 3; INFO = 4; PASS = 5 }
$rows = @($findings | Sort-Object { $rank[$_.Severity] })
$rows | Format-Table Severity, Check, Domain, Resolver, Answer -AutoSize | Out-String -Width 200 | Write-Host
foreach ($f in $rows | Where-Object { $_.Severity -in 'HIGH', 'MEDIUM' }) { Write-ToolLog WARN "$($f.Check) $($f.Domain) @$($f.Resolver): $($f.Detail)" }
$nh = @($rows | Where-Object Severity -eq 'HIGH').Count; $nm = @($rows | Where-Object Severity -eq 'MEDIUM').Count
Write-Host "Findings: $nh high, $nm medium ($($Domains.Count) domains, resolvers: $($Resolvers -join ' '))"
$summary = [ordered]@{ High = $nh; Medium = $nm; Domains = $Domains.Count; Resolvers = $Resolvers.Count }
foreach ($o in $OutputPath) { Export-ToolReport -Path $o -Rows $rows -Title 'DNS analysis' -Summary $summary -ToolName 'dns-analyzer.ps1' }
$rows
if ($nh) { exit 1 }
