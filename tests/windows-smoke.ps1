<#
    Windows smoke test (CI runs it under Windows PowerShell 5.1 on windows-latest).
    Exercises the Windows code paths: Get-NetNeighbor, Get-NetRoute,
    Get-DnsClientServerAddress and the runspace scan against localhost.
#>
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
"PowerShell $($PSVersionTable.PSVersion) on $([Environment]::OSVersion.VersionString)"

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 18080)
$listener.Start()
try {
    $r = .\scan-network.ps1 -Target 127.0.0.1 -Ports 18080, 1 -OutputPath "$env:TEMP\ns.html", "$env:TEMP\ns.csv"
    if (-not ($r | Where-Object { $_.OpenPorts -eq '18080' })) { throw 'scan-network.ps1 did not report 18080 open' }
    'ok - scan-network.ps1 (runspaces, HTML + CSV report)'
} finally { $listener.Stop() }

Import-Module .\lib\NetTools.psm1 -Force
$n = @(Get-NeighborTable)
"ok - Get-NeighborTable read $($n.Count) live ARP entries"
"ok - default gateway: $(Get-DefaultGateway)"
$dns = @(Get-SystemDnsServer)
"ok - DNS servers: $($dns -join ', ')"

.\arp-spoof-detector.ps1 -InitBaseline -BaselinePath "$env:TEMP\arp.txt"
.\arp-spoof-detector.ps1 -BaselinePath "$env:TEMP\arp.txt" -OutputPath "$env:TEMP\arp.html" | Out-Null
'ok - arp-spoof-detector.ps1 against the live table'

.\dns-analyzer.ps1 -Domains example.com -OutputPath "$env:TEMP\dns.html" | Out-Null
"ok - dns-analyzer.ps1 live run (exit $LASTEXITCODE; findings depend on the runner's DNS)"
$global:LASTEXITCODE = 0
'Windows smoke test passed.'
