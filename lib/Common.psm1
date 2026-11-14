<#
    lib/Common.psm1 - shared helpers for the PowerShell tools in this repository.
    Works on Windows PowerShell 5.1 and PowerShell 7+ (Windows, Linux, macOS).

    Provides: levelled logging (console + optional log file), a safe KEY=VALUE
    config loader, CSV/JSON/self-contained HTML report export, a runspace-pool
    parallel runner and platform/elevation checks.
    Author: Arnold Rurangwa - MIT License
#>
Set-StrictMode -Version 2.0

$script:LogLevel = 'INFO'
$script:LogFile = $null
$script:Levels = @{ DEBUG = 10; INFO = 20; WARN = 30; ERROR = 40 }

function Set-ToolLogging {
    <# .SYNOPSIS Configure the minimum log level and an optional log file. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')][string]$Level = 'INFO', [string]$Path)
    if ($PSCmdlet.ShouldProcess('logging', 'configure')) {
        $script:LogLevel = $Level
        $script:LogFile = if ($Path) { $Path } else { $null }
    }
}

function Write-ToolLog {
    <# .SYNOPSIS Write a timestamped, levelled log line to the console (host) and the log file. #>
    [CmdletBinding()]
    param([ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')][string]$Level = 'INFO', [Parameter(Mandatory)][string]$Message)
    if ($script:Levels[$Level] -lt $script:Levels[$script:LogLevel]) { return }
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz'), $Level, $Message
    if ($script:LogFile) {
        try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 } catch { Write-Verbose "log file write failed: $_" }
    }
    $colour = switch ($Level) { 'ERROR' { 'Red' } 'WARN' { 'Yellow' } 'DEBUG' { 'DarkGray' } default { 'Gray' } }
    if ($Message.StartsWith('[HIGH]') -or $Message.StartsWith('[FAIL]')) { $colour = 'Red' }   # findings stand out
    Write-Host $line -ForegroundColor $colour
}

function Import-ToolConfig {
    <#
    .SYNOPSIS Read a KEY=VALUE config file (the same file the bash tools use).
    .DESCRIPTION Lines starting with # or ; are comments, as is " # ..." after an
                 unquoted value. Quotes around values are stripped. Returns a hashtable; nothing is executed.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Config file not found: $Path" }
    $cfg = @{}
    $n = 0
    foreach ($raw in Get-Content -LiteralPath $Path) {
        $n++
        $line = $raw.Trim()
        if ($line -eq '' -or $line.StartsWith('#') -or $line.StartsWith(';')) { continue }
        if ($line -match '^([A-Z_][A-Z0-9_]*)\s*=\s*(.*)$') {
            $key = $Matches[1]; $val = $Matches[2].Trim()
            if ($val -match '^"([^"]*)"' -or $val -match "^'([^']*)'") { $val = $Matches[1] }
            else { $val = ($val -replace '(^|\s+)#.*$', '').Trim() }       # strip "  # comment"
            $cfg[$key] = $val
        } else { Write-ToolLog WARN "${Path}:${n}: ignored line (expected KEY=VALUE)" }
    }
    return $cfg
}

function Get-ConfigValue {
    <# .SYNOPSIS Return $Config[$Key] or a default when the key is missing/empty. #>
    param([hashtable]$Config, [string]$Key, $Default)
    if ($Config -and $Config.ContainsKey($Key) -and "$($Config[$Key])" -ne '') { return $Config[$Key] }
    return $Default
}

function ConvertTo-HtmlEncoded {
    param([AllowNull()][object]$Text)
    if ($null -eq $Text) { return '' }
    return ("$Text").Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function ConvertTo-ToolHtml {
    <#
    .SYNOPSIS Build a self-contained HTML report (no JavaScript, no CDN).
    .PARAMETER Summary Ordered dictionary of label => value shown as cards.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Title, [object[]]$Rows = @(), [System.Collections.IDictionary]$Summary, [string]$ToolName = 'tool')
    $sb = New-Object System.Text.StringBuilder
    $hostName = if ($env:REPORT_HOSTNAME) { $env:REPORT_HOSTNAME } else { [System.Net.Dns]::GetHostName() }
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
    [void]$sb.AppendLine("<title>$(ConvertTo-HtmlEncoded $Title)</title>")
    [void]$sb.AppendLine(@'
<style>
:root{--bg:#0f172a;--panel:#111827;--card:#1f2937;--text:#e5e7eb;--muted:#9ca3af;--line:#374151;--accent:#38bdf8}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;background:var(--bg);color:var(--text)}
header{padding:24px 32px;border-bottom:1px solid var(--line);background:var(--panel)}
h1{margin:0 0 4px;font-size:22px}header p{margin:0;color:var(--muted)}
main{padding:24px 32px}.cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:140px}
.card b{display:block;font-size:22px;color:var(--accent)}.card span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--card);color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:0}td{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px;overflow-wrap:break-word}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600}
.p-high,.p-fail,.p-critical,.p-alert,.p-error{background:#7f1d1d;color:#fecaca}.p-medium,.p-warn,.p-warning,.p-changed{background:#78350f;color:#fde68a}
.p-low,.p-info,.p-new{background:#1e3a8a;color:#bfdbfe}.p-pass,.p-ok,.p-open{background:#14532d;color:#bbf7d0}
footer{padding:16px 32px;color:var(--muted);font-size:12px}
</style></head><body>
'@)
    [void]$sb.AppendLine("<header><h1>$(ConvertTo-HtmlEncoded $Title)</h1><p>Host $(ConvertTo-HtmlEncoded $hostName) &middot; generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')</p></header><main>")
    if ($Summary -and $Summary.Count) {
        [void]$sb.AppendLine('<div class="cards">')
        foreach ($k in $Summary.Keys) {
            [void]$sb.AppendLine("<div class=""card""><b>$(ConvertTo-HtmlEncoded $Summary[$k])</b><span>$(ConvertTo-HtmlEncoded $k)</span></div>")
        }
        [void]$sb.AppendLine('</div>')
    }
    $Rows = @($Rows)
    if ($Rows.Count) {
        $cols = @($Rows[0].PSObject.Properties.Name)
        $sev = $cols | Where-Object { $_ -in 'Severity', 'Status', 'Level', 'State' } | Select-Object -First 1
        [void]$sb.Append('<table><thead><tr>')
        foreach ($c in $cols) { [void]$sb.Append("<th>$(ConvertTo-HtmlEncoded $c)</th>") }
        [void]$sb.AppendLine('</tr></thead><tbody>')
        foreach ($r in $Rows) {
            [void]$sb.Append('<tr>')
            foreach ($c in $cols) {
                $v = $r.$c
                if ($c -eq $sev) { [void]$sb.Append("<td><span class=""pill p-$(ConvertTo-HtmlEncoded ("$v".ToLower()))"">$(ConvertTo-HtmlEncoded $v)</span></td>") }
                else { [void]$sb.Append("<td>$(ConvertTo-HtmlEncoded $v)</td>") }
            }
            [void]$sb.AppendLine('</tr>')
        }
        [void]$sb.AppendLine('</tbody></table>')
    } else { [void]$sb.AppendLine('<p>No rows.</p>') }
    [void]$sb.AppendLine("</main><footer>Generated by $(ConvertTo-HtmlEncoded $ToolName) &middot; read-only report &middot; MIT License</footer></body></html>")
    return $sb.ToString()
}

function Export-ToolReport {
    <#
    .SYNOPSIS Export rows to CSV, JSON or HTML; the format comes from the file extension.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [object[]]$Rows = @(), [string]$Title = 'Report',
        [System.Collections.IDictionary]$Summary, [string]$ToolName = 'tool')
    $ext = [System.IO.Path]::GetExtension($Path).TrimStart('.').ToLower()
    switch ($ext) {
        'csv' { @($Rows) | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8 }
        'json' { ConvertTo-Json -InputObject @($Rows) -Depth 6 | Set-Content -LiteralPath $Path -Encoding UTF8 }
        { $_ -in 'html', 'htm' } { ConvertTo-ToolHtml -Title $Title -Rows $Rows -Summary $Summary -ToolName $ToolName | Set-Content -LiteralPath $Path -Encoding UTF8 }
        default { throw "Unknown report format '.$ext' (use .csv, .json or .html)" }
    }
    Write-ToolLog INFO "report written: $Path"
}

function Invoke-ToolParallel {
    <#
    .SYNOPSIS Run a script block for every input item on a runspace pool (PS 5.1 compatible).
    .DESCRIPTION The script block receives ($Item, $Arguments). It runs in its own
                 runspace, so it must be self-contained (define helpers inside it).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$InputObject, [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object]$ArgumentList, [ValidateRange(1, 512)][int]$Throttle = 32, [string]$Activity = 'Working')
    $pool = [RunspaceFactory]::CreateRunspacePool(1, $Throttle)
    $pool.Open()
    $jobs = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($item in $InputObject) {
            $ps = [PowerShell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($ScriptBlock).AddArgument($item).AddArgument($ArgumentList)
            $jobs.Add([pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() })
        }
        $done = 0
        foreach ($j in $jobs) {
            try { $j.PS.EndInvoke($j.Handle) } catch { Write-ToolLog WARN "worker failed: $($_.Exception.Message)" }
            $j.PS.Dispose()
            $done++
            if ($jobs.Count -gt 1) { Write-Progress -Activity $Activity -Status "$done / $($jobs.Count)" -PercentComplete ($done * 100 / $jobs.Count) }
        }
        Write-Progress -Activity $Activity -Completed
    } finally { $pool.Close(); $pool.Dispose() }
}

function Test-ToolIsWindows {
    <# .SYNOPSIS True on Windows (works on 5.1 where $IsWindows does not exist). #>
    [OutputType([bool])]
    param()
    return ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
}

function Test-ToolIsAdmin {
    <# .SYNOPSIS True when the session is elevated (Windows) or root (Linux/macOS). #>
    [OutputType([bool])]
    param()
    if (Test-ToolIsWindows) {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    try { return ((& id -u) -eq '0') } catch { return $false }
}

Export-ModuleMember -Function Set-ToolLogging, Write-ToolLog, Import-ToolConfig, Get-ConfigValue, ConvertTo-HtmlEncoded,
ConvertTo-ToolHtml, Export-ToolReport, Invoke-ToolParallel, Test-ToolIsWindows, Test-ToolIsAdmin
