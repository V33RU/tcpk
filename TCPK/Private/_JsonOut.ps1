#requires -Version 5.1
# Shared JSON / SARIF / CycloneDX writer.
#
# WHY THIS EXISTS. Every writer used Set-Content -Encoding UTF8. On PowerShell 5.1 that
# encoding is utf-8-BOM, so every findings.json, sbom.cdx.json, report.sarif and coverage.json
# shipped by the tool started EF BB BF. Node's JSON.parse and Python's strict json.load reject
# it, so no external consumer could read the files, and every internal consumer reads through
# ConvertFrom-Json which strips the BOM silently, so none of the 156 test suites could ever
# have surfaced the defect. -Encoding UTF8NoBOM is PS 6+, so callers have to route through
# System.IO.File with a UTF8Encoding($false).
#
# One helper and everything uses it, so a future consumer that needs a different encoding
# invariant has one place to change.

function Save-TcpkJson {
<#
.SYNOPSIS
    Write a value to a JSON file, UTF-8 without BOM.

.DESCRIPTION
    ConvertTo-Json then WriteAllText with a BOM-free UTF-8 encoding, resolving the path via
    GetUnresolvedProviderPathFromPSPath so a caller-relative path lands where the caller
    expects rather than in the module's directory.

    Never throws. On any failure a warning is written and the file is not created.

.PARAMETER Value
    Anything ConvertTo-Json accepts.

.PARAMETER Path
    Output file. May be relative to the current provider location.

.PARAMETER Depth
    Passed through to ConvertTo-Json. Default 8, matching the reports.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Value,
        [Parameter(Mandatory)][string]$Path,
        [int]$Depth = 8
    )
    process {
        try {
            $json = $Value | ConvertTo-Json -Depth $Depth
            $abs = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
            $enc = New-Object System.Text.UTF8Encoding($false)
            [IO.File]::WriteAllText($abs, $json, $enc)
        } catch { Write-Warning "Save-TcpkJson: could not write $Path : $($_.Exception.Message)" }
    }
}

function Save-TcpkText {
<#
.SYNOPSIS
    Write already-serialized text to a file, UTF-8 without BOM.

.DESCRIPTION
    For callers that build the JSON string themselves (Export-TcpkReportSarif does this
    to control the property order more tightly than ConvertTo-Json exposes).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Path
    )
    try {
        $abs = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        $enc = New-Object System.Text.UTF8Encoding($false)
        [IO.File]::WriteAllText($abs, $Text, $enc)
    } catch { Write-Warning "Save-TcpkText: could not write $Path : $($_.Exception.Message)" }
}

function Get-TcpkModuleVersion {
<#
.SYNOPSIS
    Runtime module version, so no writer hardcodes it and drifts.
#>
    try {
        $v = (Get-Module TCPK | Select-Object -First 1).Version
        if (-not $v -and $script:TcpkRoot) {
            $v = (Import-PowerShellDataFile -Path (Join-Path $script:TcpkRoot 'TCPK.psd1')).ModuleVersion
        }
        if ($v) { return "$v" }
    } catch { }
    return 'unknown'
}
