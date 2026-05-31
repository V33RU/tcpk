function Test-TcpkWcfConfig {
<#
.SYNOPSIS
    A14. Audit shipped WCF config files for cleartext / unauthenticated bindings.

.DESCRIPTION
    Walks *.config / app.config / web.config / *.exe.config files under the
    target path and flags:
      - BasicHttpBinding without transport security (cleartext SOAP)
      - <authentication mode="None"> declarations

.PARAMETER Path
    Folder. Single files ignored.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }

    $configs = Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -eq '.config' }

    foreach ($f in $configs) {
        try { $t = [IO.File]::ReadAllText($f.FullName) } catch { continue }

        if ($t -match '(?i)BasicHttpBinding' -and
            $t -notmatch '(?i)security mode="(Transport|TransportWithMessageCredential)') {
            New-TcpkFinding -Module 'static' -RuleId 'wcf.basichttp-cleartext' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "BasicHttpBinding without transport security (cleartext SOAP)" `
                -File $f.FullName -Evidence 'BasicHttpBinding without security mode=Transport' `
                -Cwe @('CWE-319') `
                -Fix 'Switch to WSHttpBinding or BasicHttpsBinding with Transport security.'
        }

        if ($t -match '<authentication[^>]*mode="None"') {
            New-TcpkFinding -Module 'static' -RuleId 'wcf.no-auth' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "WCF service declared with authentication mode='None'" `
                -File $f.FullName -Evidence 'authentication mode="None"' `
                -Cwe @('CWE-306')
        }
    }
}
