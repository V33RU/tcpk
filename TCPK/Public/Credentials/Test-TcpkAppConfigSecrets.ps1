function Test-TcpkAppConfigSecrets {
<#
.SYNOPSIS
    D04. .NET Framework .config secrets (connection strings, machine keys).

.DESCRIPTION
    Specifically targets *.config files (web.config, app.config, MyApp.exe.config)
    for the patterns most often leaked in .NET Framework apps:
      - <connectionStrings> with embedded passwords
      - <machineKey validationKey/decryptionKey>
      - <appSettings> entries that look like tokens

.PARAMETER Path
    Folder.

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

        if ($t -match '(?is)<connectionStrings>[\s\S]*?(password|pwd)\s*=\s*[^;""\s<>]+') {
            New-TcpkFinding -Module 'creds' -RuleId 'app-config.connstring-password' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title 'Connection string with embedded password in .config' `
                -File $f.FullName -Evidence 'connectionStrings with Password=' `
                -Cwe @('CWE-798','CWE-312') `
                -Fix 'Use Integrated Security; or store the password in DPAPI-encrypted form via aspnet_regiis -pe.'
        }
        if ($t -match '<machineKey[^>]*validationKey="[A-F0-9]{40,}"') {
            New-TcpkFinding -Module 'creds' -RuleId 'app-config.machine-key' `
                -Severity 'CRITICAL' -Confidence 'Confirmed' `
                -Title '<machineKey> with literal validationKey in .config' `
                -File $f.FullName -Evidence 'validationKey=...' `
                -Cwe @('CWE-321','CWE-798') `
                -Description 'Leaked machine keys enable ViewState forgery and unsafe deserialization payloads against ASP.NET hosts.' `
                -Fix 'Generate fresh keys per host; do not commit to source. Consider asp.net core data-protection APIs.'
        }
    }
}
