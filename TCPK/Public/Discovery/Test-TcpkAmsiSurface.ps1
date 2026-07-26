function Test-TcpkAmsiSurface {
<#
.SYNOPSIS
    Detect AMSI integration and flag the evasion surface.

.DESCRIPTION
    The Antimalware Scan Interface (AMSI) allows applications to send content
    to the installed AV for scanning.  When a thick client integrates AMSI
    (via AmsiInitialize / AmsiScanBuffer / AmsiScanString), it gains content
    scanning but also creates an evasion surface:

      - AmsiScanBuffer can be patched in-memory to always return AMSI_RESULT_CLEAN,
        completely blinding the application's malware scanning.
      - The AMSI provider DLL (amsi.dll) is loaded into the process and can be
        unloaded or hooked.
      - Process hollowing or debugging can disable the AMSI checks entirely.

    This scanner detects AMSI integration in first-party PEs and flags the
    resulting attack surface.  It does NOT flag .NET Framework / PowerShell
    host AMSI (which is system-level), only application-explicit integration.

    CrowdStrike VEH2 2025 reference: ETW/AMSI evasion as a thick-client
    attack primitive.

.PARAMETER Path
    File or directory to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $amsiApis = @(
        'AmsiInitialize', 'AmsiScanBuffer', 'AmsiScanString',
        'AmsiOpenSession', 'AmsiCloseSession', 'AmsiUninitialize',
        'AmsiResultIsMalware', 'AmsiNotifyOperation'
    )
    $amsiSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($a in $amsiApis) { [void]$amsiSet.Add($a) }

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        if ($pe.Name -match '(?i)^(amsi|mpclient|mpengine|mpsvc)') { continue }

        $info = Read-TcpkPe -Path $pe.FullName
        if (-not $info) { continue }

        $importsAmsi = $false
        foreach ($imp in @($info.Imports)) {
            if ($imp -and $imp.Trim() -match '(?i)^amsi\.dll$') {
                $importsAmsi = $true
                break
            }
        }

        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        $foundApis = @()
        foreach ($api in $amsiApis) {
            if ($text.Contains($api)) { $foundApis += $api }
        }

        if (-not $importsAmsi -and $foundApis.Count -eq 0) { continue }

        $hasScanBuffer = $foundApis -contains 'AmsiScanBuffer' -or $foundApis -contains 'AmsiScanString'
        $hasInit       = $foundApis -contains 'AmsiInitialize'

        $ev = @()
        if ($importsAmsi) { $ev += 'imports amsi.dll' }
        if ($foundApis.Count -gt 0) { $ev += "apis: $(($foundApis | Select-Object -First 6) -join ', ')" }

        if ($hasInit -or $importsAmsi) {
            New-TcpkFinding -Module 'static' -RuleId 'amsi.init-surface' `
                -Severity 'LOW' -Confidence $(if ($importsAmsi) { 'Confirmed' } else { 'Inferred' }) `
                -Title "AMSI integration detected in $($pe.Name)" `
                -File $pe.FullName `
                -Evidence ($ev -join '; ') `
                -Cwe @('CWE-693') `
                -Description ('This PE integrates AMSI (Antimalware Scan Interface) for content ' +
                    'scanning. While this provides malware detection, it creates an evasion surface: ' +
                    'an attacker with code execution can patch AmsiScanBuffer in memory to return ' +
                    'AMSI_RESULT_CLEAN, completely blinding the protection. The amsi.dll loaded into ' +
                    'the process can also be unloaded or hooked. (CrowdStrike VEH2 2025)') `
                -Fix 'Implement integrity checks on AMSI function pointers; use ETW canaries to detect AMSI unhooking; do not rely solely on AMSI for security-critical content validation.'
        }

        if ($hasScanBuffer) {
            New-TcpkFinding -Module 'static' -RuleId 'amsi.scan-buffer-patchable' `
                -Severity 'MEDIUM' -Confidence $(if ($importsAmsi) { 'Confirmed' } else { 'Inferred' }) `
                -Title "AMSI scan buffer is patchable in $($pe.Name)" `
                -File $pe.FullName `
                -Evidence ($ev -join '; ') `
                -Cwe @('CWE-693','CWE-345') `
                -Description ('The application calls AmsiScanBuffer/AmsiScanString to scan content. ' +
                    'This function is a well-known evasion target: a single 1-byte patch (mov eax, ' +
                    '0x80070057 -> mov eax, S_OK) at the function entry point causes all scans to ' +
                    'return clean. Any attacker with process-level code execution can perform this ' +
                    'patch before delivering malicious content.') `
                -Fix 'Validate scan results out-of-process or via a separate integrity channel; monitor for AMSI bypass indicators (ETW AmsiScanBuffer call frequency drops).'
        }
    }
}
