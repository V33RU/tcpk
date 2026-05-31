function Test-TcpkAntiInjection {
<#
.SYNOPSIS
    J03. Anti-injection / process-hollowing detection markers.

.DESCRIPTION
    Surfaces references to APIs that anti-injection code typically calls
    (NtSetInformationProcess, SetProcessMitigationPolicy with
    ProcessImageLoadPolicy, PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES).
    INFO only -- presence indicates hardening intent; not vulnerability.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $markers = @(
        'SetProcessMitigationPolicy','ProcessImageLoadPolicy',
        'PROCESS_CREATION_MITIGATION_POLICY','NtSetInformationProcess',
        'BlockNonMicrosoftBinaries','PreferSystem32Images'
    )
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        $hits = @()
        foreach ($m in $markers) {
            if ($text.Contains($m)) { $hits += $m }
        }
        if ($hits.Count -eq 0) { continue }
        New-TcpkFinding -Module 'antidebug' -RuleId 'antiinjection.markers' `
            -Severity 'INFO' -Confidence 'Inferred' `
            -Title "$($pe.Name) references anti-injection / mitigation APIs" `
            -File $pe.FullName -Evidence ($hits -join ', ') `
            -Description 'Hardening signal; confirm in ILSpy that the policy is set at startup before any LoadLibrary.'
    }
}
