function Test-TcpkMailslotsAlpc {
<#
.SYNOPSIS
    E07. Mailslots and ALPC ports.

.DESCRIPTION
    Mailslots and ALPC are lower-profile IPC primitives. Mailslots are
    enumerable via \\.\mailslot\. ALPC ports are documented in the kernel
    object namespace; PowerShell cannot enumerate them without P/Invoke to
    NtQueryDirectoryObject -- this check surfaces the gap rather than
    pretending coverage.

.PARAMETER NameLike
    Substring to match against mailslot names.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$NameLike)

    if (-not (Assert-TcpkWindows 'Test-TcpkMailslotsAlpc')) { return }

    try {
        $slots = Get-ChildItem '\\.\mailslot\' -ErrorAction Stop
        $matched = $slots | Where-Object { $_.Name -like "*$NameLike*" }
        foreach ($s in $matched) {
            New-TcpkFinding -Module 'runtime' -RuleId 'mailslot.exists' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "Mailslot present: $($s.Name)" `
                -File $s.FullName -Evidence $s.Name `
                -Cwe @('CWE-668')
        }
    } catch {
        # Most systems do not have \\.\mailslot\ enumerable; skip silently
    }

    # ALPC: surface the coverage gap rather than pretending support
    New-TcpkFinding -Module 'runtime' -RuleId 'alpc.not-enumerated' `
        -Severity 'INFO' -Confidence 'Skipped' `
        -Title 'ALPC ports not enumerated' `
        -Evidence 'NtQueryDirectoryObject + P/Invoke required; not implemented.' `
        -Description 'For ALPC port enumeration, use SysInternals winobj.exe or Process Explorer (View -> Show Lower Pane -> Handles).'
}
