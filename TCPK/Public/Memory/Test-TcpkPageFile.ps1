function Test-TcpkPageFile {
<#
.SYNOPSIS
    I02. Page file / hibernation file secrecy hygiene.

.DESCRIPTION
    Surfaces whether the page file is cleared at shutdown (ClearPageFileAtShutdown
    DWORD under SessionManager\Memory Management) and whether hibernation is
    enabled (hiberfil.sys present). Page file and hiberfile are read-restricted
    by ACL but the disk image of either may contain copies of in-memory
    secrets.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param()

    if (-not (Assert-TcpkWindows 'Test-TcpkPageFile')) { return }

    $memKey = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management'
    $clear = (Get-ItemProperty -Path $memKey -ErrorAction SilentlyContinue).ClearPageFileAtShutdown
    if ($clear -ne 1) {
        New-TcpkFinding -Module 'memory' -RuleId 'pagefile.no-clear-at-shutdown' `
            -Severity 'LOW' -Confidence 'Confirmed' `
            -Title 'Pagefile is NOT cleared at shutdown' `
            -File $memKey -Evidence "ClearPageFileAtShutdown=$clear" `
            -Cwe @('CWE-316') `
            -Description 'The pagefile may contain copies of in-memory data from running processes after a clean shutdown.' `
            -Fix 'Set ClearPageFileAtShutdown=1 in the registry (or via Local Security Policy: Shutdown: Clear virtual memory pagefile).'
    }

    $hiber = "$env:SystemDrive\hiberfil.sys"
    if (Test-Path -LiteralPath $hiber) {
        $info = Get-Item -LiteralPath $hiber -Force -ErrorAction SilentlyContinue
        if ($info) {
            New-TcpkFinding -Module 'memory' -RuleId 'pagefile.hiberfile-present' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title 'hiberfil.sys present (hibernation enabled)' `
                -File $hiber -Evidence "size=$([int]($info.Length/1MB)) MB" `
                -Description 'hiberfil.sys holds a compressed image of RAM. Any in-memory secret can be present.'
        }
    }
}
