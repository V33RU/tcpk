function Test-TcpkMsiCustomActions {
<#
.SYNOPSIS
    C28. MSI custom actions that run with elevated (SYSTEM) privileges.

.DESCRIPTION
    Opens every .msi file found under -Path using the Windows Installer COM API
    and reads the CustomAction table.

    Flags any action where:
      - The action is deferred (runs in the install script phase, Type & 0x400)
        OR the action is a commit or rollback action
      - AND the NoImpersonate bit is set (Type & 0x800), meaning the action runs
        as SYSTEM / the install service rather than the interactive user
      - AND the Target or Source field contains [PROPERTY] expansion syntax

    Such actions run as SYSTEM with user-influenced arguments -- the classic MSI
    privilege-escalation primitive. An attacker sets the property value on the
    msiexec command line (PUBLIC properties are settable by any caller) or via
    a user-writable registry key read during install.

    Requires the Windows Installer COM object (available on all Windows versions
    with the Windows Installer service). Does NOT run any custom actions.

    Also flags AlwaysInstallElevated if set in HKLM or HKCU, which makes all
    MSI installs run with SYSTEM rights regardless of context.

.PARAMETER Path
    Directory or single .msi file to audit.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkMsiCustomActions')) { return }

    # ------------------------------------------------------------------
    # AlwaysInstallElevated: if set in both HKLM and HKCU every MSI
    # installs as SYSTEM -- combine with any writable .msi for instant LPE.
    # ------------------------------------------------------------------
    $aieHklm = try { (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -EA Stop).AlwaysInstallElevated } catch { 0 }
    $aieHkcu = try { (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -EA Stop).AlwaysInstallElevated } catch { 0 }
    if ($aieHklm -eq 1 -and $aieHkcu -eq 1) {
        New-TcpkFinding -Module 'os' -RuleId 'msi.always-install-elevated' `
            -Severity 'CRITICAL' -Confidence 'Confirmed' `
            -Title 'AlwaysInstallElevated is enabled -- all MSI installs run as SYSTEM' `
            -File 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated' `
            -Evidence 'HKLM=1, HKCU=1' `
            -Cwe @('CWE-250','CWE-269') `
            -Description ('Both HKLM and HKCU AlwaysInstallElevated are set to 1. Any user on the ' +
                'machine can craft a minimal .msi that runs a custom action as SYSTEM, achieving ' +
                'full local privilege escalation. This is T1218.007 (MITRE ATT&CK).') `
            -Fix 'Disable AlwaysInstallElevated via GPO: Computer and User Configuration -> ' +
                'Administrative Templates -> Windows Components -> Windows Installer -> ' +
                '"Always install with elevated privileges" = Disabled.'
    }

    # ------------------------------------------------------------------
    # MSI file inspection.
    # Type bit flags (Windows Installer SDK):
    #   0x001-0x07F  basic action type (DLL=1, EXE=2, JScript=5, VBScript=6 ...)
    #   0x100        source is in Binary table
    #   0x200        source is a directory property (Target = DLL entry point / script text)
    #   0x300        source is a property
    #   0x400        deferred execution (runs in install script phase)
    #   0x800        NoImpersonate -- runs as SYSTEM / elevated token, not the user
    #   0x1000       rollback action
    #   0x2000       commit action
    #   0x4000       async deferred
    #   0x8000       async non-deferred
    # Security-relevant combination: (0x400 OR 0x1000 OR 0x2000) AND 0x800
    # means the action is scheduled deferred/rollback/commit AND runs without
    # impersonating the user (i.e., as the install token = SYSTEM on admin installs).
    # ------------------------------------------------------------------
    $msiFiles = if (Test-Path $Path -PathType Leaf) {
        @(Get-Item $Path)
    } else {
        @(Get-ChildItem -Path $Path -Recurse -Filter '*.msi' -File -ErrorAction SilentlyContinue |
          Select-Object -First 20)
    }
    if (-not $msiFiles.Count) { return }

    $installer = $null
    try { $installer = New-Object -ComObject WindowsInstaller.Installer -ErrorAction Stop } catch {
        New-TcpkSkippedFinding -RuleId 'msi.custom-actions.no-com' `
            -Title 'MSI custom-action check skipped (WindowsInstaller COM not available)' `
            -Reason $_.Exception.Message
        return
    }

    $deferred   = 0x400
    $rollback   = 0x1000
    $commit     = 0x2000
    $noImperson = 0x800
    $propRx     = '\[[A-Z_][A-Z0-9_]*\]'

    foreach ($msi in $msiFiles) {
        $db = $null
        try {
            $db   = $installer.OpenDatabase($msi.FullName, 0)
            $view = $db.OpenView('SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`')
            $view.Execute()
            $rec = $view.Fetch()
            while ($rec -ne $null) {
                $action = "$($rec.StringData(1))"
                $type   = [int]$rec.IntegerData(2)
                $source = "$($rec.StringData(3))"
                $target = "$($rec.StringData(4))"
                $rec    = $view.Fetch()

                $isElevated  = ($type -band $noImperson) -ne 0
                $isScheduled = (($type -band $deferred) -ne 0) -or
                               (($type -band $rollback) -ne 0) -or
                               (($type -band $commit)   -ne 0)
                if (-not ($isElevated -and $isScheduled)) { continue }

                $hasPropExpansion = ($source -match $propRx) -or ($target -match $propRx)

                $severity = if ($hasPropExpansion) { 'HIGH' } else { 'MEDIUM' }
                $conf     = if ($hasPropExpansion) { 'Confirmed' } else { 'Inferred' }
                $phase    = switch ($type -band 0x3000) {
                    0x1000 { 'rollback' }
                    0x2000 { 'commit' }
                    default { 'deferred' }
                }
                $typeHex = '0x{0:X}' -f $type

                New-TcpkFinding -Module 'os' -RuleId 'msi.custom-action.system-elevation' `
                    -Severity $severity -Confidence $conf `
                    -Title "MSI $phase custom action runs as SYSTEM: $action" `
                    -File $msi.FullName `
                    -Evidence ("Action=$action Type=$typeHex" +
                               $(if ($hasPropExpansion) { " Target=[$target] Source=[$source] -- contains [PROPERTY] expansion" } else { '' })) `
                    -Cwe @('CWE-269','CWE-250') `
                    -Description ("The MSI custom action '$action' is scheduled as a $phase " +
                        "action (Type flag 0x" + ('{0:X}' -f ($type -band 0x3C00)) + ") and has " +
                        "the NoImpersonate bit set (0x800), so it runs with the installer's " +
                        "elevated token (SYSTEM on an admin install), not as the interactive user. " +
                        $(if ($hasPropExpansion) {
                            "The Target/Source field contains [PROPERTY] expansion. PUBLIC properties " +
                            "can be set by any user via the msiexec command line (msiexec /i app.msi " +
                            "PROP=value), which means an attacker can supply the action's arguments. " +
                            "This is a confirmed LPE primitive if the action uses the property value " +
                            "to run code (EXE type) or write to a system location."
                        } else {
                            "Verify the Target/Source values do not reference user-controllable " +
                            "properties. If the property originates from a user-writable registry " +
                            "key or directory, this is a privilege escalation primitive."
                        })) `
                    -Fix ('Move user-influenced data out of deferred+SYSTEM custom actions. ' +
                        'For EXE actions that must run elevated, use a separate signed helper binary ' +
                        'that validates and sanitizes all inputs before acting. Add the property to ' +
                        'the SecureCustomProperties table to prevent it being set on the command line. ' +
                        'Consider using WiX Burn (Bootstrapper) with a separate elevated service instead.')
            }
        } catch {
            Add-TcpkScanSkip -Rule 'msi.custom-actions' -Path $msi.FullName -Reason $_.Exception.Message
        } finally {
            try { if ($db) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($db) | Out-Null } } catch {}
        }
    }
    try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer) | Out-Null } catch {}
}
