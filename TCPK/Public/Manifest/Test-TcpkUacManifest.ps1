function Test-TcpkUacManifest {
<#
.SYNOPSIS
    B09. UAC execution level in embedded RT_MANIFEST (and sidecar .manifest).

.DESCRIPTION
    The Windows application manifest -- embedded as an RT_MANIFEST resource in
    the PE, or shipped as <exe>.manifest -- declares requestedExecutionLevel.
    The manifest is stored as text, so we can read it out of the binary.

    Flags:
      requireAdministrator  HIGH      app always runs elevated -> every bug is an EoP
      highestAvailable      MEDIUM    elevates for admins silently
      uiAccess=true         MEDIUM    can drive other windows' UI (input injection)
      autoElevate=true      CRITICAL  UAC auto-elevation; on a non-Microsoft-signed
                                      binary this is a UAC bypass / misconfiguration

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if ($pe.Extension -ine '.exe') { continue }
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }

        # embedded manifest text + any sidecar <exe>.manifest
        $text = Read-TcpkAllText -Path $pe.FullName
        $sidecar = "$($pe.FullName).manifest"
        if (Test-Path -LiteralPath $sidecar) {
            try { $text += "`n" + (Get-Content -LiteralPath $sidecar -Raw) } catch { }
        }
        if (-not $text) { continue }
        if ($text -notmatch 'requestedExecutionLevel|asInvoker|requireAdministrator|autoElevate') { continue }

        if ($text -match 'autoElevate"?\s*[:=]\s*"?\s*true') {
            New-TcpkFinding -Module 'manifest' -RuleId 'uac.auto-elevate' `
                -Severity 'CRITICAL' -Confidence 'Inferred' `
                -Title "$($pe.Name) manifest requests autoElevate=true" `
                -File $pe.FullName -Evidence 'autoElevate=true' -Cwe @('CWE-250','CWE-269') `
                -Description 'autoElevate silently elevates without a UAC prompt. Only specific Microsoft-signed binaries are honored by the OS; on a third-party binary this signals a UAC-bypass attempt or a packaging error. Any input-handling bug becomes a direct local privilege escalation.' `
                -Fix 'Remove autoElevate. Run as asInvoker and elevate an explicit, separately-signed helper only when required.'
        }
        if ($text -match 'level\s*=\s*"requireAdministrator"') {
            New-TcpkFinding -Module 'manifest' -RuleId 'uac.require-administrator' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "$($pe.Name) always runs elevated (requireAdministrator)" `
                -File $pe.FullName -Evidence 'requestedExecutionLevel level="requireAdministrator"' -Cwe @('CWE-250') `
                -Description 'The process always runs as administrator. Every memory-safety, deserialization, IPC, or input-parsing bug in it is therefore a local privilege-escalation primitive. Confirm the elevated surface is minimal.' `
                -Fix 'Run unprivileged (asInvoker); move the few operations that need admin into a small, audited, separately-elevated component.'
        }
        elseif ($text -match 'level\s*=\s*"highestAvailable"') {
            New-TcpkFinding -Module 'manifest' -RuleId 'uac.highest-available' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "$($pe.Name) requests highestAvailable" `
                -File $pe.FullName -Evidence 'requestedExecutionLevel level="highestAvailable"' -Cwe @('CWE-250') `
                -Description 'Runs elevated for administrators without an explicit per-launch consent. Same EoP exposure as requireAdministrator when launched by an admin.'
        }
        if ($text -match 'uiAccess\s*=\s*"true"') {
            New-TcpkFinding -Module 'manifest' -RuleId 'uac.ui-access' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "$($pe.Name) requests uiAccess=true" `
                -File $pe.FullName -Evidence 'uiAccess="true"' -Cwe @('CWE-1021') `
                -Description 'uiAccess lets the process send input to / read UI of higher-integrity windows (accessibility surface). Confirm it does not relay attacker-controlled input to elevated UI.'
        }
    }
}
