function Test-TcpkLoopbackExempt {
<#
.SYNOPSIS
    C35. The package registers a loopback exemption, disabling its own AppContainer
    network isolation.

.DESCRIPTION
    An AppContainer (an MSIX-packaged app) cannot reach 127.0.0.1 by default: network
    isolation blocks loopback so a sandboxed app cannot quietly talk to local services.
    A loopback EXEMPTION turns that off for a named package. It is registered with
    `CheckNetIsolation LoopbackExempt -a -n:<package>` or the native
    NetworkIsolationSetAppContainerConfig API, usually from the installer or a shipped
    script.

    WHY IT MATTERS. The AppContainer network-isolation bypasses in the Project Zero set
    (WFP default rules, WSAQuerySocketSecurity) are bugs in Windows' enforcement and are
    not a vendor's to fix. The vendor-owned half is the app REMOVING the boundary itself:
    an exemption lets the packaged app, and anything that can drive it, reach every
    loopback service on the machine, which is a real reduction in the sandbox the package
    model is supposed to provide. It is also a common developer shortcut left in a shipping
    build.

    This is a STATIC scan of the shipped scripts and installer, not a check of the live
    machine's exemption list (that would be host state, not the target's). It reports that
    the package ASKS for the exemption, which is the vendor's decision and the vendor's to
    justify.

    NOT a defect by itself. Some packaged apps legitimately need loopback for local IPC or
    a bundled helper. The finding is a prompt to confirm it is necessary and scoped to this
    package, not a blanket wrong.

.PARAMETER Path
    MSIX file, extracted package, or install directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $scriptExts = @('.ps1','.psm1','.bat','.cmd','.vbs','.js','.wsf','.wxs','.iss','.nsi','.nsh','.py','.txt','.xml','.json')

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $files = @()
    if ($item.PSIsContainer) {
        try {
            $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                       Where-Object { $scriptExts -contains $_.Extension.ToLowerInvariant() -and $_.Length -lt 2097152 })
        } catch { return }
    } elseif ($scriptExts -contains $item.Extension.ToLowerInvariant()) {
        $files = @($item)
    }
    # Native PEs can call the API directly; include first-party binaries by string match.
    $peFiles = @()
    try { $peFiles = @(Get-TcpkPeFiles -Path $Path | Where-Object { -not (Test-TcpkIsFrameworkFile $_.Name) }) } catch { }

    # Shapes:
    #  1. CheckNetIsolation LoopbackExempt -a            (command, in a script)
    #  2. the native config API
    # 'LoopbackExempt' is the CheckNetIsolation verb and appears in no other context; the
    # camelCase token does not match prose like "loopback exempt" with a space. That keeps
    # it specific while catching both the direct form and Start-Process -Args forms, where
    # the exe name and the verb are not adjacent.
    $shapes = @(
        @{ Name='checknetisolation'; Rx='LoopbackExempt' }
        @{ Name='native-api';        Rx='NetworkIsolationSetAppContainerConfig' }
    )

    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($f in @($files) + @($peFiles)) {
        $body = $null
        try { $body = [IO.File]::ReadAllText($f.FullName) } catch { continue }
        if (-not $body) { continue }
        foreach ($sh in $shapes) {
            if ($body -notmatch $sh.Rx) { continue }
            if (-not $seen.Add($f.FullName)) { break }
            New-TcpkFinding -Module 'os' -RuleId 'appcontainer.loopback-exempt' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "Package registers a loopback exemption: $($f.Name)" `
                -File $f.FullName `
                -Evidence ("matched $($sh.Name)") `
                -Cwe @('CWE-923','CWE-668') `
                -Description ('This package registers an AppContainer loopback exemption, which turns off ' +
                    'the network isolation that normally stops a sandboxed app from reaching 127.0.0.1. ' +
                    'With it, the packaged app and anything that can drive it can reach every loopback ' +
                    'service on the machine, which is a real reduction in the sandbox the package model ' +
                    'provides. The AppContainer isolation BYPASS bugs are Windows'' to fix; removing the ' +
                    'boundary like this is the vendor''s. It is often a developer shortcut left in a ' +
                    'shipping build. Confirm the app genuinely needs loopback and that the exemption is ' +
                    'scoped to this package rather than broad.') `
                -Fix ('Remove the loopback exemption if the app does not need local IPC. If it does, use ' +
                    'a named-object or pipe channel scoped to the package instead of a general loopback ' +
                    'hole, and never ship CheckNetIsolation as a convenience in the installer.')
            break
        }
    }
}
