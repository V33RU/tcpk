function Test-TcpkIfeoHijack {
<#
.SYNOPSIS
    C11. Image File Execution Options debugger-key hijack.

.DESCRIPTION
    Any executable name under
      HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>
    with a 'Debugger' value will be replaced by that debugger at launch.
    Legitimate uses exist (gflags). Unexpected entries naming the target
    binary are HIGH severity.

.PARAMETER NameLike
    Substring to match against the .exe key name (default '*').

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string[]]$NameLike = @())

    if (-not (Assert-TcpkWindows 'Test-TcpkIfeoHijack')) { return }

    $terms = Get-TcpkNameTerms -NameLike $NameLike

    $ifeo = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (-not (Test-Path $ifeo)) { return }

    foreach ($k in (Get-ChildItem $ifeo -ErrorAction SilentlyContinue)) {
        if ($terms.Count -and -not (Test-TcpkTermMatch -Text $k.PSChildName -Terms $terms)) { continue }
        $debugger = (Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue).Debugger
        if (-not $debugger) { continue }

        New-TcpkFinding -Module 'os' -RuleId 'ifeo.debugger-hijack' `
            -Severity 'HIGH' -Confidence 'Confirmed' `
            -Title "IFEO debugger hijack: $($k.PSChildName) -> $debugger" `
            -File $k.PSPath -Evidence $debugger `
            -Cwe @('CWE-732','CWE-426') `
            -Description 'The OS replaces the named executable with the configured Debugger at launch. Unexpected entries are persistence / privesc primitives.' `
            -Fix 'Confirm legitimacy. Remove the Debugger value if unintended.'
    }

    # ---- ifeo.silent-process-exit -----------------------------------------------
    # HKLM\...\Image File Execution Options\<exe>  GlobalFlag = 0x200 (FLG_MONITOR_SILENT_PROCESS_EXIT)
    # HKLM\...\SilentProcessExit\<exe>             MonitorProcess = <path\to\attacker.exe>
    #                                              LocalDumpFolder = <writable path>
    #                                              ReportingMode = 1|2|3
    # When the named exe exits normally, Windows runs MonitorProcess as SYSTEM.
    # Persistence + privesc primitive; harder to spot than IFEO Debugger.
    $spe = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    if (Test-Path -LiteralPath $spe) {
        foreach ($k in (Get-ChildItem -LiteralPath $spe -ErrorAction SilentlyContinue)) {
            if ($terms.Count -and -not (Test-TcpkTermMatch -Text $k.PSChildName -Terms $terms)) { continue }
            $props = $null
            try { $props = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue } catch { continue }
            if (-not $props) { continue }
            $monitor = "$($props.MonitorProcess)"
            $folder  = "$($props.LocalDumpFolder)"
            $mode    = "$($props.ReportingMode)"
            if (-not $monitor -and -not $folder) { continue }
            # Cross-check: the exe should ALSO have GlobalFlag=0x200 in the IFEO key
            # for the SilentProcessExit callback to actually fire. Absence still gets
            # reported as a staged primitive - the attacker only needs to flip the
            # flag later.
            $ifeoKey = Join-Path $ifeo $k.PSChildName
            $flag = $null
            try { $flag = (Get-ItemProperty -LiteralPath $ifeoKey -ErrorAction SilentlyContinue).GlobalFlag } catch { }
            $armed = ($flag -and ([int]$flag -band 0x200))
            $sev = if ($armed) { 'HIGH' } else { 'MEDIUM' }
            New-TcpkFinding -Module 'os' -RuleId 'ifeo.silent-process-exit' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "SilentProcessExit callback: $($k.PSChildName) -> $monitor" `
                -File $k.PSPath -Evidence "MonitorProcess=$monitor; LocalDumpFolder=$folder; ReportingMode=$mode; GlobalFlag=$flag (armed=$armed)" `
                -Cwe @('CWE-732','CWE-426','CWE-269') `
                -Description ('An entry under HKLM\...\SilentProcessExit\<exe> tells Windows to spawn ' +
                    'MonitorProcess as SYSTEM when the named executable exits normally. Persistence + ' +
                    'privilege-escalation primitive; unlike IFEO Debugger it only fires on process EXIT, ' +
                    'which is harder to notice than launch-time hijack. GlobalFlag=0x200 in the paired ' +
                    'IFEO key is what actually arms it; MEDIUM when the flag is absent because the entry ' +
                    'is staged but not live.') `
                -Fix 'Remove the SilentProcessExit\<exe> subkey unless it is a documented crash-dump investigator (rare). Also clear GlobalFlag bit 0x200 in the paired IFEO\<exe> key.'
        }
    }
}
