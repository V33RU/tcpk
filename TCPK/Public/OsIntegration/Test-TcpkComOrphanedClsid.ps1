function Test-TcpkComOrphanedClsid {
<#
.SYNOPSIS
    C27. CLSIDs the application activates that are registered NOWHERE, so an attacker can
    define them first.

.DESCRIPTION
    Test-TcpkComHijack covers the case where a class IS registered in HKLM and HKCU is left
    free, so a standard user can shadow it. This covers the case it deliberately skips: a
    class the application asks for that no registration answers at all.

    WHY THE ORPHANED CASE IS THE WORSE ONE. Shadowing a real class replaces something that
    works, so the original functionality breaks or changes and someone may notice. An
    orphaned CLSID has no incumbent. Registering it takes nothing away, nothing
    malfunctions, and the only observable change is that a request which used to fail now
    succeeds and loads a DLL. HKCU is writable by the user who owns it, so this needs no
    privilege, and the load happens whenever the application next asks for that class.

    WHY THE CANDIDATE SET IS NARROW, ON PURPOSE. The obvious approach is to scan the binary
    for GUID-shaped strings and report any not present in the registry. That would be
    wrong: most GUIDs in a PE are interface IDs, type-library IDs and assembly IDs, none of
    which are ever registered under CLSID, so nearly every one would be reported. Two
    sources are used instead, both of which mean the application activates a CLASS:

      1. Type.GetTypeFromCLSID with a recoverable literal. In IL the argument is a Guid
         built by newobj Guid(String), so the constant is recovered by walking back through
         the ctor to the ldstr rather than reading the instruction immediately before the
         call.
      2. [ComImport] types that are NOT interfaces. A coclass carries a CLSID; an interface
         carries an IID and is excluded, because an unregistered IID is normal and means
         nothing.

    A CLSID found this way is reported only when absent from BOTH HKLM and HKCU, in the
    native and WOW6432Node views.

    Rules:
      comhijack.orphaned-clsid  HIGH  The application activates a class that no registration
                                      defines. Registering it under HKCU is unprivileged and
                                      breaks nothing.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkComOrphanedClsid')) { return }
    if (-not (Test-Path -LiteralPath $Path)) { return }

    $guidRx = '^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$'
    # clsid -> how it was found, so the evidence names the activation site
    $found = [ordered]@{}

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $asm = Get-TcpkCecilAssembly -DllPath $pe.FullName
        if (-not $asm) { continue }
        $mod = $null
        try { $mod = $asm.MainModule } catch { $mod = $null }
        if (-not $mod) { continue }
        $types = @()
        try { $types = @($mod.GetTypes()) } catch { $types = @() }

        foreach ($t in $types) {
            # ---- source 2: [ComImport] COCLASS (not an interface) ------------
            $isImport = $false; $isIface = $true
            try { $isImport = [bool]$t.IsImport; $isIface = [bool]$t.IsInterface } catch { }
            if ($isImport -and -not $isIface) {
                try {
                    foreach ($ca in $t.CustomAttributes) {
                        if ("$($ca.AttributeType.FullName)" -ne 'System.Runtime.InteropServices.GuidAttribute') { continue }
                        if ($ca.ConstructorArguments.Count -lt 1) { continue }
                        $g = "$($ca.ConstructorArguments[0].Value)"
                        if ($g -match $guidRx -and -not $found.Contains($g)) {
                            $found[$g] = "[ComImport] coclass $($t.Name) in $($pe.Name)"
                        }
                    }
                } catch { }
            }

            # ---- source 1: Type.GetTypeFromCLSID(new Guid("...")) -------------
            $methods = @()
            try { $methods = @($t.Methods) } catch { continue }
            foreach ($m in $methods) {
                if (-not $m.HasBody) { continue }
                $instrs = $null
                try { $instrs = @($m.Body.Instructions) } catch { continue }
                if (-not $instrs) { continue }

                for ($i = 0; $i -lt $instrs.Count; $i++) {
                    $ins = $instrs[$i]
                    $op = ''
                    try { $op = "$($ins.OpCode.Name)" } catch { continue }
                    if ($op -ne 'call' -and $op -ne 'callvirt') { continue }
                    $mref = $ins.Operand -as [Mono.Cecil.MethodReference]
                    if ($null -eq $mref) { continue }
                    $mn = ''; $dt = ''
                    try { $mn = "$($mref.Name)"; $dt = "$($mref.DeclaringType.FullName)" } catch { continue }
                    if ($dt -ne 'System.Type' -or $mn -ne 'GetTypeFromCLSID') { continue }

                    # The Guid is constructed just before the call, so the literal is not
                    # the previous instruction. Walk back a short window looking for the
                    # ldstr that feeds newobj Guid(String).
                    $lit = ''
                    for ($j = $i - 1; $j -ge 0 -and $j -ge ($i - 6); $j--) {
                        $bop = ''
                        try { $bop = "$($instrs[$j].OpCode.Name)" } catch { continue }
                        if ($bop -ne 'ldstr') { continue }
                        $cand = ''
                        try { $cand = "$($instrs[$j].Operand)" } catch { $cand = '' }
                        if ($cand -match $guidRx) { $lit = $cand; break }
                    }
                    if ($lit -and -not $found.Contains($lit)) {
                        $found[$lit] = "Type.GetTypeFromCLSID in $($t.Name)::$($m.Name) ($($pe.Name))"
                    }
                }
            }
        }
    }

    if ($found.Count -eq 0) { return }

    foreach ($raw in $found.Keys) {
        # Normalise to the braced form the registry uses.
        $clsid = $raw
        if (-not $clsid.StartsWith('{')) { $clsid = '{' + $clsid }
        if (-not $clsid.EndsWith('}'))   { $clsid = $clsid + '}' }

        # Absent from every view, or it is not orphaned and belongs to Test-TcpkComHijack.
        $views = @(
            "HKLM:\Software\Classes\CLSID\$clsid",
            "HKLM:\Software\Classes\Wow6432Node\CLSID\$clsid",
            "HKLM:\Software\Wow6432Node\Classes\CLSID\$clsid",
            "HKCU:\Software\Classes\CLSID\$clsid",
            "HKCU:\Software\Classes\Wow6432Node\CLSID\$clsid"
        )
        $registered = $false
        foreach ($v in $views) {
            try { if (Test-Path -LiteralPath $v) { $registered = $true; break } } catch { }
        }
        if ($registered) { continue }

        New-TcpkFinding -Module 'os' -RuleId 'comhijack.orphaned-clsid' `
            -Severity 'HIGH' -Confidence 'Confirmed' `
            -Title "Application activates an unregistered class: $clsid" `
            -File $Path `
            -Evidence ("$clsid activated by $($found[$raw]); absent from HKLM and HKCU CLSID in both registry views") `
            -Cwe @('CWE-1188', 'CWE-427') `
            -Description ('The application asks COM for this class and nothing on the system registers it, ' +
                'so the request fails today. That failure is the opportunity: an attacker creates the key ' +
                'under HKCU\Software\Classes\CLSID with an InprocServer32 value pointing at their DLL, and ' +
                'the next activation loads it into this process. HKCU is writable by the user who owns it, ' +
                'so no privilege is needed. This is worse than shadowing a registered class, because there ' +
                'is no incumbent to displace: nothing stops working, no behaviour changes, and the only ' +
                'difference is that a call which used to fail now succeeds. The server DLL does not need a ' +
                '.dll extension either, so the payload can sit among ordinary-looking files. The candidate ' +
                'set here is deliberately narrow: only classes the application demonstrably activates, ' +
                'never the interface or type-library GUIDs that also appear in a binary and are never ' +
                'registered under CLSID.') `
            -Fix 'Remove the activation if the class is a leftover from a component the product no longer ships, which is the usual cause. If it is genuinely required, ensure the installer registers it under HKLM so there is an incumbent, and verify at runtime that the loaded server is the expected signed module rather than accepting whatever the resolution returns.'
    }
}
