# Active Frida bypass support for Invoke-TcpkHookBypass. Where the hook-mode script OBSERVES
# traffic, this FORCES a named native export's return value (and optionally skips its body) --
# the runtime-manipulation leap: flip a client-side auth / license / integrity check that the
# app trusts. Gated by the public cmdlet. Managed-.NET method bypass needs the frida-clr
# bridge and is out of scope here; this targets native exports resolved by name.

# Generate a concrete Frida bypass script for one function. $Ret is forced onLeave; $Skip
# replaces the whole body with an immediate return (onEnter) when the function must not run.
function New-TcpkBypassScript {
    param(
        [Parameter(Mandatory)][string]$Function,
        [string]$Module,
        [int]$Ret = 1,
        [switch]$Skip
    )
    $modArg = if ($Module) { "'" + ($Module -replace "'", '') + "'" } else { 'null' }
    $fn = ($Function -replace "'", '')
    $skipBlock = if ($Skip) {
        @"
        onEnter: function (args) { this.tcpkSkip = true; },
        onLeave: function (retval) { retval.replace($Ret); emit({ event: 'forced', func: '$fn', ret: $Ret, skipped: true }); }
"@
    } else {
        @"
        onLeave: function (retval) { var old = retval.toInt32(); retval.replace($Ret); emit({ event: 'forced', func: '$fn', old: old, ret: $Ret }); }
"@
    }
    @"
'use strict';
function emit(r){ try { console.log('TCPKBYPASS ' + JSON.stringify(r)); } catch (e) {} }
function resolveExport(mod, name) {
    try { if (typeof Module.findExportByName === 'function') { var a = Module.findExportByName(mod, name); if (a) return a; } } catch (e) {}
    try { if (typeof Module.getExportByName === 'function') { return Module.getExportByName(mod, name); } } catch (e) {}
    try { if (mod === null && typeof Module.getGlobalExportByName === 'function') { return Module.getGlobalExportByName(name); } } catch (e) {}
    try {
        var mods = Process.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            try { var e2 = (typeof mods[i].findExportByName === 'function') ? mods[i].findExportByName(name) : (typeof mods[i].getExportByName === 'function' ? mods[i].getExportByName(name) : null); if (e2) return e2; } catch (e) {}
        }
    } catch (e) {}
    return null;
}
var addr = resolveExport($modArg, '$fn');
if (!addr) { emit({ event: 'not-found', func: '$fn' }); }
else {
    try {
        Interceptor.attach(addr, {
$skipBlock
        });
        emit({ event: 'hooked', func: '$fn', ret: $Ret });
    } catch (e) { emit({ event: 'error', func: '$fn', message: '' + e }); }
}
"@
}

# Turn the bypass script's output log (TCPKBYPASS lines) into a finding.
function ConvertFrom-TcpkBypassLog {
    param([string]$LogFile, [string]$Function, [string]$Target)
    $lines = @()
    if (Test-Path -LiteralPath $LogFile) { $lines = @(Get-Content -LiteralPath $LogFile | Where-Object { "$_" -match 'TCPKBYPASS' }) }
    $forced = @($lines | Where-Object { $_ -match '"event":"forced"' })
    $hooked = @($lines | Where-Object { $_ -match '"event":"hooked"' })
    if ($forced.Count) {
        return (New-TcpkFinding -Module 'exploit' -RuleId 'exploit.check-bypassed' -Severity 'HIGH' -Confidence 'Confirmed (exploit)' `
            -Title "Forced the return value of $Function at runtime" -File $Target `
            -Evidence (($forced | Select-Object -First 4) -join ' | ') -Cwe @('CWE-602', 'CWE-807') `
            -Description "Injected a Frida hook that overrode the return value of $Function in the running process, and it executed ($($forced.Count) time(s)). A client-side check the app trusts (auth / license / integrity) can be flipped by anyone able to run code in the app context. Confirm the security decision is also enforced server-side." `
            -Fix 'Do not make security decisions client-side; enforce them on the server. Client-side tamper resistance only raises the bar, it does not prevent a determined local attacker.')
    }
    if ($hooked.Count) {
        return (New-TcpkFinding -Module 'exploit' -RuleId 'exploit.check-bypassed' -Severity 'MEDIUM' -Confidence 'Confirmed (dynamic)' `
            -Title "Hooked $Function but it was not invoked during the window" -File $Target `
            -Evidence (($hooked | Select-Object -First 2) -join ' | ') `
            -Description "The bypass hook installed on $Function but the function was not called in the capture window. Drive the app to exercise the check (e.g. attempt the gated action) to force it." `
            -Fix 'Re-run and trigger the guarded action so the hook fires.')
    }
    return (New-TcpkFinding -Module 'exploit' -RuleId 'exploit.check-bypassed' -Severity 'INFO' -Confidence 'Inferred' `
        -Title "Bypass did not install on $Function" -File $Target `
        -Evidence (($lines | Select-Object -First 2) -join ' | ') `
        -Description "The function $Function was not found as a native export (it may be a managed .NET method -- which needs the frida-clr bridge -- statically linked, stripped, or named differently). Check the recon module list for the exact export name." `
        -Fix 'Verify the export name/module (e.g. via the decompile / PE import view); for a managed .NET check use the frida-clr bridge.')
}
