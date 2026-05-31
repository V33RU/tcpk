function Test-TcpkDebugFlags {
<#
.SYNOPSIS
    A16. Debug switches, security-disabling flags, and backdoor markers.

.DESCRIPTION
    Scans first-party assemblies + config/text for strings that disable security
    controls or expose debug/backdoor paths. Three tiers:

      * security-off  (HIGH)  -- flags that turn OFF a protection
                                 (--no-sandbox, --ignore-certificate-errors,
                                  TrustAllCerts, BypassAuth, --disable-web-security)
      * backdoor      (HIGH)  -- master-password / godmode style markers
      * debug-surface (LOW)   -- remote-debug / dev-mode toggles

    All Inferred -- presence of the literal does not prove it is reachable;
    confirm by decompiling the referencing method.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $markers = @(
        # --- security-disabling ---
        @{ s='--no-sandbox';                    t='security-off'; sev='HIGH' }
        @{ s='--disable-web-security';          t='security-off'; sev='HIGH' }
        @{ s='--ignore-certificate-errors';     t='security-off'; sev='HIGH' }
        @{ s='--allow-running-insecure-content';t='security-off'; sev='HIGH' }
        @{ s='--disable-gpu-sandbox';           t='security-off'; sev='HIGH' }
        @{ s='TrustAllCerts';                   t='security-off'; sev='HIGH' }
        @{ s='TrustAllCertificates';            t='security-off'; sev='HIGH' }
        @{ s='AllowUntrustedCertificates';      t='security-off'; sev='HIGH' }
        @{ s='DisableCertificateValidation';    t='security-off'; sev='HIGH' }
        @{ s='SkipCertificateCheck';            t='security-off'; sev='HIGH' }
        @{ s='BypassAuth';                      t='security-off'; sev='HIGH' }
        @{ s='SkipAuthentication';              t='security-off'; sev='HIGH' }
        @{ s='DisableAuthentication';           t='security-off'; sev='HIGH' }
        @{ s='DisableSecurity';                 t='security-off'; sev='HIGH' }
        @{ s='DisableCSRF';                     t='security-off'; sev='HIGH' }
        @{ s='AllowInsecure';                   t='security-off'; sev='MEDIUM' }
        # --- backdoor-ish ---
        @{ s='backdoor';                        t='backdoor';     sev='HIGH' }
        @{ s='godmode';                         t='backdoor';     sev='HIGH' }
        @{ s='god_mode';                        t='backdoor';     sev='HIGH' }
        @{ s='masterpassword';                  t='backdoor';     sev='HIGH' }
        @{ s='master_password';                 t='backdoor';     sev='HIGH' }
        @{ s='superpassword';                   t='backdoor';     sev='HIGH' }
        @{ s='magicword';                       t='backdoor';     sev='HIGH' }
        # --- debug surface ---
        @{ s='--remote-debugging-port';         t='debug-surface'; sev='LOW' }
        @{ s='--inspect-brk';                   t='debug-surface'; sev='LOW' }
        @{ s='EnableDeveloperMode';             t='debug-surface'; sev='LOW' }
        @{ s='--dev-mode';                      t='debug-surface'; sev='LOW' }
    )
    $descByTier = @{
        'security-off'  = 'A literal that disables a security control was found. If reachable at runtime (via config, env var, or arg) it can switch off sandboxing, certificate validation, or authentication.'
        'backdoor'      = 'A backdoor-style marker was found. Confirm whether a hardcoded master credential or hidden code path exists.'
        'debug-surface' = 'A debug/developer surface marker was found. Remote-debug ports and dev modes can expose internal state or code execution if enabled in production.'
    }

    $cap = 80; $n = 0
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if ($n -ge $cap) { break }
        if ($pe.Extension -notin '.dll','.exe') { continue }
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        if (Test-TcpkIsNativeNoise $pe.Name)   { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        $low = $text.ToLowerInvariant()
        foreach ($mk in $markers) {
            if ($low.IndexOf($mk.s.ToLowerInvariant(), [StringComparison]::Ordinal) -lt 0) { continue }
            New-TcpkFinding -Module 'static' -RuleId "debugflags.$($mk.t)" `
                -Severity $mk.sev -Confidence 'Inferred' `
                -Title "$($mk.t) marker '$($mk.s)' in $($pe.Name)" `
                -File $pe.FullName -Evidence $mk.s -Cwe @('CWE-489','CWE-912') `
                -Description $descByTier[$mk.t] `
                -Fix 'Confirm reachability by decompiling the referencing method. Remove debug/insecure switches from release builds; gate developer paths behind a compile-time flag, not a runtime string.'
            $n++
            if ($n -ge $cap) { break }
        }
    }
}
