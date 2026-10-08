function Test-TcpkImpersonationBalance {
<#
.SYNOPSIS
    A49. Unbalanced impersonation in the thick client's own managed code (IL).

.DESCRIPTION
    A helper service or privileged component that impersonates its IPC client and then does
    not revert on every exit path keeps the client's token on the thread after the method
    returns or throws. If a lower-privilege caller reached that code over a pipe / RPC / COM
    surface, the leaked impersonation is a local privilege-escalation primitive.

    This reads the first-party managed binaries with Mono.Cecil and reports a method that
    calls a MANUAL-revert impersonation sink (ImpersonateNamedPipeClient / ImpersonateLoggedOnUser
    / SetThreadToken) with no revert anywhere in the SAME body (RevertToSelf, or
    WindowsImpersonationContext.Undo/Dispose) and no auto-reverting wrapper
    (WindowsIdentity.RunImpersonated, or WindowsIdentity.Impersonate() in a using). It is
    reported Inferred: the method reverts on no path of ITS OWN, but it could delegate the
    revert to a caller or callee, which this single-method view cannot see -- confirm before
    treating it as exploitable.

.PARAMETER Path
    File or directory (recursive).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        foreach ($v in (Get-TcpkImpersonationVerdicts -DllPath $pe.FullName)) {
            $ev = New-Object 'System.Collections.Generic.List[string]'
            $ev.Add("Impersonation sink '$($v.Sink)' is called with no revert on the method's own exit paths.")
            $ev.Add('')
            $ev.Add('LOCATION (open THIS assembly in ILSpy/dnSpy):')
            $ev.Add("  Assembly : $($v.Assembly)")
            $ev.Add("  Namespace: $($v.Namespace)")
            $ev.Add("  Type     : $($v.Type)")
            $ev.Add("  Method   : $($v.Method)")
            $ev.Add("  MD token : $($v.Token)")
            $ev.Add('')
            $ev.Add('IL PROOF (instructions ending at the impersonation sink):')
            $ev.Add($v.Il)
            New-TcpkFinding -Module 'static' -RuleId 'ipc.unbalanced-impersonation' `
                -Severity 'HIGH' -Confidence 'Inferred' `
                -Title "Impersonation without revert on all paths: $($v.Type)::$($v.Method) in $($pe.Name)" `
                -File $pe.FullName -Evidence ($ev -join "`n") `
                -Cwe @('CWE-648','CWE-269') `
                -AttributionBasis 'established-code' -Subject $pe.FullName `
                -Description 'A method in the app''s own code impersonates a caller (ImpersonateNamedPipeClient / ImpersonateLoggedOnUser / SetThreadToken) and contains no RevertToSelf or WindowsImpersonationContext revert anywhere in its body, and no auto-reverting wrapper. If it returns early or throws, the thread keeps running as the impersonated client. When a lower-privilege caller can reach this code over an IPC surface, the leaked token is a local privilege-escalation primitive. Inferred because the revert could live in a caller or callee this single-method view does not cover -- confirm the method has no reachable revert.' `
                -Fix 'Wrap the impersonated work in try { Impersonate... } finally { RevertToSelf() } (or Undo the WindowsImpersonationContext), or use WindowsIdentity.RunImpersonated / a using over WindowsIdentity.Impersonate() so the revert runs on every path including exceptions.'
        }
    }
}
