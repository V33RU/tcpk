function Test-TcpkHandleInheritance {
<#
.SYNOPSIS
    A50. Blanket handle inheritance when the thick client spawns a child (IL).

.DESCRIPTION
    A process that creates a child with handle inheritance turned on, and does not restrict
    WHICH handles are inherited (no PROC_THREAD_ATTRIBUTE_HANDLE_LIST), leaks every inheritable
    handle it holds into that child. When the child is less trusted than the parent (a renderer,
    a plugin host, a sandboxed worker), the child can use a leaked privileged handle to escalate.

    This reads the first-party managed binaries with Mono.Cecil and proves, from the constant
    actually loaded, two inheritance-enabling shapes:
      * SetHandleInformation(h, dwMask, dwFlags) with HANDLE_FLAG_INHERIT (0x1) set in dwFlags.
      * a marshalled SECURITY_ATTRIBUTES whose bInheritHandle field is stored a non-zero
        constant (TRUE).
    A zero / FALSE store, or a value computed at runtime, is never reported. The object-DACL
    side of handle exposure is covered separately (Test-TcpkProcessDacl / ThreadDacl / TokenDacl);
    this is the inheritance side.

.PARAMETER Path
    File or directory (recursive).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        foreach ($v in (Get-TcpkHandleInheritVerdicts -DllPath $pe.FullName)) {
            $ev = New-Object 'System.Collections.Generic.List[string]'
            $ev.Add($v.Reason)
            $ev.Add('')
            $ev.Add('LOCATION (open THIS assembly in ILSpy/dnSpy):')
            $ev.Add("  Assembly : $($v.Assembly)")
            $ev.Add("  Namespace: $($v.Namespace)")
            $ev.Add("  Type     : $($v.Type)")
            $ev.Add("  Method   : $($v.Method)")
            $ev.Add("  MD token : $($v.Token)")
            $ev.Add('')
            $ev.Add('IL PROOF (the value fed to the inheritance setter):')
            $ev.Add($v.Il)
            New-TcpkFinding -Module 'static' -RuleId ('handle.inherit-leak.' + ($v.Kind -replace '-inherit$','')) `
                -Severity 'MEDIUM' -Confidence $v.Confidence `
                -Title "Inheritable handle when spawning a child: $($v.Type)::$($v.Method) in $($pe.Name)" `
                -File $pe.FullName -Evidence ($ev -join "`n") `
                -Cwe @('CWE-403') `
                -AttributionBasis 'established-code' -Subject $pe.FullName `
                -Description 'The app turns on handle inheritance (the exact constant is in the Evidence). If it then creates a child process without a PROC_THREAD_ATTRIBUTE_HANDLE_LIST restricting which handles pass, every inheritable handle the parent holds is leaked into the child. A less-trusted child (renderer, plugin host, sandboxed worker) can use a leaked privileged handle to escalate. Confirm the child is lower-trust and that no explicit inherit-handle list narrows what is passed.' `
                -Fix 'Pass only the handles the child needs via STARTUPINFOEX + PROC_THREAD_ATTRIBUTE_HANDLE_LIST, and keep bInheritHandle / HANDLE_FLAG_INHERIT off for everything else. Do not enable blanket inheritance when launching a lower-trust process.'
        }
    }
}
