function Test-TcpkNamedPipeHardening {
<#
.SYNOPSIS
    A51. Named-pipe server created without FILE_FLAG_FIRST_PIPE_INSTANCE (IL).

.DESCRIPTION
    A thick-client helper service that creates a fixed-named pipe without
    FILE_FLAG_FIRST_PIPE_INSTANCE (0x00080000 in dwOpenMode) can be squatted: a
    low-privilege process that creates the pipe first owns the name and captures the
    server's first client, which is a spoofing / privilege-boundary problem (CWE-283).

    This reads the first-party managed binaries with Mono.Cecil and reports a
    CreateNamedPipe call whose literal dwOpenMode argument does NOT carry the flag, on a
    fixed (ldstr) pipe name. The argument is read by position and only when every call
    argument is a single leaf load, so a computed open mode is skipped rather than guessed
    (no false positive). The pipe DACL is covered separately by Test-TcpkNamedPipeDacl; this
    is the first-instance / squatting dimension.

.PARAMETER Path
    File or directory (recursive).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        foreach ($v in (Get-TcpkPipeFirstInstanceVerdicts -DllPath $pe.FullName)) {
            $ev = New-Object 'System.Collections.Generic.List[string]'
            $ev.Add("CreateNamedPipe on '$($v.PipeName)' with dwOpenMode=$($v.OpenMode) -- FILE_FLAG_FIRST_PIPE_INSTANCE (0x80000) is not set.")
            $ev.Add('')
            $ev.Add('LOCATION (open THIS assembly in ILSpy/dnSpy):')
            $ev.Add("  Assembly : $($v.Assembly)")
            $ev.Add("  Namespace: $($v.Namespace)")
            $ev.Add("  Type     : $($v.Type)")
            $ev.Add("  Method   : $($v.Method)")
            $ev.Add("  MD token : $($v.Token)")
            $ev.Add('')
            $ev.Add('IL PROOF (the dwOpenMode constant fed to CreateNamedPipe):')
            $ev.Add($v.Il)
            New-TcpkFinding -Module 'static' -RuleId 'pipe.no-first-instance' `
                -Severity 'MEDIUM' -Confidence 'Confirmed (IL)' `
                -Title "Named pipe created without FIRST_PIPE_INSTANCE: $($v.PipeName) in $($pe.Name)" `
                -File $pe.FullName -Evidence ($ev -join "`n") `
                -Cwe @('CWE-283','CWE-708') `
                -AttributionBasis 'established-code' -Subject $pe.FullName `
                -Description 'The app creates a fixed-named pipe without FILE_FLAG_FIRST_PIPE_INSTANCE (the dwOpenMode constant is in the Evidence and lacks bit 0x80000). Without that flag a low-privilege process can create the pipe name first, so when the real server starts it attaches to the squatter''s pipe, or a client that connects by name reaches the squatter. Combined with impersonation on the server side this is a spoofing / privilege-boundary bug. Proven from the literal open mode; confirm the server is not otherwise guaranteed to create the pipe first.' `
                -Fix 'Pass FILE_FLAG_FIRST_PIPE_INSTANCE (0x00080000) in dwOpenMode so CreateNamedPipe fails if the name already exists, and set a restrictive pipe DACL. On NamedPipeServerStream use a first-instance / ACL-bearing constructor.'
        }
    }
}
