function Test-TcpkNamedPipeDacl {
<#
.SYNOPSIS
    E05. Named pipe DACL inspection (TCAWin gap).

.DESCRIPTION
    Connects to each named pipe matching -NameLike as a client (briefly),
    reads back the pipe's SecurityIdentifier (RemotePipeAccess), and inspects
    the DACL via NamedPipeClientStream + GetAccessControl.

    Rules (rule id / severity / confidence):
      pipe-dacl.null       HIGH   Confirmed   SDDL contains 'D:NO_ACCESS_CONTROL',
                                                i.e. the pipe was created with
                                                lpSecurityAttributes=NULL and grants
                                                everything to everyone (KB4014981-class,
                                                distinct from an explicit weak ACE).
      pipe-dacl.weak       HIGH   Confirmed   An ACE grants Everyone / Authenticated
                                                Users / Users / INTERACTIVE Write /
                                                ChangePermissions / FullControl.
      pipe-dacl.unreadable INFO   Skipped     Connect failed in all three directions.
      pipe-dacl.enum-fail  INFO   Skipped     Cannot enumerate the pipe list.

    Best-effort: if a server doesn't allow client connection, the pipe is
    reported with Confidence=Skipped.

.PARAMETER NameLike
    Pipe-name substring (case-insensitive).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string[]]$NameLike)

    if (-not (Assert-TcpkWindows 'Test-TcpkNamedPipeDacl')) { return }

    $terms = Get-TcpkNameTerms -NameLike $NameLike
    if (-not $terms.Count) { return }

    try {
        $pipes = Get-ChildItem '\\.\pipe\' -ErrorAction Stop |
                 Where-Object { Test-TcpkTermMatch -Text $_.Name -Terms $terms }
    } catch {
        New-TcpkSkippedFinding -RuleId 'pipe-dacl.enum-fail' `
            -Title 'Cannot enumerate named pipes' -Reason $_.Exception.Message
        return
    }

    foreach ($pipe in $pipes) {
        # Probe In, then Out, then Duplex. A server created PIPE_ACCESS_INBOUND (it reads,
        # the client WRITES) refuses an In-only client -- exactly the write-accepting pipe
        # that is the cross-user injection primitive we most want to inspect, so an In-only
        # probe silently reports it "unreadable". Opening for Out/Duplex and reading the ACL
        # sends no data.
        $ac = $null; $lastErr = 'no direction connected'
        foreach ($dir in @('In', 'Out', 'InOut')) {
            $client = $null
            try {
                $client = New-Object System.IO.Pipes.NamedPipeClientStream(
                    '.', $pipe.Name,
                    [System.IO.Pipes.PipeDirection]$dir,
                    [System.IO.Pipes.PipeOptions]::None
                )
                $client.Connect(180)
                $ac = $client.GetAccessControl()
                break
            } catch {
                $lastErr = $_.Exception.Message
            } finally {
                if ($client) { try { $client.Dispose() } catch {} }
            }
        }
        if (-not $ac) {
            New-TcpkFinding -Module 'runtime' -RuleId 'pipe-dacl.unreadable' `
                -Severity 'INFO' -Confidence 'Skipped' `
                -Title "Pipe DACL unreadable: $($pipe.Name)" `
                -File $pipe.FullName -Evidence $lastErr `
                -Description 'Connect failed in all directions (In / Out / Duplex) -- the pipe likely has a restrictive ACL preventing the client probe, or a message-only OpenMode.'
            continue
        }

        # NULL DACL first (the strongest primitive, distinct rule so the operator can
        # tell "world-writable by construction" apart from "an ACE names a broad group").
        # A NULL DACL is the KB4014981 shape: CreateNamedPipe called with lpSecurityAttributes
        # = NULL, or a security descriptor whose DACL is not present. Windows treats it as
        # "grant everything to everyone" - stronger than any explicit weak ACE. In SDDL this
        # appears as 'D:NO_ACCESS_CONTROL' (SDDL is machine-generated upper case, so a
        # case-sensitive -cmatch is used to make the assertion explicit; the SDDL for the
        # empty-DACL case which denies everyone is bare 'D:' and is a DIFFERENT bug, not
        # fired here).
        $sddl = $null; $sddlErr = $null
        try { $sddl = $ac.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) }
        catch { $sddlErr = $_.Exception.Message }
        if (-not $sddl -and $sddlErr) {
            # Do not silently downgrade a HIGH: SDDL read failed after a successful connect,
            # so we cannot answer "NULL DACL vs weak DACL" for this pipe. Surface the failure
            # so the operator does not see a green pipe that was actually unassessed.
            New-TcpkFinding -Module 'runtime' -RuleId 'pipe-dacl.sddl-fail' `
                -Severity 'INFO' -Confidence 'Skipped' `
                -Title "Pipe SDDL read failed: $($pipe.Name)" `
                -File $pipe.FullName -Evidence $sddlErr `
                -Description 'The pipe accepted the client connect but GetSecurityDescriptorSddlForm threw, so the NULL-DACL check could not run against this pipe. The pipe-dacl.null / pipe-dacl.weak result for this pipe is unassessed rather than clean.'
        }
        $isNullDacl = ($sddl -and $sddl -cmatch 'D:NO_ACCESS_CONTROL')
        if ($isNullDacl) {
            New-TcpkFinding -Module 'runtime' -RuleId 'pipe-dacl.null' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Named pipe has NULL DACL (world-writable by construction): $($pipe.Name)" `
                -File $pipe.FullName -Evidence "SDDL=$sddl" `
                -Cwe @('CWE-732','CWE-284','CWE-269') `
                -Description ('The pipe was created with lpSecurityAttributes=NULL (or with a security ' +
                    "descriptor whose DACL is not present). Windows interprets that as 'grant everything " +
                    "to everyone', so ANY process on the box can connect, read, write, and modify the ACL " +
                    "of this IPC endpoint. Historically dominant thick-client-service LPE pattern " +
                    "(KB4014981-class). Distinct from pipe-dacl.weak: this primitive gives write to " +
                    "principals not enumerated in an ACE at all.") `
                -Fix 'Pass a real SECURITY_ATTRIBUTES with an explicit DACL to CreateNamedPipe. In .NET, pass a PipeSecurity object to NamedPipeServerStream that grants only the app principal + SYSTEM.'
            continue
        }

        $weak = $ac.Access | Where-Object {
            $_.IdentityReference.Value -match '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE)\b' -and
            $_.AccessControlType.ToString() -eq 'Allow' -and
            ($_.PipeAccessRights.ToString() -match 'Write|ChangePermissions|FullControl')
        }
        if ($weak) {
            $grants = ($weak | ForEach-Object {
                "$($_.IdentityReference)=$($_.PipeAccessRights)"
            }) -join '; '
            New-TcpkFinding -Module 'runtime' -RuleId 'pipe-dacl.weak' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Named pipe DACL grants non-admin Write/FullControl: $($pipe.Name)" `
                -File $pipe.FullName -Evidence $grants `
                -Cwe @('CWE-732','CWE-269') `
                -Description 'Any code running under the granted identity can write or modify ACL on this IPC endpoint -- direct primitive for cross-user / cross-context attack.' `
                -Fix 'Constrain the pipe DACL to the app principal + SYSTEM only.'
        }
    }
}
