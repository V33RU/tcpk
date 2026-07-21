function Test-TcpkNamedPipeDacl {
<#
.SYNOPSIS
    E05. Named pipe DACL inspection (TCAWin gap).

.DESCRIPTION
    Connects to each named pipe matching -NameLike as a client (briefly),
    reads back the pipe's SecurityIdentifier (RemotePipeAccess), and inspects
    the DACL via NamedPipeClientStream + GetAccessControl. Emits a finding
    for each ACE granting Everyone / Authenticated Users / Users / INTERACTIVE
    Write / FullControl on the pipe.

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
