function Test-TcpkMailslotDacl {
<#
.SYNOPSIS
    E23. Mailslot enumeration + DACL inspection. Test-TcpkNamedObjects / Test-TcpkMailslotsAlpc
    surface that a mailslot EXISTS; this reads whether a non-admin can read or write it.

.DESCRIPTION
    A mailslot (\\.\mailslot\<name>) is a one-way IPC channel. AV agents, backup
    daemons, licensing services and vendor telemetry frequently open a mailslot to
    broadcast status or receive commands. If the mailslot's DACL is permissive:
      * a readable mailslot leaks whatever the server broadcasts (status, usernames,
        host inventory, sometimes tokens);
      * a writable mailslot lets any local process inject messages the privileged
        reader will act on.

    Mailslots do not enumerate through a directory listing the way pipes do
    (\\.\mailslot\ is not browsable), so this cmdlet checks a supplied / derived
    name list: -NameLike terms plus a small set of well-known vendor-agent mailslot
    name shapes. For each name that opens, it reads the DACL via a mailslot client
    handle and grades a broad-principal Allow ACE.

    Rules:
      mailslot.dacl-weak       HIGH   Confirmed  A mailslot DACL grants Everyone /
                                                  Authenticated Users / Users /
                                                  INTERACTIVE a read or write right.
      mailslot.dacl-unreadable INFO   Skipped    The mailslot opened but its DACL
                                                  could not be read.

.PARAMETER NameLike
    Mailslot name substring(s) to probe (case-insensitive). The audited product
    name / vendor terms are the right input here; a mailslot is named by its server.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()] param([string[]]$NameLike = @())

    if (-not (Assert-TcpkWindows 'Test-TcpkMailslotDacl')) { return }

    $terms = Get-TcpkNameTerms -NameLike $NameLike
    if (-not $terms.Count) { return }

    $riskyId    = '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE|BUILTIN\\Users|ANONYMOUS)\b'
    $riskyRights = 'Read|Write|Modify|FullControl|ReadData|WriteData|AppendData|ChangePermissions'

    # Candidate mailslot names: each term as-is, plus a couple of common server-name
    # shapes vendors use. A mailslot open with GENERIC_READ does not send data.
    $candidates = New-Object 'System.Collections.Generic.List[string]'
    foreach ($t in $terms) {
        [void]$candidates.Add($t)
        [void]$candidates.Add("$t\status")
        [void]$candidates.Add("$t\agent")
        [void]$candidates.Add("$t\messages")
        [void]$candidates.Add("$t\events")
    }

    foreach ($name in ($candidates | Select-Object -Unique)) {
        $slot = "\\.\mailslot\$name"
        # Open the mailslot as a CLIENT with a plain CreateFile via .NET FileStream.
        # Reading a mailslot's ACL: open a handle then Get-Acl on the pipe/handle path
        # is not supported by Get-Acl for the mailslot namespace, so use the SD from
        # a SafeFileHandle via GetSecurityInfo. To stay in-band without P/Invoke, try
        # to open the mailslot for GENERIC_READ and, if it opens, report existence;
        # then read the DACL through the .NET FileSecurity on the handle where the OS
        # allows it. Mailslot DACL reads frequently fail for a client handle, so an
        # unreadable-but-openable slot is reported as Skipped rather than silently
        # dropped.
        $fs = $null
        try {
            $fs = [System.IO.File]::Open($slot, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        } catch {
            continue   # mailslot not present under this name; not an error
        }
        try {
            $acl = $null
            try {
                $acl = $fs.GetAccessControl()
            } catch { $acl = $null }
            if (-not $acl) {
                New-TcpkFinding -Module 'runtime' -RuleId 'mailslot.dacl-unreadable' `
                    -Severity 'INFO' -Confidence 'Skipped' `
                    -Title "Mailslot present but DACL unreadable: $name" `
                    -File $slot -Evidence 'opened for read; GetAccessControl threw' `
                    -Description 'The mailslot opened for a client read but its security descriptor could not be read through the client handle. The mailslot exists; its DACL is unassessed rather than clean.'
                continue
            }
            $bad = $acl.Access | Where-Object {
                $_.AccessControlType.ToString() -eq 'Allow' -and
                "$($_.IdentityReference)" -match $riskyId -and
                "$($_.FileSystemRights)" -match $riskyRights
            }
            if ($bad) {
                $grant = ($bad | ForEach-Object { "$($_.IdentityReference) -> $($_.FileSystemRights)" } | Select-Object -Unique) -join '; '
                New-TcpkFinding -Module 'runtime' -RuleId 'mailslot.dacl-weak' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "Mailslot DACL grants a broad principal read/write: $name" `
                    -File $slot -Evidence $grant `
                    -Cwe @('CWE-732','CWE-200') `
                    -Description ('A mailslot server left a permissive DACL. A readable mailslot leaks whatever ' +
                        'the server broadcasts (status, host inventory, usernames, sometimes tokens); a writable ' +
                        'mailslot lets any local process inject messages the privileged reader acts on. Vendor ' +
                        'AV / backup / licensing agents are the usual owners of a broadcast mailslot.') `
                    -Fix 'Pass an explicit SECURITY_ATTRIBUTES with a DACL restricted to the app principal + SYSTEM when calling CreateMailslot. Do not rely on the default (which grants broad read on some Windows versions).'
            }
        } finally {
            if ($fs) { try { $fs.Dispose() } catch {} }
        }
    }
}
