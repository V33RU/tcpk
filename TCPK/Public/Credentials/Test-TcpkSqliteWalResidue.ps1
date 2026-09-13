function Test-TcpkSqliteWalResidue {
<#
.SYNOPSIS
    D10. Secret residue in SQLite write-ahead-log / rollback-journal sidecars
    (<db>-wal, <db>-journal, <db>-shm). Complements Test-TcpkLocalDb (which reads
    the committed database) by scanning the UNCOMMITTED / rolled-back pages that a
    client-side "delete" leaves behind.

.DESCRIPTION
    SQLite in WAL mode writes new/changed pages to <db>-wal before they are
    checkpointed into the main file; in rollback-journal mode it copies the ORIGINAL
    pages into <db>-journal before overwriting them. Either way, when an app
    "deletes" a token row, rotates a key, or clears a credential, the plaintext of
    the old value very often survives verbatim in the sidecar until the next
    checkpoint / vacuum - which for a rarely-restarted desktop app can be a long
    time, or forever if the app crashes.

    This scans each sidecar's raw bytes for credential-shaped strings. It does NOT
    parse the SQLite page format (that would need the schema); a raw string scan
    over the sidecar is enough to prove residue and is the same technique a local
    attacker would use.

    Rules:
      localdb.sqlite-wal-residue     HIGH   Confirmed  A <db>-wal / <db>-journal
                                                        sidecar contains a
                                                        credential-shaped string
                                                        (token / bearer / password /
                                                        api key / JWT / a
                                                        Bearer/Basic auth header).
      localdb.sqlite-wal-present     LOW    Confirmed  A sidecar is present but no
                                                        credential string was found.
                                                        Scope info: the residue
                                                        surface exists even if this
                                                        snapshot is clean.

.PARAMETER Path
    Install directory or a single SQLite DB / sidecar file.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    # Sidecars by extension suffix. We also accept an explicit sidecar file.
    $sidecarSuffix = @('-wal','-journal')

    $files = @()
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        try {
            $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                       Where-Object {
                           $n = $_.Name.ToLowerInvariant()
                           ($n.EndsWith('-wal') -or $n.EndsWith('-journal')) -and $_.Length -gt 32 -and $_.Length -lt 67108864
                       })
        } catch { return }
    } else {
        $n = $item.Name.ToLowerInvariant()
        if ($n.EndsWith('-wal') -or $n.EndsWith('-journal')) { $files = @($item) }
    }
    if ($files.Count -eq 0) { return }

    # Credential-shaped patterns. Applied over BOTH an ASCII and a UTF-16LE decode of
    # the raw bytes, because SQLite stores TEXT as UTF-8 but a value that came from a
    # .NET string column round-trips as UTF-8 too; UTF-16 is scanned defensively.
    $credRx = @(
        @{ Id='jwt';        Rx='(?-i)eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}';                      Why='A JWT (three base64url segments) survives in the sidecar.' }
        @{ Id='bearer';     Rx='(?i)(authorization"?\s*[:=]\s*"?\s*)?bearer\s+[A-Za-z0-9._~+/-]{20,}';                     Why='A Bearer token / Authorization header value.' }
        @{ Id='basic-auth'; Rx='(?i)authorization"?\s*[:=]\s*"?\s*basic\s+[A-Za-z0-9+/]{16,}={0,2}';                        Why='A Basic auth header (base64 user:pass).' }
        @{ Id='api-key';    Rx='(?i)(api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret)"?\s*[:=]\s*"?[A-Za-z0-9._\-]{16,}'; Why='An API / access / secret key value.' }
        @{ Id='password';   Rx='(?i)(password|passwd|pwd)"?\s*[:=]\s*"?[^\s"'']{6,64}';                                     Why='A password field value.' }
        @{ Id='aws';        Rx='(?-i)AKIA[0-9A-Z]{16}';                                                                     Why='An AWS access key id.' }
    )

    foreach ($f in $files) {
        $bytes = $null
        try { $bytes = [IO.File]::ReadAllBytes($f.FullName) } catch { continue }
        if (-not $bytes -or $bytes.Length -lt 32) { continue }

        $ascii = [Text.Encoding]::ASCII.GetString($bytes)
        $utf16 = ''
        try { $utf16 = [Text.Encoding]::Unicode.GetString($bytes) } catch { }

        $fired = $false
        foreach ($c in $credRx) {
            foreach ($hay in @($ascii, $utf16)) {
                if (-not $hay) { continue }
                $mm = [regex]::Match($hay, $c.Rx)
                if ($mm.Success) {
                    $sample = $mm.Value
                    if ($sample.Length -gt 12) { $sample = $sample.Substring(0, 6) + '***' + $sample.Substring($sample.Length - 3, 3) }
                    New-TcpkFinding -Module 'creds' -RuleId 'localdb.sqlite-wal-residue' `
                        -Severity 'HIGH' -Confidence 'Confirmed' `
                        -Title "Credential residue in SQLite sidecar: $($f.Name) ($($c.Id))" `
                        -File $f.FullName -Evidence "match=$($c.Id) sample=$sample" `
                        -Cwe @('CWE-212','CWE-312','CWE-522') `
                        -Description ('A SQLite write-ahead-log / rollback-journal sidecar contains a ' +
                            "credential-shaped string ($($c.Why)). SQLite writes changed / original pages to " +
                            'the sidecar before a checkpoint; when the app "deletes" a token row or rotates a ' +
                            'key, the old plaintext very often survives verbatim in the sidecar until the next ' +
                            'checkpoint or vacuum. Any local process that can read the file recovers the ' +
                            'credential the app believes it has cleared.') `
                        -Fix 'After deleting or rotating a secret, run "PRAGMA wal_checkpoint(TRUNCATE)" (WAL mode) or VACUUM to flush the sidecar. Better, do not store long-lived credentials in a local SQLite DB at all - use DPAPI / the OS credential store. Restrict the DB directory DACL to the app user only.'
                    $fired = $true
                    break
                }
            }
            if ($fired) { break }
        }

        if (-not $fired) {
            New-TcpkFinding -Module 'creds' -RuleId 'localdb.sqlite-wal-present' `
                -Severity 'LOW' -Confidence 'Confirmed' `
                -Title "SQLite sidecar present (residue surface): $($f.Name)" `
                -File $f.FullName -Evidence "size=$($f.Length) bytes" `
                -Cwe @('CWE-212') `
                -Description ('A SQLite -wal / -journal sidecar is present. No credential-shaped string was ' +
                    'found in this snapshot, but the residue surface exists: a future delete / rotate can ' +
                    'leave plaintext here until the next checkpoint. Scope information for the reader.') `
                -Fix 'Checkpoint (PRAGMA wal_checkpoint(TRUNCATE)) or VACUUM after secret mutations; restrict the DB directory DACL to the app user.'
        }
    }
}
