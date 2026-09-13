function Save-TcpkFileSnapshot {
<#
.SYNOPSIS
    C19a. Regshot-style FILE-SYSTEM snapshot (before/after the app runs).

.DESCRIPTION
    Captures every file under the given root(s) - relative path, size, last-write
    time, and SHA-256 - into a JSON snapshot. Run it BEFORE launching the app, run
    the app (login, license check, data export, update), then run it AGAIN to a
    second file and diff with Compare-TcpkFileSnapshot to see exactly what the app
    created, modified, or deleted (dropped binaries, cached creds, temp residue).

    This is the file-system twin of Save/Compare-TcpkRegistrySnapshot.

.PARAMETER OutFile
    Path to write the snapshot JSON.

.PARAMETER Root
    Directory root(s) to capture, e.g. the install dir, %LOCALAPPDATA%\Vendor,
    %ProgramData%\Vendor, or %TEMP%.

.PARAMETER MaxHashBytes
    Skip hashing files larger than this (size+mtime still recorded). Default 100 MB.

.OUTPUTS
    [TcpkFinding] (one INFO confirming the snapshot)
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutFile,
        [Parameter(Mandatory)][string[]]$Root,
        [long]$MaxHashBytes = 104857600
    )

    $snap = @{}
    foreach ($r in $Root) {
        if (-not (Test-Path -LiteralPath $r)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $r -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            $hash = ''
            if ($f.Length -le $MaxHashBytes) {
                try { $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $hash = '' }
            } else { $hash = 'SKIPPED-LARGE' }
            # Owner and a broad-principal DACL summary. Without these the diff can say a
            # file appeared but not whether other local users can read it, which is the
            # question that decides whether a runtime-created temp or cache file matters.
            # Read best-effort: a locked or reparse-pointed file must not abort the walk.
            $owner = ''; $broad = ''
            try {
                $acl = Get-Acl -LiteralPath $f.FullName -ErrorAction Stop
                try { $owner = "$($acl.Owner)" } catch { $owner = '' }
                $hits = New-Object 'System.Collections.Generic.List[string]'
                foreach ($ace in $acl.Access) {
                    if ("$($ace.AccessControlType)" -ne 'Allow') { continue }
                    $id = "$($ace.IdentityReference)"
                    if ($id -match '(?i)\b(Everyone|Authenticated Users|BUILTIN\\Users|Users|INTERACTIVE|ANONYMOUS)\b') {
                        $hits.Add("$id=$($ace.FileSystemRights)")
                    }
                }
                if ($hits.Count) { $broad = ($hits | Select-Object -Unique) -join '; ' }
            } catch { }

            $snap[$f.FullName] = [ordered]@{
                Size  = $f.Length
                Mtime = $f.LastWriteTimeUtc.ToString('o')
                Sha256 = $hash
                Owner  = $owner
                BroadAcl = $broad
            }
        }
    }
    Confirm-TcpkParentDir -FilePath $OutFile
    Save-TcpkJson -Value $snap -Path $OutFile -Depth 4

    New-TcpkFinding -Module 'os' -RuleId 'fs.snapshot' `
        -Severity 'INFO' -Confidence 'Confirmed' `
        -Title "File-system snapshot saved ($($snap.Count) files)" `
        -File $OutFile -Evidence "roots: $($Root -join ', ')" `
        -Description 'Run this before AND after exercising the app, then Compare-TcpkFileSnapshot to see what the app created/modified/deleted on disk.'
}
