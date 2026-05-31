function Test-TcpkFolderAcls {
<#
.SYNOPSIS
    C05. Recursive ACL audit on a folder.

.DESCRIPTION
    More aggressive than Test-TcpkInstallDirAcl -- emits a finding for
    every user-writable item, not just files. Severity MEDIUM (vs HIGH for
    the install-dir version) because data dirs are sometimes legitimately
    user-writable.

.PARAMETER Path
    Folder.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkFolderAcls')) { return }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }

    foreach ($f in (Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue)) {
        try { $acl = Get-Acl -LiteralPath $f.FullName -ErrorAction Stop } catch { continue }
        $w = $acl.Access | Where-Object {
            $_.IdentityReference.Value -match '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE)\b' -and
            $_.FileSystemRights -match 'Write|Modify|FullControl' -and
            $_.AccessControlType -eq 'Allow'
        }
        if ($w) {
            $grant = ($w | ForEach-Object { "$($_.IdentityReference) $($_.FileSystemRights)" }) -join '; '
            New-TcpkFinding -Module 'os' -RuleId 'acl.user-writable' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "User-writable: $($f.Name)" `
                -File $f.FullName -Evidence $grant -Cwe @('CWE-732')
        }
    }
}
