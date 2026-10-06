function Test-TcpkInstallDirAcl {
<#
.SYNOPSIS
    C01. Non-admin-writable files in an admin-installed directory.

.DESCRIPTION
    Walks the path and emits a HIGH finding for any file or directory whose
    ACL grants Write / Modify / FullControl to Everyone / Authenticated Users
    / Users / INTERACTIVE. A non-admin-writable file inside a path that the
    app runs from elevated is a privilege-escalation primitive.

.PARAMETER Path
    Directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkInstallDirAcl')) { return }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }

    $entries = Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
    foreach ($e in $entries) {
        try { $acl = Get-Acl -LiteralPath $e.FullName -ErrorAction Stop } catch { continue }
        $bad = $acl.Access | Where-Object {
            $_.IdentityReference.Value -match '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE)\b' -and
            $_.FileSystemRights -match 'Write|Modify|FullControl' -and
            $_.AccessControlType -eq 'Allow'
        }
        if ($bad) {
            $grant = ($bad | ForEach-Object { "$($_.IdentityReference) -> $($_.FileSystemRights)" }) -join '; '
            New-TcpkFinding -Module 'os' -RuleId 'install-dir.user-writable' `
                -Description 'An item in the application install directory is writable by a non-admin user, in a location the app and its services load from with elevated trust. A standard user replaces that file and the next privileged load runs attacker-controlled content, which is local privilege escalation.' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "User-writable item in admin install context: $($e.Name)" `
                -File $e.FullName -Evidence $grant `
                -Cwe @('CWE-732','CWE-276') `
                -Fix 'Reset ACL to inherit from Program Files; remove explicit grants to non-admin principals.'
        }
    }
}
