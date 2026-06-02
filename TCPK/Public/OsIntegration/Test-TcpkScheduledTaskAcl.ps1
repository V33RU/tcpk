function Test-TcpkScheduledTaskAcl {
<#
.SYNOPSIS
    C15. User-modifiable scheduled tasks (privilege escalation).

.DESCRIPTION
    Scheduled tasks are stored as XML under C:\Windows\System32\Tasks. If a
    task that runs as SYSTEM / an administrator has a task-definition file (or
    its registry twin) writable by a standard user, that user can rewrite the
    Action to run an arbitrary command at the task's privilege -> EoP.

    For each task matching -NameLike this checks the on-disk task file DACL and
    reports the principal the task runs as.

.PARAMETER NameLike
    Vendor/product substring to match the task name.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string[]]$NameLike)

    if (-not (Assert-TcpkWindows 'Test-TcpkScheduledTaskAcl')) { return }

    $terms = Get-TcpkNameTerms -NameLike $NameLike
    if (-not $terms.Count) { return }

    $taskDir = Join-Path $env:SystemRoot 'System32\Tasks'
    if (-not (Test-Path $taskDir)) { return }
    $userPrincipals = '(?i)\b(Everyone|Authenticated Users|BUILTIN\\Users|\\Users$|^Users$|INTERACTIVE)\b'

    $files = Get-ChildItem -LiteralPath $taskDir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { Test-TcpkTermMatch -Text $_.Name -Terms $terms }

    foreach ($f in $files) {
        # runs-as principal + action, from the task XML
        $runAs = '(unknown)'; $action = ''
        try {
            [xml]$xml = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
            if ($xml.Task.Principals.Principal.UserId)    { $runAs = $xml.Task.Principals.Principal.UserId }
            if ($xml.Task.Principals.Principal.GroupId)   { $runAs = $xml.Task.Principals.Principal.GroupId }
            if ($xml.Task.Principals.Principal.RunLevel)  { $runAs += " ($($xml.Task.Principals.Principal.RunLevel))" }
            if ($xml.Task.Actions.Exec.Command)           { $action = $xml.Task.Actions.Exec.Command }
        } catch { }

        $acl = $null
        try { $acl = Get-Acl -LiteralPath $f.FullName -ErrorAction Stop } catch { continue }
        $weak = $acl.Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            "$($_.IdentityReference)" -match $userPrincipals -and
            "$($_.FileSystemRights)" -match 'Write|Modify|FullControl'
        }

        $runsPrivileged = $runAs -match '(?i)SYSTEM|HighestAvailable|Administrators|S-1-5-18'
        if ($weak -and $runsPrivileged) {
            $grant = ($weak | ForEach-Object { "$($_.IdentityReference)=$($_.FileSystemRights)" } | Select-Object -Unique) -join '; '
            New-TcpkFinding -Module 'os' -RuleId 'scheduled-task.user-writable' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "User-writable privileged task: $($f.Name) runs as $runAs" `
                -File $f.FullName -Evidence "action=$action | $grant" -Cwe @('CWE-732','CWE-269') `
                -Description 'A standard user can rewrite this task definition, which executes at a privileged identity. Editing the Action grants arbitrary code execution as that identity (privilege escalation).' `
                -Fix 'Restrict the task file (and its HKLM\...\Schedule\TaskCache twin) so only SYSTEM/Administrators can write.'
        }
        else {
            # still surface the privileged task as INFO triage even if ACL is tight
            New-TcpkFinding -Module 'os' -RuleId 'scheduled-task.present' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "Scheduled task: $($f.Name) runs as $runAs" `
                -File $f.FullName -Evidence "action=$action" `
                -Description 'Triage aid -- product scheduled task. ACL appears restricted; confirm the action target is not itself user-writable.'
        }
    }
}
