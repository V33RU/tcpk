function Test-TcpkTokenDacl {
<#
.SYNOPSIS
    E20. Access-token DACL -- can a low-privileged user duplicate or adjust it?

.DESCRIPTION
    Test-TcpkProcessToken reports what the token CONTAINS (privileges, integrity
    level, elevation). This reports who may OPERATE ON it.

    The token is a securable object with its own DACL, and the rights that matter
    are different from the process ones:

      TOKEN_DUPLICATE     clone the token, then CreateProcessAsUser with it. On an
                          elevated or SYSTEM process this is a direct escalation
                          and needs no code injection at all.
      TOKEN_IMPERSONATE   assume the identity on a thread.
      TOKEN_ADJUST_*      enable a disabled privilege already present in the token,
                          or change its groups and default DACL.

    Flags any allow-ACE granting one of those to a low-privilege well-known group.
    The default token DACL grants none of them to those groups, so a hit means
    something explicitly widened it.

    Read-only: opens the process with PROCESS_QUERY_INFORMATION and the token with
    TOKEN_QUERY | READ_CONTROL.

.PARAMETER ProcessName
    Name of the running process (no .exe).

.PARAMETER ProcessId
    Specific PID instead of resolving by name.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName='ById')][int]$ProcessId
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkTokenDacl')) { return }
    if (-not ('Tcpk.ObjSec' -as [type])) {
        New-TcpkSkippedFinding -RuleId 'token-dacl.unavailable' `
            -Title 'Token security-descriptor primitive unavailable' `
            -Reason 'Tcpk.ObjSec failed to compile.'
        return
    }

    $rights = [ordered]@{
        DUPLICATE = 0x0002; IMPERSONATE = 0x0004; ADJUST_PRIVILEGES = 0x0020
        ADJUST_GROUPS = 0x0040; ADJUST_DEFAULT = 0x0080; ADJUST_SESSIONID = 0x0100
        WRITE_DAC = 0x40000; WRITE_OWNER = 0x80000; ALL_ACCESS = 0xF01FF
    }

    $procs = if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Get-TcpkProcess -ProcessName $ProcessName
    } else {
        Get-TcpkProcess -ProcessId $ProcessId
    }

    foreach ($p in $procs) {
        $sddl = $null
        try { $sddl = [Tcpk.ObjSec]::GetTokenSddl($p.Id) } catch { }
        if (-not $sddl) {
            New-TcpkSkippedFinding -RuleId 'token.dacl-unreadable' `
                -Title "Could not read token DACL for $($p.Name) (PID $($p.Id))" `
                -Reason 'OpenProcessToken/GetSecurityInfo denied (likely insufficient rights).'
            continue
        }

        foreach ($g in (Get-TcpkSddlLowPrivGrants -Sddl $sddl -RightsMap $rights)) {
            # TOKEN_DUPLICATE is the one that needs no further primitive, so it leads
            # the severity decision.
            $sev = 'MEDIUM'
            if ($g.Granted -contains 'DUPLICATE' -or $g.Granted -contains 'ALL_ACCESS' -or
                $g.Granted -contains 'IMPERSONATE' -or $g.Granted -contains 'WRITE_DAC') { $sev = 'HIGH' }

            New-TcpkFinding -Module 'runtime' -RuleId 'token.dacl-weak' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "$($p.Name) token DACL grants $($g.Granted -join '/') to $($g.Account)" `
                -File "$($p.Name) (PID $($p.Id))" `
                -Evidence "$($g.Account) ($($g.Sid)) -> $($g.Granted -join ', ')" `
                -Cwe @('CWE-732', 'CWE-269') `
                -Description ('A low-privileged group holds rights over this process''s access token. ' +
                    'TOKEN_DUPLICATE is the sharpest of these: the token can be cloned and used with ' +
                    'CreateProcessAsUser, so if this process is elevated or runs as SYSTEM an ' +
                    'unprivileged local user gains those rights without injecting any code. ' +
                    'The default token DACL does not grant this, so it was widened deliberately.') `
                -Fix 'Restore the default token DACL. Never grant TOKEN_DUPLICATE, TOKEN_IMPERSONATE or TOKEN_ADJUST_* to Users, Everyone or Authenticated Users.'
        }
    }
}
