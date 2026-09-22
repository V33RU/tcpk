function Test-TcpkAuthFlags {
<#
.SYNOPSIS
    A23. Client-side authorization, privilege and licensing gates.

.DESCRIPTION
    A thick client that decides locally whether the user is allowed to do something has
    already lost the argument: the attacker owns the process. Patch the binary, flip the
    value in memory, or return true from the check, and the feature opens.

    TWO KINDS OF GATE, AND THE SECOND ONE MATTERS MORE.
    Licensing gates (IsLicensed, IsTrial, IsPro) cost the vendor revenue. PRIVILEGE gates
    (isAdmin, userRole, accessLevel) cost the vendor their authorization model, because the
    same flag usually decides which UI, which menu and which server calls the user gets.
    Only the licensing family was listed here before, so a role check was invisible.

    NAMES COME FROM METADATA, NOT FROM THE STRING TABLE.
    The earlier implementation searched the decoded bytes of the whole file for gate-shaped
    text. That fails in both directions at once: any assembly that merely CONTAINS the text
    matches, so a bundled third-party library gets reported for a gate it does not have,
    while a real gate is reported with no evidence that the name is used in a decision.
    Field and property names live in the metadata tables, so reading them there means a
    match is a member this assembly actually declares or calls.

    IL DECIDES THE CONFIDENCE.
    Get-TcpkClientGateVerdicts requires the member to be loaded AND consumed by a branch or
    comparison. When that holds the finding is 'Confirmed (IL)' and carries the type, method,
    metadata token and the IL itself, so the claim can be checked in a decompiler in seconds.
    A name that never reaches a branch is reported at INFO as an inventory entry, because a
    field called IsLicensed that is only ever serialized is not a gate.

    WHAT IT CANNOT SEE. Local variable names do not survive a release build without a PDB,
    so a gate held in a local is undetectable by name whatever it is called. A value read
    from a database, a server response or a file and branched on immediately is also a
    client-side gate, and catching that shape needs taint analysis rather than a name list.
    Neither gap is closed here.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    # Licensing and activation gates: the feature is paid for, the check is local.
    $licenceFlags = @(
        'IsLicensed', 'IsTrial', 'IsActivated', 'IsRegistered', 'IsPremium', 'IsPro',
        'IsPaid', 'IsPaidUser', 'IsUnlocked', 'HasLicense', 'HasValidLicense', 'LicenseValid',
        'IsValidLicense', 'IsFullVersion', 'IsActivatedLicense', 'CheckLicense',
        'ValidateLicense', 'IsExpired', 'IsDemo', 'DemoMode', 'IsCracked'
    )
    # Authorization and privilege gates: the check decides what the user may DO. These were
    # absent, which is why a role-based gate produced nothing at all.
    $privFlags = @(
        'IsAdmin', 'IsAdministrator', 'IsSuperUser', 'IsRoot', 'IsElevated', 'IsPrivileged',
        'IsOwner', 'IsStaff', 'IsManager', 'IsSupervisor', 'IsOperator', 'IsGuest',
        'IsAuthorized', 'IsApproved', 'HasPermission', 'HasAccess', 'HasRole', 'CanAccess',
        'CanEdit', 'CanDelete', 'CanApprove', 'CanManage', 'AccessLevel', 'UserRole',
        'UserLevel', 'PrivilegeLevel', 'PermissionLevel', 'RoleId', 'AdminMode'
    )
    # Explicit bypasses. A member named this way is a finding on sight.
    $bypassFlags = @(
        'BypassAuth', 'SkipAuth', 'SkipLogin', 'BypassLogin', 'NoLicenseCheck',
        'LicenseBypass', 'SkipValidation', 'DisableSecurity', 'IgnoreCertificateErrors'
    )

    $all = @($licenceFlags + $privFlags + $bypassFlags)
    # Anchored whole-name match. An unanchored pattern would fire on any member whose name
    # merely contains the text, which is the failure being fixed, not repeated.
    $nameRx = '^(?i)(' + (($all | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')$'

    $byKind = @{}
    foreach ($n in $licenceFlags) { $byKind[$n.ToLowerInvariant()] = 'licensing' }
    foreach ($n in $privFlags)    { $byKind[$n.ToLowerInvariant()] = 'authorization' }
    foreach ($n in $bypassFlags)  { $byKind[$n.ToLowerInvariant()] = 'security bypass' }

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        if (Test-TcpkIsNativeNoise $pe.Name)   { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        if (-not $text.Contains('BSJB')) { continue }   # managed only

        $verdicts = @()
        try { $verdicts = @(Get-TcpkClientGateVerdicts -DllPath $pe.FullName -NameRegex $nameRx) } catch { $verdicts = @() }
        if ($verdicts.Count -eq 0) { continue }

        # One finding per distinct member, listing every decision point it reaches. Emitting
        # per call site would bury a single real gate under a dozen near-identical rows.
        foreach ($g in ($verdicts | Group-Object Member)) {
            $member = "$($g.Name)"
            $kind = 'authorization'
            $k = $member.ToLowerInvariant()
            if ($byKind.ContainsKey($k)) { $kind = $byKind[$k] }

            $sites = @($g.Group)
            $first = $sites[0]
            $where = New-Object 'System.Collections.Generic.List[string]'
            foreach ($s in ($sites | Select-Object -First 5)) {
                $where.Add("$($s.Type)::$($s.Method) ($($s.Token)) via $($s.Branch)")
            }
            $more = ''
            if ($sites.Count -gt 5) { $more = " ...(+$($sites.Count - 5) more)" }

            $sev = 'MEDIUM'
            if ($kind -eq 'security bypass')  { $sev = 'HIGH' }
            elseif ($kind -eq 'authorization') { $sev = 'HIGH' }

            New-TcpkFinding -Module 'static' -RuleId 'authflags.client-side-gate' `
                -Severity $sev -Confidence 'Confirmed (IL)' `
                -Title "Client-side $kind gate '$member' decides control flow in $($pe.Name)" `
                -File $pe.FullName `
                -Evidence ("$member consumed by a branch at $($sites.Count) site(s): " + ($where -join '; ') + $more) `
                -Cwe @('CWE-602', 'CWE-603') `
                -Description ("The member '$member' is loaded and fed straight into a conditional branch, so this " +
                    "$kind decision is made inside the client process. An attacker controls that process: the value " +
                    "can be patched in the binary, flipped in memory while the app runs, or the accessor made to " +
                    "return a constant. Whatever the check protects opens without the server being involved. " +
                    "IL proof at $($first.Type)::$($first.Method) ($($first.Token)):`n$($first.Il)") `
                -Fix ('Make the decision on the server and have the client render what the server returns. ' +
                    'If the flag must exist client-side for UI purposes, treat it as a display hint only and ' +
                    're-authorize every privileged operation server-side.')
        }
    }
}
