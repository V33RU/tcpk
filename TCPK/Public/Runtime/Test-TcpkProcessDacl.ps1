function Test-TcpkProcessDacl {
<#
.SYNOPSIS
    E15. Running-process DACL -- injectable by low-privileged users?

.DESCRIPTION
    Reads the target process's discretionary ACL (GetSecurityInfo) and flags any
    ACE that grants a LOW-PRIVILEGE well-known group (Everyone / Authenticated
    Users / Users / INTERACTIVE / Anonymous) one of the takeover rights:
    PROCESS_VM_WRITE, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION,
    PROCESS_DUP_HANDLE, WRITE_DAC, WRITE_OWNER, or PROCESS_ALL_ACCESS.

    Such a grant lets an unprivileged local user inject code into the process
    (or rewrite its DACL). Whether that is an ESCALATION is measured, not assumed:
    the process integrity level is read and the severity set from it. The granted
    principals run at Medium, so a Medium target is level with them (code
    injection, no boundary crossed, MEDIUM), a High or System target is above them
    (escalation, HIGH), and a Low target is below them (LOW). An unreadable
    integrity level stays HIGH, because an unmeasured boundary must not read as an
    absent one. The process owner's own full-control ACE is intentionally ignored
    (that is normal, not a finding).

.PARAMETER ProcessName
    Name of the running process (no .exe).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName='ById')][int]$ProcessId
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkProcessDacl')) { return }

    if (-not ('Tcpk.ProcDacl' -as [type])) {
        Add-Type -Namespace 'Tcpk' -Name 'ProcDacl' -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
[DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
[DllImport("kernel32.dll")] public static extern IntPtr LocalFree(IntPtr p);
[DllImport("advapi32.dll")]
public static extern uint GetSecurityInfo(IntPtr handle, int objectType, int securityInfo,
   IntPtr o, IntPtr g, IntPtr dacl, IntPtr sacl, out IntPtr sd);
[DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
   IntPtr sd, uint rev, int si, out IntPtr str, out int len);

public static string GetSddl(int pid){
   IntPtr h = OpenProcess(0x0400 | 0x00020000, false, pid); // QUERY_INFORMATION | READ_CONTROL
   if (h == IntPtr.Zero) return null;
   try {
      IntPtr sd;
      uint r = GetSecurityInfo(h, 6, 4, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out sd); // SE_KERNEL_OBJECT, DACL
      if (r != 0 || sd == IntPtr.Zero) return null;
      IntPtr str; int len;
      bool ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, 4, out str, out len);
      string s = ok ? System.Runtime.InteropServices.Marshal.PtrToStringUni(str) : null;
      if (str != IntPtr.Zero) LocalFree(str);
      LocalFree(sd);
      return s;
   } finally { CloseHandle(h); }
}
'@
    }

    $rights = [ordered]@{
        CREATE_THREAD = 0x0002; VM_OPERATION = 0x0008; VM_WRITE = 0x0020;
        DUP_HANDLE = 0x0040; WRITE_DAC = 0x40000; WRITE_OWNER = 0x80000;
        ALL_ACCESS = 0x1F0FFF
    }
    $dangerMask = 0
    foreach ($v in $rights.Values) { $dangerMask = $dangerMask -bor $v }

    # The shared list from Private\_ObjSecurity.ps1, not a local copy. This file used to
    # declare a byte-identical literal, so adding a principal in one place left this check
    # grading by the old set: process.dacl-injectable silently kept the narrower view.
    $lowSids = $script:TcpkLowPrivSids

    $procs = if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Get-TcpkProcess -ProcessName $ProcessName
    } else {
        Get-TcpkProcess -ProcessId $ProcessId
    }

    foreach ($p in $procs) {
        # Whether a weak process DACL is an ESCALATION depends on where this process sits
        # relative to the principal being granted the rights. The low-privilege groups in
        # $lowSids run at Medium by default, so injecting into another Medium process
        # crosses no boundary: it is the same privilege the attacker already has. Only a
        # target ABOVE Medium turns the grant into privilege escalation. The check used to
        # emit HIGH either way and pass the question to the reader in its own Description
        # ("If this process is elevated/SYSTEM..."), which is the one thing it was in a
        # position to measure. -1 means the integrity could not be read, which is treated
        # as unknown rather than assumed safe.
        $intRid = -1
        try { $intRid = Get-TcpkProcessIntegrityRid -ProcessId $p.Id } catch { $intRid = -1 }
        $intLabel = if ($intRid -ge 0) { Get-TcpkIntegrityLabel -Rid $intRid } else { 'unreadable' }

        $sddl = $null
        try { $sddl = [Tcpk.ProcDacl]::GetSddl($p.Id) } catch { $sddl = $null }
        if (-not $sddl) {
            New-TcpkFinding -Module 'runtime' -RuleId 'process.dacl-unreadable' `
                -Severity 'INFO' -Confidence 'Skipped' `
                -Title "Could not read DACL for $($p.Name) (PID $($p.Id))" `
                -File "$($p.Name) (PID $($p.Id))" -Evidence 'OpenProcess/GetSecurityInfo denied (likely insufficient rights).'
            continue
        }

        $rsd = $null
        try { $rsd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddl) } catch { continue }
        if (-not $rsd.DiscretionaryAcl) { continue }

        foreach ($ace in $rsd.DiscretionaryAcl) {
            if ("$($ace.AceType)" -notmatch 'AccessAllowed') { continue }
            $sid = $ace.SecurityIdentifier
            $sidVal = $sid.Value
            $isLow = $false
            foreach ($ls in $lowSids) { if ($sidVal -eq $ls) { $isLow = $true; break } }
            if (-not $isLow) { continue }

            $mask = [int]$ace.AccessMask
            if (($mask -band $dangerMask) -eq 0) { continue }

            $granted = @()
            foreach ($rn in $rights.Keys) { if ($mask -band $rights[$rn]) { $granted += $rn } }
            $acct = try { $sid.Translate([System.Security.Principal.NTAccount]).Value } catch { $sidVal }

            # High / System is above the granted principal -> escalation.
            # Medium is level with it -> code injection, but no boundary crossed.
            # Low / Untrusted is below it -> not an escalation at all.
            # Unreadable stays HIGH: an unmeasured boundary must not read as absent.
            $sev = if ($intRid -lt 0)          { 'HIGH' }
                   elseif ($intRid -ge 0x3000) { 'HIGH' }
                   elseif ($intRid -ge 0x2000) { 'MEDIUM' }
                   else                        { 'LOW' }

            $boundary = switch ($sev) {
                'HIGH'   { if ($intRid -lt 0) {
                               'the integrity level could not be read, so whether this crosses a privilege boundary is unmeasured and the finding is rated as if it does'
                           } else {
                               "this process runs at $intLabel integrity, above the granted principal, so the grant is a privilege-escalation primitive"
                           } }
                'MEDIUM' { "this process runs at $intLabel integrity, the same level as the granted principal, so injecting into it is code execution in a context the caller already has rather than an escalation" }
                default  { "this process runs at $intLabel integrity, BELOW the granted principal, so the grant is not an escalation path" }
            }

            New-TcpkFinding -Module 'runtime' -RuleId 'process.dacl-injectable' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "$($p.Name) process DACL grants injection rights to $acct (target integrity: $intLabel)" `
                -File "$($p.Name) (PID $($p.Id))" `
                -Evidence "$acct ($sidVal) -> $($granted -join ', '); target integrity=$intLabel" `
                -Cwe @('CWE-732','CWE-269') `
                -Description ('A low-privileged group is granted process rights that allow code injection ' +
                    'or a DACL rewrite on this process. Severity is set by the measured integrity level, ' +
                    'not assumed: ' + $boundary + '. The rights themselves are the same in every case; what ' +
                    'changes is whether using them gains the attacker anything they did not already have.') `
                -Fix 'Do not loosen the default process DACL. Remove explicit grants to Users/Everyone/Authenticated Users.'
        }
    }
}
