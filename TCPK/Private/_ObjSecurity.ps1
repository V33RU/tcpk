# Security descriptors for kernel objects other than the process itself: THREADS and
# ACCESS TOKENS. Test-TcpkProcessDacl already covers the process object; these are the
# same class of bug on the neighbouring objects, and both are injection primitives in
# their own right:
#
#   thread  THREAD_SET_CONTEXT lets a caller rewrite the register state of a thread,
#           which redirects execution without ever touching process memory rights.
#   token   TOKEN_DUPLICATE on an elevated process's token lets a caller clone it and
#           spawn a process with those rights.
#
# Also exposes the token's UAC virtualization state, which is read from the same handle.
# Read-only throughout: opens with QUERY | READ_CONTROL and never modifies anything.

$script:TcpkObjSecSrc = @'
using System;
using System.Runtime.InteropServices;
namespace Tcpk {
 public static class ObjSec {
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint a, bool inh, int pid);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenThread(uint a, bool inh, int tid);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr h, uint a, out IntPtr tok);
  [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(IntPtr handle, int objectType, int securityInfo,
     IntPtr o, IntPtr g, IntPtr dacl, IntPtr sacl, out IntPtr sd);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr sd, uint rev, int si, out IntPtr str, out int len);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr tok, int cls, out uint val, int len, out int ret);

  const int SE_KERNEL_OBJECT = 6;
  const int DACL_SECURITY_INFORMATION = 4;
  const uint READ_CONTROL = 0x00020000;

  static string SddlFrom(IntPtr handle) {
     IntPtr sd;
     uint r = GetSecurityInfo(handle, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                              IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out sd);
     if (r != 0 || sd == IntPtr.Zero) return null;
     IntPtr str; int len;
     bool ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, DACL_SECURITY_INFORMATION, out str, out len);
     string s = ok ? Marshal.PtrToStringUni(str) : null;
     if (str != IntPtr.Zero) LocalFree(str);
     LocalFree(sd);
     return s;
  }

  // THREAD_QUERY_INFORMATION | READ_CONTROL
  public static string GetThreadSddl(int tid) {
     IntPtr h = OpenThread(0x0040 | READ_CONTROL, false, tid);
     if (h == IntPtr.Zero) return null;
     try { return SddlFrom(h); } finally { CloseHandle(h); }
  }

  // PROCESS_QUERY_INFORMATION -> TOKEN_QUERY | READ_CONTROL
  public static string GetTokenSddl(int pid) {
     IntPtr h = OpenProcess(0x0400, false, pid);
     if (h == IntPtr.Zero) return null;
     IntPtr tok = IntPtr.Zero;
     try {
        if (!OpenProcessToken(h, 0x0008 | READ_CONTROL, out tok)) return null;
        return SddlFrom(tok);
     } finally {
        if (tok != IntPtr.Zero) CloseHandle(tok);
        CloseHandle(h);
     }
  }

  // Packed UAC virtualization state: -1 unreadable, else (allowed ? 2 : 0) | (enabled ? 1 : 0).
  // TokenVirtualizationAllowed = 23, TokenVirtualizationEnabled = 24.
  public static int GetVirtualization(int pid) {
     IntPtr h = OpenProcess(0x0400, false, pid);
     if (h == IntPtr.Zero) return -1;
     IntPtr tok = IntPtr.Zero;
     try {
        if (!OpenProcessToken(h, 0x0008, out tok)) return -1;
        uint allowed = 0, enabled = 0; int ret;
        bool okA = GetTokenInformation(tok, 23, out allowed, 4, out ret);
        bool okE = GetTokenInformation(tok, 24, out enabled, 4, out ret);
        if (!okA && !okE) return -1;
        int v = 0;
        if (okA && allowed != 0) v |= 2;
        if (okE && enabled != 0) v |= 1;
        return v;
     } finally {
        if (tok != IntPtr.Zero) CloseHandle(tok);
        CloseHandle(h);
     }
  }
 }
}
'@

if (-not ('Tcpk.ObjSec' -as [type])) {
    try { Add-Type -TypeDefinition $script:TcpkObjSecSrc -ErrorAction Stop } catch { }
}

# Well-known low-privilege SIDs. Same set Test-TcpkProcessDacl uses, kept here so the
# thread and token checks cannot drift from the process one.
$script:TcpkLowPrivSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4', 'S-1-5-7', 'S-1-5-32-546')

# Parse an SDDL string and return every allow-ACE that grants a low-privilege well-known
# group any right in $RightsMap. Returns records @{ Account; Sid; Granted[] }.
function Get-TcpkSddlLowPrivGrants {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Sddl,
          [Parameter(Mandatory)][System.Collections.IDictionary]$RightsMap)

    $out = New-Object 'System.Collections.Generic.List[object]'
    if ([string]::IsNullOrWhiteSpace($Sddl)) { return $out.ToArray() }

    $danger = 0
    foreach ($v in $RightsMap.Values) { $danger = $danger -bor [int]$v }

    $rsd = $null
    try { $rsd = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl) } catch { return $out.ToArray() }
    if (-not $rsd.DiscretionaryAcl) { return $out.ToArray() }

    foreach ($ace in $rsd.DiscretionaryAcl) {
        if ("$($ace.AceType)" -notmatch 'AccessAllowed') { continue }
        $sid = $ace.SecurityIdentifier
        $sidVal = "$($sid.Value)"
        if ($script:TcpkLowPrivSids -notcontains $sidVal) { continue }

        $mask = [int]$ace.AccessMask
        if (($mask -band $danger) -eq 0) { continue }

        $granted = @()
        foreach ($rn in $RightsMap.Keys) { if ($mask -band [int]$RightsMap[$rn]) { $granted += $rn } }
        $acct = try { $sid.Translate([System.Security.Principal.NTAccount]).Value } catch { $sidVal }

        $out.Add([pscustomobject]@{ Account = $acct; Sid = $sidVal; Granted = $granted })
    }
    return $out.ToArray()
}


# =====================================================================================
# Can a low-privilege principal PLACE a file at a path that does not exist yet?
#
# Lives here because Get-TcpkSddlLowPrivGrants does, and because nothing else in the
# module can answer it: every other writability helper in the codebase bails the moment
# the path is absent, which is exactly the case a dangling registration presents.
# =====================================================================================
# ---------------------------------------------------------------------------------
# Can a low-privilege principal PLACE a file at this path?
#
# This is a different question from _IsWritable above and needs a different answer.
# _IsWritable asks "can the attacker overwrite this existing FILE", which needs
# WriteData on the file. A dangling registration has no file to overwrite, so the
# question becomes "can the attacker create one", which is a right on a DIRECTORY:
#
#   leaf directory EXISTS      -> needs FILE_ADD_FILE (0x2) on it
#   leaf directory is MISSING  -> needs FILE_ADD_SUBDIRECTORY (0x4) on the nearest
#                                 existing ancestor. Creating the directory makes the
#                                 attacker its owner, so everything below follows.
#
# The second case is the one that matters in practice. The registration that prompted
# this check pointed into %PROGRAMDATA%\<vendor>\, where the vendor directory did not
# exist and C:\ProgramData grants Users FILE_ADD_SUBDIRECTORY by default.
#
# DO NOT "FIX" THIS BY DROPPING AppendData. Test-TcpkRegistryLoadPoints excludes that
# bit on purpose and its reasoning is right for the case it handles: there the DLL
# EXISTS and has to be REPLACED, and creating a subdirectory cannot overwrite a file.
# It also notes that every drive root grants Users exactly this bit, so counting it
# would flag the parent of any DLL sitting at a drive root.
#
# Neither argument reaches this check, because AppendData is only consulted on the
# branch where the leaf directory is ABSENT. Creating the missing directory makes the
# attacker its owner, which is how the file gets placed -- nothing is being replaced.
# And a DLL registered at a drive root has a leaf directory that EXISTS, so it takes
# the other branch and is judged on FILE_ADD_FILE, which drive roots do not grant.
# The two rules disagree about the bit and agree about the threat model.
#
# Rights are matched NUMERICALLY through Get-TcpkSddlLowPrivGrants rather than by
# regex on the FileSystemRights string, because a substring match on 'Write' also hits
# WriteAttributes and WriteExtendedAttributes, which change metadata and cannot plant
# anything. Returns Ok=$false when the ACL could not be read, so an unreadable path is
# reported as skipped rather than silently passing as clean.
$script:TcpkPlantRights = [ordered]@{
    'WriteData/AddFile'          = 0x00000002
    'AppendData/AddSubdirectory' = 0x00000004
    'WriteDAC'                   = 0x00040000
    'WriteOwner'                 = 0x00080000
    'GenericAll'                 = 0x10000000
    'GenericWrite'               = 0x40000000
}

function Get-TcpkPlantGrants {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)

    $ImagePath = $Path
    $none = [pscustomobject]@{ Ok = $true; Anchor = $null; Needed = $null; Grants = @() }

    $leaf = $null
    try { $leaf = [IO.Path]::GetDirectoryName($ImagePath) } catch { return $none }
    if (-not $leaf) { return $none }

    # Walk up to the deepest directory that actually exists. Whether we stopped at the
    # leaf or above it decides which right is the planting primitive.
    $anchor = $leaf
    while ($anchor -and -not (Test-Path -LiteralPath $anchor -PathType Container)) {
        $up = $null
        try { $up = [IO.Path]::GetDirectoryName($anchor) } catch { $up = $null }
        if (-not $up -or $up -eq $anchor) { $anchor = $null; break }
        $anchor = $up
    }
    if (-not $anchor) { return $none }

    $needed = if ($anchor -eq $leaf) { 'WriteData/AddFile' } else { 'AppendData/AddSubdirectory' }

    $acl = $null
    try { $acl = Get-Acl -LiteralPath $anchor -ErrorAction Stop } catch {
        return [pscustomobject]@{ Ok = $false; Anchor = $anchor; Needed = $needed; Grants = @() }
    }
    if (-not $acl) { return [pscustomobject]@{ Ok = $false; Anchor = $anchor; Needed = $needed; Grants = @() } }

    $sddl = ''
    try { $sddl = "$($acl.Sddl)" } catch { }
    $granted = @(Get-TcpkSddlLowPrivGrants -Sddl $sddl -RightsMap $script:TcpkPlantRights)
    if ($granted.Count -eq 0) {
        return [pscustomobject]@{ Ok = $true; Anchor = $anchor; Needed = $needed; Grants = @() }
    }

    # Get-TcpkSddlLowPrivGrants walks the RAW descriptor, which still contains
    # InheritOnly ACEs. Those do not apply to the directory itself, only to what is
    # created inside it, so a grant that is InheritOnly cannot be what lets an
    # attacker create the entry. This is not a theoretical guard: the default DACL on
    # C:\ProgramData carries both an InheritOnly ACE for Users and a separate
    # container-inherit AddSubdirectory ACE, and only the second one is the primitive.
    # Keep a grant when it has at least one effective (non-InheritOnly) allow ACE
    # carrying the needed right, or when no matching ACE was found at all, which means
    # the SID did not translate and the raw grant is the better evidence.
    $neededMask = [int]$script:TcpkPlantRights[$needed]
    $effective = @()
    foreach ($g in $granted) {
        $ok = $false
        $sawRule = $false
        foreach ($ace in @($acl.Access)) {
            if ("$($ace.AccessControlType)" -ne 'Allow') { continue }
            $rsid = ''
            try { $rsid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $rsid = '' }
            if (-not $rsid -or $rsid -ne $g.Sid) { continue }
            $sawRule = $true
            $prop = 0
            try { $prop = [int]$ace.PropagationFlags } catch { $prop = 0 }
            if (($prop -band [int][System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
            $mask = 0
            try { $mask = [int]$ace.FileSystemRights } catch { $mask = 0 }
            if (($mask -band $neededMask) -eq 0) { continue }
            $ok = $true
            break
        }
        if ($ok -or (-not $sawRule)) { $effective += $g }
    }
    if ($effective.Count -eq 0) {
        return [pscustomobject]@{ Ok = $true; Anchor = $anchor; Needed = $needed; Grants = @() }
    }
    $granted = $effective

    # An explicit DENY for the same identity overrides the allow, and the SDDL walk
    # only reads allow ACEs. Match the deny numerically against the exact right that
    # would do the planting, not against the whole map: a deny of WriteDAC says
    # nothing about whether the principal can still add a file.
    $denyIds = @()
    $aces = @()
    try { $aces = @($acl.Access) } catch { }
    foreach ($ace in $aces) {
        $atype = ''
        try { $atype = "$($ace.AccessControlType)" } catch { continue }
        if ($atype -ne 'Deny') { continue }
        $dmask = 0
        try { $dmask = [int]$ace.FileSystemRights } catch { continue }
        if (($dmask -band $neededMask) -eq 0) { continue }
        try { $denyIds += "$($ace.IdentityReference.Value)" } catch { }
        $dsid = $null
        try { $dsid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) } catch { }
        if ($dsid) { $denyIds += "$($dsid.Value)" }
    }

    $out = @()
    foreach ($g in $granted) {
        if ($denyIds -contains "$($g.Account)") { continue }
        if ($denyIds -contains "$($g.Sid)") { continue }
        if (@($g.Granted) -notcontains $needed) { continue }
        $out += "$($g.Account) -> $($g.Granted -join ',')"
    }
    return [pscustomobject]@{ Ok = $true; Anchor = $anchor; Needed = $needed; Grants = $out }
}

# Pick the image path out of a server value. LocalServer32 carries arguments and the
# value may or may not be quoted, so a single regex strip is not safe: it turns
# "C:\Program Files\My App -X\srv.exe" into a path that does not exist, which would be
# reported as a dangling registration. Try the readings in order and prefer whichever
# one resolves; only when none resolves does the choice matter, and then the quoted
# span (or the argument-stripped form) is the honest candidate to name in the finding.
function Resolve-TcpkComServerImage {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $v = "$Value".Trim()
    if (-not $v) { return $null }

    $cands = New-Object 'System.Collections.Generic.List[string]'
    if ($v.StartsWith('"')) {
        $close = $v.IndexOf('"', 1)
        if ($close -gt 1) { [void]$cands.Add($v.Substring(1, $close - 1)) }
    }
    [void]$cands.Add(($v -replace '"', ''))
    [void]$cands.Add((($v -replace '"', '') -replace '\s+[/-].*$', ''))

    $best = $null
    foreach ($c in $cands) {
        $p = "$c".Trim()
        if (-not $p) { continue }
        try { $p = [Environment]::ExpandEnvironmentVariables($p) } catch { }

        # IsPathRooted / GetFullPath throw on an invalid path character in .NET
        # Framework. Registry data is attacker-influenced and routinely junk, so a
        # value like that is dropped rather than allowed to terminate the check.
        $bad = $false
        foreach ($ch in [IO.Path]::GetInvalidPathChars()) {
            if ($p.IndexOf($ch) -ge 0) { $bad = $true; break }
        }
        if ($bad) { continue }
        try { if ([IO.Path]::IsPathRooted($p)) { $p = [IO.Path]::GetFullPath($p) } } catch { continue }

        if (-not $best) { $best = $p }
        if (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue) {
            return [pscustomobject]@{ Path = $p; Exists = $true }
        }
    }
    return [pscustomobject]@{ Path = $best; Exists = $false }
}

