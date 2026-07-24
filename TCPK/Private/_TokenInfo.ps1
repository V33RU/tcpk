# Shared live-process token primitives for the Runtime bucket. Read-only:
# opens the target with PROCESS_QUERY_LIMITED_INFORMATION + TOKEN_QUERY only,
# reads its privilege set and integrity level, and closes the handle.
# Defines Tcpk.TokenInfo once per AppDomain (guarded for -Force reloads).

$script:TcpkTokenInfoSrc = @'
using System;
using System.Text;
using System.Runtime.InteropServices;
namespace Tcpk {
 public static class TokenInfo {
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint a, bool inh, int pid);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr proc, uint acc, out IntPtr tok);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr tok, int cls, IntPtr buf, int len, out int retlen);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool LookupPrivilegeName(string sys, ref LUID luid, StringBuilder name, ref int len);

  [StructLayout(LayoutKind.Sequential)] struct LUID { public uint Low; public int High; }
  [StructLayout(LayoutKind.Sequential)] struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

  const uint TOKEN_QUERY = 0x0008;
  const uint PROCESS_QUERY_LIMITED = 0x1000;
  const uint PROCESS_QUERY_INFORMATION = 0x0400;
  const uint SE_PRIVILEGE_ENABLED = 0x2;
  const uint SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1;
  const int TokenPrivileges = 3;
  const int TokenIntegrityLevel = 25;

  static IntPtr OpenTok(int pid) {
   IntPtr proc = OpenProcess(PROCESS_QUERY_LIMITED, false, pid);
   if (proc == IntPtr.Zero) proc = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
   if (proc == IntPtr.Zero) return IntPtr.Zero;
   IntPtr tok;
   bool ok = OpenProcessToken(proc, TOKEN_QUERY, out tok);
   CloseHandle(proc);
   return ok ? tok : IntPtr.Zero;
  }

  // "SeDebugPrivilege:enabled;SeImpersonatePrivilege:present;..." or null on failure.
  public static string Privileges(int pid) {
   IntPtr tok = OpenTok(pid);
   if (tok == IntPtr.Zero) return null;
   try {
    int len = 0;
    GetTokenInformation(tok, TokenPrivileges, IntPtr.Zero, 0, out len);
    if (len <= 0) return null;
    IntPtr buf = Marshal.AllocHGlobal(len);
    try {
     if (!GetTokenInformation(tok, TokenPrivileges, buf, len, out len)) return null;
     int count = Marshal.ReadInt32(buf);
     long baseAddr = buf.ToInt64() + 4;             // PrivilegeCount then the array
     int recSize = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
     var sb = new StringBuilder();
     for (int i = 0; i < count; i++) {
      IntPtr rec = (IntPtr)(baseAddr + (long)i * recSize);
      LUID_AND_ATTRIBUTES la = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(rec, typeof(LUID_AND_ATTRIBUTES));
      LUID luid = la.Luid;
      int cch = 0;
      LookupPrivilegeName(null, ref luid, null, ref cch);
      if (cch <= 0) continue;
      var name = new StringBuilder(cch + 1);
      cch = name.Capacity;
      if (!LookupPrivilegeName(null, ref luid, name, ref cch)) continue;
      bool en = (la.Attributes & (SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT)) != 0;
      if (sb.Length > 0) sb.Append(';');
      sb.Append(name.ToString()); sb.Append(':'); sb.Append(en ? "enabled" : "present");
     }
     return sb.ToString();
    } finally { Marshal.FreeHGlobal(buf); }
   } finally { CloseHandle(tok); }
  }

  // Integrity RID: 0x0=untrusted 0x1000=low 0x2000=medium 0x3000=high 0x4000=system; -1 on failure.
  public static int Integrity(int pid) {
   IntPtr tok = OpenTok(pid);
   if (tok == IntPtr.Zero) return -1;
   try {
    int len = 0;
    GetTokenInformation(tok, TokenIntegrityLevel, IntPtr.Zero, 0, out len);
    if (len <= 0) return -1;
    IntPtr buf = Marshal.AllocHGlobal(len);
    try {
     if (!GetTokenInformation(tok, TokenIntegrityLevel, buf, len, out len)) return -1;
     IntPtr sid = Marshal.ReadIntPtr(buf);          // TOKEN_MANDATORY_LABEL.Label.Sid
     if (sid == IntPtr.Zero) return -1;
     byte cnt = Marshal.ReadByte(sid, 1);           // SID.SubAuthorityCount
     if (cnt <= 0) return -1;
     return Marshal.ReadInt32(sid, 8 + (cnt - 1) * 4);  // last SubAuthority
    } finally { Marshal.FreeHGlobal(buf); }
   } finally { CloseHandle(tok); }
  }
 }
}
'@

if (-not ('Tcpk.TokenInfo' -as [type])) {
    try { Add-Type -TypeDefinition $script:TcpkTokenInfoSrc -ErrorAction Stop } catch { }
}

# Impactful-privilege classification, shared by Test-TcpkProcessToken. The
# "system-grade" set yields SYSTEM or a full token; the "resource-grade" set
# grants read/write/ownership of arbitrary files or the security log.
$script:TcpkPrivSystemGrade = @(
    'SeImpersonatePrivilege','SeAssignPrimaryTokenPrivilege','SeTcbPrivilege',
    'SeCreateTokenPrivilege','SeLoadDriverPrivilege','SeDebugPrivilege','SeRelabelPrivilege'
)
$script:TcpkPrivResourceGrade = @(
    'SeBackupPrivilege','SeRestorePrivilege','SeTakeOwnershipPrivilege',
    'SeManageVolumePrivilege','SeSecurityPrivilege'
)

function Get-TcpkIntegrityLabel {
    [CmdletBinding()] param([int]$Rid)
    switch ($Rid) {
        { $_ -ge 0x4000 } { return 'System' }
        { $_ -ge 0x3000 } { return 'High' }
        { $_ -ge 0x2000 } { return 'Medium' }
        { $_ -ge 0x1000 } { return 'Low' }
        { $_ -ge 0 }      { return 'Untrusted' }
        default           { return '(unknown)' }
    }
}

# Thin wrappers over the P/Invoke statics so Test-TcpkProcessToken stays
# mock-testable (a live elevated token is not available on a CI runner).
function Get-TcpkProcessIntegrityRid {
    [CmdletBinding()] param([int]$ProcessId)
    if ('Tcpk.TokenInfo' -as [type]) { return [Tcpk.TokenInfo]::Integrity($ProcessId) }
    return -1
}
function Get-TcpkProcessPrivilegeString {
    [CmdletBinding()] param([int]$ProcessId)
    if ('Tcpk.TokenInfo' -as [type]) { return [Tcpk.TokenInfo]::Privileges($ProcessId) }
    return $null
}

# Parse a "Name:enabled;Name:present;..." privilege string (as returned by
# Tcpk.TokenInfo.Privileges) into the impactful subset, split by live state.
# Pure -- unit-tested without needing a live elevated token.
function Split-TcpkImpactfulPrivileges {
    [CmdletBinding()] param([string]$PrivRaw)
    $enabled = New-Object System.Collections.Generic.List[string]
    $present = New-Object System.Collections.Generic.List[string]
    $sawSys = $false
    if ($PrivRaw) {
        foreach ($tok in $PrivRaw -split ';') {
            $parts = $tok -split ':', 2
            if ($parts.Count -ne 2) { continue }
            $pname = $parts[0]; $pstate = $parts[1]
            $isSys = $script:TcpkPrivSystemGrade -contains $pname
            if (-not ($isSys -or ($script:TcpkPrivResourceGrade -contains $pname))) { continue }
            if ($pstate -eq 'enabled') {
                $enabled.Add($pname)
                if ($isSys) { $sawSys = $true }
            } else {
                $present.Add($pname)
            }
        }
    }
    return [pscustomobject]@{ Enabled = $enabled; Present = $present; SawSystemGrade = $sawSys }
}
