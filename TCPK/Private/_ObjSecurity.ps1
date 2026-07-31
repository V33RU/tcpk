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
