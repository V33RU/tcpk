# Live handle enumeration with per-object security descriptors.
#
# Test-TcpkHandleEnumeration reports handle COUNTS and defers detail to handle.exe.
# This is the detail: the actual kernel objects a process holds open, and the DACL on
# each, so a weak one becomes a finding instead of a number.
#
# HANG HAZARD, and why the design looks like it does.
# NtQueryObject(ObjectNameInformation) blocks FOREVER on a synchronous file/pipe handle
# that has pending I/O. This is the well-known trap that makes naive handle enumerators
# freeze, and Process Hacker works around it by querying names on a sacrificial thread
# with a timeout. TCPK takes the simpler and safer route: it NEVER asks for the name of
# a File-type handle. Type queries and GetSecurityInfo do not block, so everything else
# is safe. The cost is that file and pipe handle NAMES are unavailable here, which is
# acceptable because Test-TcpkNamedPipeDacl already covers pipes properly and the value
# of this check is the synchronisation objects nothing else looks at.

$script:TcpkHandlesSrc = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
namespace Tcpk {
 public static class Handles {
  [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int cls, IntPtr buf, int len, out int ret);
  [DllImport("ntdll.dll")] static extern int NtQueryObject(IntPtr h, int cls, IntPtr buf, int len, out int ret);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint a, bool inh, int pid);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool DuplicateHandle(IntPtr sp, IntPtr sh, IntPtr tp, out IntPtr th, uint acc, bool inh, uint opt);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
  [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(IntPtr handle, int objectType, int securityInfo,
     IntPtr o, IntPtr g, IntPtr dacl, IntPtr sacl, out IntPtr sd);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr sd, uint rev, int si, out IntPtr str, out int len);

  const int SystemExtendedHandleInformation = 64;
  const int ObjectTypeInformation = 2;

  static string SddlOf(IntPtr h) {
     IntPtr sd;
     if (GetSecurityInfo(h, 6, 4, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out sd) != 0 || sd == IntPtr.Zero) return null;
     IntPtr str; int len;
     bool ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, 4, out str, out len);
     string s = ok ? Marshal.PtrToStringUni(str) : null;
     if (str != IntPtr.Zero) LocalFree(str);
     LocalFree(sd);
     return s;
  }

  // OBJECT_TYPE_INFORMATION begins with a UNICODE_STRING TypeName. Type queries do not
  // block, unlike name queries, so this is always safe to call.
  static string TypeOf(IntPtr h) {
     int len = 0x1000;
     IntPtr buf = Marshal.AllocHGlobal(len);
     try {
        int ret;
        if (NtQueryObject(h, ObjectTypeInformation, buf, len, out ret) != 0) return null;
        short blen = Marshal.ReadInt16(buf, 0);
        IntPtr sptr = Marshal.ReadIntPtr(buf, IntPtr.Size);
        if (sptr == IntPtr.Zero || blen <= 0) return null;
        return Marshal.PtrToStringUni(sptr, blen / 2);
     } catch { return null; }
     finally { Marshal.FreeHGlobal(buf); }
  }

  // Returns "Type<US>Sddl<US>GrantedAccess" per handle, where <US> is \u001F. A control
  // character is used as the separator because an SDDL string can legitimately contain
  // almost any printable character, so any printable delimiter risks colliding with it.
  // Names are deliberately never queried (see the hang note above).
  public static string[] Inspect(int pid, int maxHandles) {
     var outp = new List<string>();
     int len = 0x10000; IntPtr buf = IntPtr.Zero; int ret = 0;
     for (int attempt = 0; attempt < 12; attempt++) {
        buf = Marshal.AllocHGlobal(len);
        int st = NtQuerySystemInformation(SystemExtendedHandleInformation, buf, len, out ret);
        if (st == 0) break;
        Marshal.FreeHGlobal(buf); buf = IntPtr.Zero;
        if ((uint)st != 0xC0000004) return outp.ToArray();   // STATUS_INFO_LENGTH_MISMATCH
        len = (ret > len) ? ret + 0x10000 : len * 2;
     }
     if (buf == IntPtr.Zero) return outp.ToArray();

     IntPtr self = GetCurrentProcess();
     IntPtr ph = OpenProcess(0x0040, false, pid);           // PROCESS_DUP_HANDLE
     try {
        long count = Marshal.ReadIntPtr(buf).ToInt64();
        int stride = IntPtr.Size * 2 + IntPtr.Size + 4 + 2 + 2 + 4 + 4;  // 40 on x64
        int baseOff = IntPtr.Size * 2;
        int seen = 0;
        for (long i = 0; i < count && seen < maxHandles; i++) {
           long off = baseOff + i * stride;
           long owner = Marshal.ReadIntPtr(buf, (int)(off + IntPtr.Size)).ToInt64();
           if (owner != pid) continue;
           if (ph == IntPtr.Zero) continue;
           IntPtr hv = Marshal.ReadIntPtr(buf, (int)(off + IntPtr.Size * 2));
           uint gacc = (uint)Marshal.ReadInt32(buf, (int)(off + IntPtr.Size * 3));

           IntPtr dup;
           if (!DuplicateHandle(ph, hv, self, out dup, 0, false, 2)) continue;  // DUPLICATE_SAME_ACCESS
           try {
              string t = TypeOf(dup);
              if (t == null) continue;
              // File covers pipes too, and a name query on one can block forever.
              // Skip it entirely rather than risk hanging the scan.
              if (t == "File") { seen++; continue; }
              string sddl = SddlOf(dup);
              outp.Add(t + "\u001F" + (sddl ?? "") + "\u001F" + gacc.ToString());
              seen++;
           } finally { CloseHandle(dup); }
        }
     } catch { }
     finally {
        if (ph != IntPtr.Zero) CloseHandle(ph);
        Marshal.FreeHGlobal(buf);
     }
     return outp.ToArray();
  }
 }
}
'@

if (-not ('Tcpk.Handles' -as [type])) {
    try { Add-Type -TypeDefinition $script:TcpkHandlesSrc -ErrorAction Stop } catch { }
}
