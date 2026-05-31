# Shared live-process memory primitives (x64) for the Memory/Runtime/Exploit
# buckets. Read-only by default; WriteBytes is only used by gated exploit cmdlets.
# Defines Tcpk.MemRead once per AppDomain (guarded for -Force reloads).

$script:TcpkMemReadSrc = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
namespace Tcpk {
 public static class MemRead {
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint a, bool inh, int pid);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr written);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool VirtualProtectEx(IntPtr h, IntPtr addr, IntPtr size, uint newProt, out uint oldProt);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, IntPtr len);
  [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr h, int cls, ref PBI pbi, int len, out int ret);

  [StructLayout(LayoutKind.Sequential)] struct MBI {
   public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect; public uint a1;
   public IntPtr RegionSize; public uint State; public uint Protect; public uint Type; public uint a2;
  }
  [StructLayout(LayoutKind.Sequential)] struct PBI {
   public IntPtr ExitStatus; public IntPtr PebBaseAddress; public IntPtr AffinityMask;
   public IntPtr BasePriority; public IntPtr UniqueProcessId; public IntPtr InheritedFromUniqueProcessId;
  }

  public static IntPtr Open(int pid, bool write) {
   uint a = 0x0400 | 0x0010;             // QUERY_INFORMATION | VM_READ
   if (write) a |= 0x0020 | 0x0008;      // VM_WRITE | VM_OPERATION
   return OpenProcess(a, false, pid);
  }

  // flattened [base,size,base,size,...] of committed, readable, non-guard regions
  public static long[] Regions(IntPtr h, long maxRegion, bool includeImage) {
   var list = new List<long>();
   long addr = 0; long ceiling = 0x7FFFFFFFFFFF; int count = 0;
   while (addr < ceiling && count < 200000) {
     MBI m;
     IntPtr r = VirtualQueryEx(h, (IntPtr)addr, out m, (IntPtr)Marshal.SizeOf(typeof(MBI)));
     if (r == IntPtr.Zero) break;
     long rsize = (long)m.RegionSize;
     if (rsize <= 0) break;
     uint p = m.Protect;
     bool commit = (m.State == 0x1000);
     bool guard = (p & 0x100) != 0;
     bool noaccess = (p & 0x01) != 0;
     bool readable = (p & (0x02|0x04|0x08|0x20|0x40|0x80)) != 0;
     bool isImage = (m.Type == 0x1000000);
     if (commit && readable && !guard && !noaccess && (includeImage || !isImage)) {
       long use = rsize; if (use > maxRegion) use = maxRegion;
       list.Add((long)m.BaseAddress); list.Add(use);
     }
     addr += rsize; count++;
   }
   return list.ToArray();
  }

  public static byte[] ReadBytes(IntPtr h, long addr, int size) {
   byte[] buf = new byte[size];
   IntPtr read;
   if (!ReadProcessMemory(h, (IntPtr)addr, buf, (IntPtr)size, out read)) return null;
   int n = (int)read;
   if (n <= 0) return null;
   if (n < size) { byte[] t = new byte[n]; Array.Copy(buf, t, n); return t; }
   return buf;
  }

  public static int WriteBytes(IntPtr h, long addr, byte[] data) {
   uint old;
   VirtualProtectEx(h, (IntPtr)addr, (IntPtr)data.Length, 0x40, out old); // PAGE_EXECUTE_READWRITE
   IntPtr written;
   bool ok = WriteProcessMemory(h, (IntPtr)addr, data, (IntPtr)data.Length, out written);
   uint tmp;
   VirtualProtectEx(h, (IntPtr)addr, (IntPtr)data.Length, old, out tmp);
   return ok ? (int)written : -1;
  }

  static long ReadPtr(IntPtr h, long addr) {
   byte[] b = ReadBytes(h, addr, 8);
   if (b == null || b.Length < 8) return 0;
   return BitConverter.ToInt64(b, 0);
  }

  // x64 PEB walk -> environment block (NAME=VALUE\0...\0\0) as a string
  public static string GetEnv(int pid) {
   IntPtr h = Open(pid, false);
   if (h == IntPtr.Zero) return null;
   try {
     PBI pbi = new PBI(); int ret;
     int st = NtQueryInformationProcess(h, 0, ref pbi, Marshal.SizeOf(typeof(PBI)), out ret);
     if (st != 0 || pbi.PebBaseAddress == IntPtr.Zero) return null;
     long peb = (long)pbi.PebBaseAddress;
     long pp = ReadPtr(h, peb + 0x20);       // PEB.ProcessParameters
     if (pp == 0) return null;
     long env = ReadPtr(h, pp + 0x80);        // RTL_USER_PROCESS_PARAMETERS.Environment
     if (env == 0) return null;
     byte[] raw = ReadBytes(h, env, 65536);
     if (raw == null) return null;
     string s = System.Text.Encoding.Unicode.GetString(raw);
     int dz = s.IndexOf("\0\0");
     if (dz >= 0) s = s.Substring(0, dz);
     return s;
   } finally { CloseHandle(h); }
  }
 }
}
'@

if (-not ('Tcpk.MemRead' -as [type])) {
    try { Add-Type -TypeDefinition $script:TcpkMemReadSrc -ErrorAction Stop } catch { }
}

# Compile the secrets.json rules into regex once, returning the rule list.
function Get-TcpkSecretRegexRules {
    [CmdletBinding()] param()
    $rules = (Get-TcpkData).rules
    foreach ($r in $rules) {
        if (-not $r.PSObject.Properties['_RX']) {
            $r | Add-Member -NotePropertyName _RX -NotePropertyValue ([regex]::new(
                $r.pattern,
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                [System.Text.RegularExpressions.RegexOptions]::Compiled)) -Force
        }
    }
    return $rules
}
