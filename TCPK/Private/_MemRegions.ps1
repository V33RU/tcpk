# Live-process virtual memory REGION enumeration (protection + type per region).
#
# Deliberately a separate type from Tcpk.MemRead rather than another method on it:
# that type is guarded by `if (-not ('Tcpk.MemRead' -as [type]))`, so once it is loaded
# into the AppDomain a new method added to its source is silently ignored until a fresh
# session. A distinct type avoids that trap entirely.
#
# Read-only. Opens the target with PROCESS_QUERY_INFORMATION only, which is the minimum
# VirtualQueryEx needs, so it succeeds against more processes than a VM_READ open would.

$script:TcpkMemRegionsSrc = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
namespace Tcpk {
 public static class MemRegions {
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint a, bool inh, int pid);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, IntPtr len);

  [StructLayout(LayoutKind.Sequential)] struct MBI {
   public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect; public uint a1;
   public IntPtr RegionSize; public uint State; public uint Protect; public uint Type; public uint a2;
  }

  // PROCESS_QUERY_INFORMATION (0x0400) is all VirtualQueryEx requires.
  public static IntPtr Open(int pid) { return OpenProcess(0x0400, false, pid); }

  // Flattened [base, size, protect, type] per COMMITTED region. Flat longs rather than a
  // struct array so the marshalling stays trivial across PowerShell versions.
  public static long[] Enumerate(IntPtr h) {
   var list = new List<long>();
   long addr = 0; long ceiling = 0x7FFFFFFFFFFF; int count = 0;
   while (addr < ceiling && count < 200000) {
     MBI m;
     IntPtr r = VirtualQueryEx(h, (IntPtr)addr, out m, (IntPtr)Marshal.SizeOf(typeof(MBI)));
     if (r == IntPtr.Zero) break;
     long rsize = (long)m.RegionSize;
     if (rsize <= 0) break;
     if (m.State == 0x1000) {            // MEM_COMMIT
       list.Add((long)m.BaseAddress);
       list.Add(rsize);
       list.Add((long)m.Protect);
       list.Add((long)m.Type);
     }
     addr += rsize; count++;
   }
   return list.ToArray();
  }
 }
}
'@

if (-not ('Tcpk.MemRegions' -as [type])) {
    try { Add-Type -TypeDefinition $script:TcpkMemRegionsSrc -ErrorAction Stop } catch { }
}
