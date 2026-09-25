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

# THE ONE PLACE secrets.json rules are prepared. Every consumer must come through here.
#
# There used to be two builders: this one, and a second inline in Test-TcpkSecrets. They
# disagreed about three things, and because Get-TcpkData hands out CACHED objects that both
# mutated with -Force behind an "if the property is absent" guard, whichever check ran first
# in a session decided the behaviour of every check after it:
#
#   match timeout  Test-TcpkSecrets set 5s and documented it as MANDATORY, because a rule
#                  that backtracks pathologically otherwise runs forever and its own
#                  RegexMatchTimeoutException handler is dead code without it. This builder
#                  set none. A live-memory scan running first therefore silently removed the
#                  static scanner's only protection against a hang.
#   Multiline      set there, not here, which changes what ^ and $ mean mid-buffer.
#   the gates      below. Built there, never here.
#
# THE GATES ARE NOT AN OPTIMISATION. 47 of the 49 rules carry a literal prefix or a
# 'prefilter' needle set that makes them meaningful; several are unusable without one.
# particle-io-access-token is [0-9a-f]{40} at HIGH, gated on 'api.particle.io'. Ungated
# against a process heap that matches every SHA-1, every certificate thumbprint and every
# hex blob in the address space, and reports each as HIGH. Consumers that skipped the gates
# were not running a faster scan, they were running a different and much worse one.
function Get-TcpkSecretRegexRules {
    [CmdletBinding()] param()

    # Per-rule match budget, applied per Match call. 5s is far above any legitimate rule.
    if (-not $script:TcpkSecretsRuleTimeout) {
        $script:TcpkSecretsRuleTimeout = [TimeSpan]::FromSeconds(5)
    }

    $rules = (Get-TcpkData).rules
    foreach ($r in $rules) {
        if (-not $r.PSObject.Properties['_RX']) {
            # NO RegexOptions.Compiled. It defers IL generation and JIT to first use, so the
            # cost of building all 49 rules lands on the first file scanned and reads as a
            # hang; three rules are variable-length lookbehinds and are the most expensive of
            # the set to build. It also fights the _QuickLit gate directly: that gate exists
            # so a rule whose literal is absent NEVER RUNS, and Compiled pays to JIT every
            # one of them anyway. It repays only after thousands of matches against the same
            # instance, which this workload never performs.
            #
            # MATCH TIMEOUT IS MANDATORY. The 2-argument overload leaves matchTimeout at
            # Regex.InfiniteMatchTimeout, so one badly backtracking rule stalls the scan with
            # no output and no way to tell a hang from slow progress.
            $r | Add-Member -NotePropertyName _RX -NotePropertyValue ([regex]::new(
                $r.pattern,
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                [System.Text.RegularExpressions.RegexOptions]::Multiline,
                $script:TcpkSecretsRuleTimeout
            )) -Force
        }

        if (-not $r.PSObject.Properties['_QuickLit']) {
            # Gate 1: the MANDATORY literal run at the START of the pattern, after stripping
            # leading inline flags and anchors. Only a LEADING literal is taken: an earlier
            # extractor pulled regex SYNTAX out of the middle of a pattern --  became 'b'
            # ('bsk_', 'bgithub_pat_'), (?: became ':' (':AKIA'), [A-Z0-9] became 'A-Z0-9' --
            # none of which occur in real data, so those rules were silently skipped and AWS
            # / GitHub-PAT / Stripe / Aptabase detection was ZEROED OUT. If the pattern opens
            # with a group, a class or a short literal the gate is left null and the rule
            # always runs: correctness over speed.
            $p = $r.pattern
            $p = [regex]::Replace($p, '^\(\?[a-zA-Z]+\)', '')
            $p = [regex]::Replace($p, '^(?:\\b|\^)+', '')
            $lit = $null
            $lm = [regex]::Match($p, '^[A-Za-z0-9_./=:\-]{4,}')
            if ($lm.Success) {
                $cand = $lm.Value
                # A quantifier after the run makes its last char optional or variable.
                $next = if ($p.Length -gt $cand.Length) { $p[$cand.Length] } else { [char]0 }
                if ($next -eq '?' -or $next -eq '*' -or $next -eq '{') { $cand = $cand.Substring(0, $cand.Length - 1) }
                if ($cand.Length -ge 4) { $lit = $cand }
            }
            $r | Add-Member -NotePropertyName _QuickLit -NotePropertyValue $lit -Force
        }

        if (-not $r.PSObject.Properties['_Needles']) {
            # Gate 2: the rule's own 'prefilter' set of cheap literal triggers. The credential
            # rules require a password-ish keyword to mean anything, so gating on it is
            # loss-free; SecretPrefilter.Tests.ps1 asserts that property rule by rule.
            $nd = @()
            if ($r.PSObject.Properties['prefilter'] -and $r.prefilter) { $nd = @($r.prefilter | ForEach-Object { "$_" }) }
            $r | Add-Member -NotePropertyName _Needles -NotePropertyValue $nd -Force
        }
    }
    return $rules
}

# Should this rule's regex run against this text at all? Both gates are cheap ordinal
# substring tests and both are loss-free by construction: a rule only carries a gate when
# the gate's literal is MANDATORY for the pattern to match.
#
# Callers that scan decoded process memory, clipboard contents, environment blocks, UI text
# or extracted archive members must call this. Without it the heavier rules match binary
# noise and every hit is reported at the rule's own severity.
function Test-TcpkSecretRuleApplies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Rule,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text
    )
    if ([string]::IsNullOrEmpty($Text)) { return $false }

    $ql = $null
    try { $ql = $Rule._QuickLit } catch { $ql = $null }
    if ($ql -and ($Text.IndexOf($ql, [System.StringComparison]::OrdinalIgnoreCase) -lt 0)) { return $false }

    $nd = @()
    try { $nd = @($Rule._Needles) } catch { $nd = @() }
    if ($nd.Count) {
        foreach ($n in $nd) {
            if ($Text.IndexOf($n, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
        }
        return $false
    }
    return $true
}
