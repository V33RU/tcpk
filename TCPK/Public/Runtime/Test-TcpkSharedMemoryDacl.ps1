function Test-TcpkSharedMemoryDacl {
<#
.SYNOPSIS
    E13. Shared-memory / memory-mapped file DACL inspection.

.DESCRIPTION
    Enumerates Section (memory-mapped file) handles owned by the target process
    via NtQuerySystemInformation, resolves their names, then checks the DACL on
    each NAMED section by opening it with MemoryMappedFile.OpenExisting and
    calling GetAccessControl.

    Reports sections where Everyone / Authenticated Users / Users / INTERACTIVE
    are granted Write or FullControl -- a direct primitive for cross-process
    data injection via shared memory.

    Requires elevation when the target runs as a different user or at higher
    integrity. Best-effort: unnamed or inaccessible sections are silently skipped.

.PARAMETER ProcessName
    Running process name (no .exe suffix).

.PARAMETER ProcessId
    Running process ID.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName='ById')][int]$ProcessId
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkSharedMemoryDacl')) { return }
    $procs = if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Get-TcpkProcess -ProcessName $ProcessName
    } else {
        Get-TcpkProcess -ProcessId $ProcessId
    }
    if (-not $procs) { return }

    if (-not ('Tcpk.ShmEnum' -as [type])) {
        $src = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Tcpk {
    public static class ShmEnum {
        [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int cls, IntPtr buf, int sz, out int len);
        [DllImport("ntdll.dll")] static extern int NtDuplicateObject(IntPtr sp, IntPtr sh, IntPtr tp, out IntPtr th, uint acc, uint attr, uint opt);
        [DllImport("ntdll.dll")] static extern int NtQueryObject(IntPtr h, int cls, IntPtr buf, int sz, out int len);
        [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint acc, bool inh, int pid);
        [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);

        const int SystemHandleInformation = 16;
        const int ObjectTypeInformation = 2;
        const int ObjectNameInformation = 1;

        [StructLayout(LayoutKind.Sequential)]
        struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
            public ushort UniqueProcessId;
            public ushort CreatorBackTraceIndex;
            public byte ObjectTypeIndex;
            public byte HandleAttributes;
            public ushort HandleValue;
            public IntPtr Object;
            public uint GrantedAccess;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

        static string QueryObjectName(IntPtr h) {
            int len; int sz = 1024;
            IntPtr buf = Marshal.AllocHGlobal(sz);
            try {
                int st = NtQueryObject(h, ObjectNameInformation, buf, sz, out len);
                if (st != 0) return null;
                var us = (UNICODE_STRING)Marshal.PtrToStructure(buf, typeof(UNICODE_STRING));
                if (us.Length == 0 || us.Buffer == IntPtr.Zero) return null;
                return Marshal.PtrToStringUni(us.Buffer, us.Length / 2);
            } finally { Marshal.FreeHGlobal(buf); }
        }

        static byte FindSectionTypeIndex(IntPtr[] handles, ushort[] pids, byte[] types) {
            // Heuristic: the Section type index is consistent per boot. Find it by
            // querying one handle's type name. If we can't, return 0 (skip all).
            var tried = new HashSet<byte>();
            IntPtr me = GetCurrentProcess();
            for (int i = 0; i < handles.Length && tried.Count < 30; i++) {
                byte ti = types[i];
                if (tried.Contains(ti)) continue;
                tried.Add(ti);
                IntPtr proc = OpenProcess(0x0040, false, pids[i]); // PROCESS_DUP_HANDLE
                if (proc == IntPtr.Zero) continue;
                IntPtr dup;
                int st = NtDuplicateObject(proc, handles[i], me, out dup, 0, 0, 0);
                CloseHandle(proc);
                if (st != 0) continue;
                // query type name
                int len2; int sz2 = 512;
                IntPtr buf2 = Marshal.AllocHGlobal(sz2);
                st = NtQueryObject(dup, ObjectTypeInformation, buf2, sz2, out len2);
                string typeName = null;
                if (st == 0) {
                    var us2 = (UNICODE_STRING)Marshal.PtrToStructure(buf2, typeof(UNICODE_STRING));
                    if (us2.Length > 0 && us2.Buffer != IntPtr.Zero)
                        typeName = Marshal.PtrToStringUni(us2.Buffer, us2.Length / 2);
                }
                Marshal.FreeHGlobal(buf2);
                CloseHandle(dup);
                if (typeName == "Section") return ti;
            }
            return 0;
        }

        public static string[] GetSectionNames(int pid) {
            var names = new List<string>();
            int sz = 1024 * 1024;
            IntPtr buf = Marshal.AllocHGlobal(sz);
            int len;
            int st = NtQuerySystemInformation(SystemHandleInformation, buf, sz, out len);
            while (st == unchecked((int)0xC0000004)) { // STATUS_INFO_LENGTH_MISMATCH
                sz *= 2; if (sz > 128 * 1024 * 1024) break;
                Marshal.FreeHGlobal(buf);
                buf = Marshal.AllocHGlobal(sz);
                st = NtQuerySystemInformation(SystemHandleInformation, buf, sz, out len);
            }
            if (st != 0) { Marshal.FreeHGlobal(buf); return names.ToArray(); }

            int count = Marshal.ReadInt32(buf);
            int entrySize = Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
            IntPtr entryPtr = buf + IntPtr.Size; // skip count (padded to pointer size)

            // collect all handles
            var allHandles = new List<IntPtr>(); var allPids = new List<ushort>(); var allTypes = new List<byte>();
            for (int i = 0; i < count; i++) {
                var entry = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)Marshal.PtrToStructure(entryPtr, typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
                allHandles.Add(new IntPtr(entry.HandleValue)); allPids.Add(entry.UniqueProcessId); allTypes.Add(entry.ObjectTypeIndex);
                entryPtr += entrySize;
            }

            byte sectionType = FindSectionTypeIndex(allHandles.ToArray(), allPids.ToArray(), allTypes.ToArray());
            if (sectionType == 0) { Marshal.FreeHGlobal(buf); return names.ToArray(); }

            // now enumerate only our target pid's Section handles
            IntPtr me = GetCurrentProcess();
            IntPtr proc = OpenProcess(0x0040, false, pid);
            if (proc == IntPtr.Zero) { Marshal.FreeHGlobal(buf); return names.ToArray(); }

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < allHandles.Count; i++) {
                if (allPids[i] != (ushort)pid) continue;
                if (allTypes[i] != sectionType) continue;
                IntPtr dup;
                st = NtDuplicateObject(proc, allHandles[i], me, out dup, 0x00020000 /*READ_CONTROL*/, 0, 0);
                if (st != 0) continue;
                string name = QueryObjectName(dup);
                CloseHandle(dup);
                if (name != null && name.Length > 0 && !seen.Contains(name)) {
                    seen.Add(name);
                    names.Add(name);
                }
            }
            CloseHandle(proc);
            Marshal.FreeHGlobal(buf);
            return names.ToArray();
        }
    }
}
'@
        try { Add-Type -TypeDefinition $src -ErrorAction Stop } catch {
            if (-not ('Tcpk.ShmEnum' -as [type])) {
                New-TcpkSkippedFinding -RuleId 'sharedmem.enum-unavailable' -Title 'Shared-memory enumeration unavailable' -Reason $_.Exception.Message
                return
            }
        }
    }

    foreach ($p in $procs) {
        $sectionNames = @()
        try { $sectionNames = @([Tcpk.ShmEnum]::GetSectionNames($p.Id)) } catch { }

        if (-not $sectionNames.Count) {
            New-TcpkFinding -Module 'runtime' -RuleId 'sharedmem.none-found' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "No named shared-memory sections found for $($p.Name) (PID $($p.Id))" `
                -File "$($p.Name) (PID $($p.Id))" `
                -Evidence 'Section handle enumeration returned no named objects (process may use unnamed sections or enumeration was denied).'
            continue
        }

        $weakCount = 0
        foreach ($name in $sectionNames) {
            # strip the kernel object-manager prefix for display
            $display = $name -replace '^\\BaseNamedObjects\\', '' -replace '^\\Sessions\\\d+\\BaseNamedObjects\\', ''
            if (-not $display) { continue }

            # try opening with MemoryMappedFile to check access
            $canRead = $false; $canWrite = $false; $aclInfo = ''
            try {
                $mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::OpenExisting(
                    $display,
                    [System.IO.MemoryMappedFiles.MemoryMappedFileRights]::ReadWrite
                )
                $canRead = $true; $canWrite = $true
                try {
                    $sec = $mmf.GetAccessControl()
                    $weak = $sec.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
                    $grants = @()
                    foreach ($ace in $weak) {
                        if ($ace.IdentityReference.Value -match '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE)\b' -and
                            $ace.AccessControlType.ToString() -eq 'Allow') {
                            $grants += "$($ace.IdentityReference)=$($ace.FileSystemRights)"
                        }
                    }
                    if ($grants) { $aclInfo = $grants -join '; ' }
                } catch { }
                $mmf.Dispose()
            } catch {
                # try read-only
                try {
                    $mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::OpenExisting(
                        $display,
                        [System.IO.MemoryMappedFiles.MemoryMappedFileRights]::Read
                    )
                    $canRead = $true
                    $mmf.Dispose()
                } catch { }
            }

            if ($canWrite) {
                $weakCount++
                New-TcpkFinding -Module 'runtime' -RuleId 'sharedmem.weak-dacl' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "Shared memory writable by current user: $display" `
                    -File "$($p.Name) (PID $($p.Id))" `
                    -Evidence "section=$name access=ReadWrite$(if ($aclInfo) { " dacl=$aclInfo" })" `
                    -Cwe @('CWE-732','CWE-787') `
                    -Description "The named shared-memory section '$display' is writable by the current user context. An attacker process can modify data in the shared region, potentially corrupting application state, injecting commands, or altering security decisions that depend on shared data." `
                    -Fix 'Restrict the Section DACL to the application SID + SYSTEM. Validate shared-memory contents with integrity checks (HMAC / checksum) before use.'
            } elseif ($canRead) {
                New-TcpkFinding -Module 'runtime' -RuleId 'sharedmem.readable' `
                    -Severity 'LOW' -Confidence 'Confirmed' `
                    -Title "Shared memory readable by current user: $display" `
                    -File "$($p.Name) (PID $($p.Id))" `
                    -Evidence "section=$name access=Read" `
                    -Cwe @('CWE-200') `
                    -Description "The named shared-memory section '$display' is readable. An attacker process can observe application state, potentially leaking credentials, tokens, or configuration." `
                    -Fix 'If the section contains sensitive data, restrict the DACL to the app SID + SYSTEM.'
            } else {
                New-TcpkFinding -Module 'runtime' -RuleId 'sharedmem.exists' `
                    -Severity 'INFO' -Confidence 'Confirmed' `
                    -Title "Named shared-memory section: $display" `
                    -File "$($p.Name) (PID $($p.Id))" `
                    -Evidence "section=$name access=denied"
            }
        }

        New-TcpkFinding -Module 'runtime' -RuleId 'sharedmem.summary' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "Shared memory: $($sectionNames.Count) named sections, $weakCount writable" `
            -File "$($p.Name) (PID $($p.Id))" `
            -Evidence "total=$($sectionNames.Count) writable=$weakCount"
    }
}
