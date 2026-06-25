function Test-TcpkMailslotsAlpc {
<#
.SYNOPSIS
    E07. Mailslots and ALPC ports.

.DESCRIPTION
    Mailslots and ALPC are lower-profile IPC primitives. Mailslots are
    enumerable via \\.\mailslot\. ALPC ports live in the kernel object
    namespace; this check enumerates the \RPC Control directory via a
    compile-guarded P/Invoke to NtOpenDirectoryObject + NtQueryDirectoryObject
    and reports ALPC Port objects whose name matches an identity term. If the
    P/Invoke cannot be built or the query fails on this host, it falls back to
    surfacing the coverage gap (alpc.not-enumerated) rather than throwing.

.PARAMETER NameLike
    Substring(s) to match against mailslot / ALPC port names.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string[]]$NameLike = @())

    if (-not (Assert-TcpkWindows 'Test-TcpkMailslotsAlpc')) { return }

    # ----- mailslots (\\.\mailslot\) -----
    try {
        $slots = Get-ChildItem '\\.\mailslot\' -ErrorAction Stop
        $matched = $slots | Where-Object { Test-TcpkNameInclude -Text $_.Name -Terms $NameLike }
        foreach ($s in $matched) {
            New-TcpkFinding -Module 'runtime' -RuleId 'mailslot.exists' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "Mailslot present: $($s.Name)" `
                -File $s.FullName -Evidence $s.Name `
                -Cwe @('CWE-668')
        }
    } catch {
        # Most systems do not have \\.\mailslot\ enumerable; skip silently
    }

    # ----- ALPC ports (\RPC Control) via compile-guarded P/Invoke -----
    $ports = $null
    $enumerated = $false
    try {
        Add-TcpkAlpcType   # idempotent; throws only on a genuine compile failure
        $ports = [TcpkAlpc]::Enumerate('\RPC Control', 8192)
        $enumerated = $true
    } catch {
        $enumerated = $false
    }

    if (-not $enumerated -or $null -eq $ports) {
        # Could not enumerate (older OS / compile failure) -- surface the gap honestly.
        New-TcpkFinding -Module 'runtime' -RuleId 'alpc.not-enumerated' `
            -Severity 'INFO' -Confidence 'Skipped' `
            -Title 'ALPC ports not enumerated' `
            -Evidence 'NtQueryDirectoryObject P/Invoke unavailable on this host.' `
            -Description 'For manual ALPC port enumeration use SysInternals winobj.exe or Process Explorer (View -> Show Lower Pane -> Handles).'
        return
    }

    # Only ALPC Port type objects; match against the identity terms.
    $alpc = @($ports | Where-Object { "$($_[1])" -eq 'ALPC Port' })
    $hit  = @($alpc | Where-Object { Test-TcpkNameInclude -Text "$($_[0])" -Terms $NameLike })
    foreach ($p in $hit) {
        New-TcpkFinding -Module 'runtime' -RuleId 'alpc.port' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "ALPC port: $($p[0])" `
            -File "\RPC Control\$($p[0])" -Evidence "name=$($p[0]); type=ALPC Port" `
            -Cwe @('CWE-668') `
            -Description 'A named ALPC port attributable to the target. ALPC is a local IPC channel; confirm the server validates the caller and that the port DACL is not world-accessible.'
    }
    if (-not $hit.Count) {
        # Enumeration worked but no port matched the target -- record that we DID run,
        # so coverage shows ALPC as Ran (not NotImplemented), with the total seen.
        New-TcpkFinding -Module 'runtime' -RuleId 'alpc.enumerated-clean' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title 'ALPC ports enumerated; none matched the target' `
            -Evidence "$(@($alpc).Count) ALPC port(s) in \RPC Control; none matched the identity terms." `
            -Description 'ALPC enumeration succeeded; no port name matched this application. Informational.'
    }
}

# Compile-guarded loader for the ALPC P/Invoke surface. Idempotent: returns immediately if
# the type is already loaded this session. ASCII-only C#. Kept here (next to its only caller)
# rather than a shared Private file so the ALPC feature is self-contained.
function Add-TcpkAlpcType {
    if (('TcpkAlpc' -as [type])) { return }
    $cs = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class TcpkAlpc {
    [StructLayout(LayoutKind.Sequential)]
    struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

    [StructLayout(LayoutKind.Sequential)]
    struct OBJECT_ATTRIBUTES {
        public int Length; public IntPtr RootDirectory; public IntPtr ObjectName;
        public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct OBJECT_DIRECTORY_INFORMATION { public UNICODE_STRING Name; public UNICODE_STRING TypeName; }

    [DllImport("ntdll.dll")]
    static extern int NtOpenDirectoryObject(out IntPtr handle, uint access, ref OBJECT_ATTRIBUTES attr);
    [DllImport("ntdll.dll")]
    static extern int NtQueryDirectoryObject(IntPtr handle, IntPtr buffer, int length, bool returnSingle, bool restartScan, ref uint context, out uint retLen);
    [DllImport("ntdll.dll")]
    static extern int NtClose(IntPtr handle);

    public static List<string[]> Enumerate(string dirPath, int cap) {
        var result = new List<string[]>();
        IntPtr nameBuf = Marshal.StringToHGlobalUni(dirPath);
        var name = new UNICODE_STRING();
        name.Buffer = nameBuf;
        name.Length = (ushort)(dirPath.Length * 2);
        name.MaximumLength = (ushort)((dirPath.Length * 2) + 2);
        IntPtr pName = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
        Marshal.StructureToPtr(name, pName, false);
        var oa = new OBJECT_ATTRIBUTES();
        oa.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
        oa.ObjectName = pName;
        oa.Attributes = 0x40; // OBJ_CASE_INSENSITIVE
        IntPtr hDir;
        const uint DIRECTORY_QUERY = 0x0001;
        int st = NtOpenDirectoryObject(out hDir, DIRECTORY_QUERY, ref oa);
        Marshal.FreeHGlobal(pName);
        Marshal.FreeHGlobal(nameBuf);
        if (st != 0) { return result; }
        try {
            int bufLen = 16384;
            IntPtr buf = Marshal.AllocHGlobal(bufLen);
            try {
                uint ctx = 0; uint retLen;
                bool restart = true;
                int count = 0;
                int entrySize = Marshal.SizeOf(typeof(OBJECT_DIRECTORY_INFORMATION));
                while (count < cap) {
                    int s = NtQueryDirectoryObject(hDir, buf, bufLen, false, restart, ref ctx, out retLen);
                    restart = false;
                    if (s != 0) { break; }
                    IntPtr cur = buf;
                    bool any = false;
                    while (count < cap) {
                        var info = (OBJECT_DIRECTORY_INFORMATION)Marshal.PtrToStructure(cur, typeof(OBJECT_DIRECTORY_INFORMATION));
                        if (info.Name.Buffer == IntPtr.Zero && info.Name.Length == 0) { break; }
                        string nm = info.Name.Buffer != IntPtr.Zero ? Marshal.PtrToStringUni(info.Name.Buffer, info.Name.Length / 2) : "";
                        string tp = info.TypeName.Buffer != IntPtr.Zero ? Marshal.PtrToStringUni(info.TypeName.Buffer, info.TypeName.Length / 2) : "";
                        if (nm.Length > 0) { result.Add(new string[] { nm, tp }); count++; any = true; }
                        cur = (IntPtr)(cur.ToInt64() + entrySize);
                    }
                    if (!any) { break; }
                }
            } finally { Marshal.FreeHGlobal(buf); }
        } finally { NtClose(hDir); }
        return result;
    }
}
'@
    Add-Type -TypeDefinition $cs -Language CSharp -ErrorAction Stop
}
