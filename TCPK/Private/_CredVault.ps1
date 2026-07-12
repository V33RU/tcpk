# Windows Credential Manager extraction for Get-TcpkStoredCredentials. Enumerates the
# current user's vault via CredEnumerate (advapi32) and decodes each CredentialBlob to
# plaintext (the OS returns it decrypted to the owning user). Win32-only: the public cmdlet
# gates this behind Assert-TcpkWindows, so it never runs on a non-Windows host. Parse-safe
# everywhere (Add-Type runs at call time, not module load).
function Read-TcpkCredentialVault {
    param([string]$Filter)
    $sig = @'
using System;
using System.Runtime.InteropServices;
public static class TcpkCred {
    [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredEnumerate(string filter, int flag, out int count, out IntPtr credentials);
    [DllImport("advapi32", SetLastError = true)]
    public static extern void CredFree(IntPtr buffer);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }
}
'@
    try { Add-Type -TypeDefinition $sig -ErrorAction Stop } catch { }   # ignore "type already exists" on re-run
    $out = New-Object 'System.Collections.Generic.List[object]'
    $count = 0; $ptr = [IntPtr]::Zero
    if (-not [TcpkCred]::CredEnumerate($null, 0, [ref]$count, [ref]$ptr)) { return $out.ToArray() }
    try {
        for ($i = 0; $i -lt $count; $i++) {
            $credPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($ptr, $i * [IntPtr]::Size)
            $cred = [System.Runtime.InteropServices.Marshal]::PtrToStructure($credPtr, [type]([TcpkCred+CREDENTIAL]))
            $target = "$($cred.TargetName)"
            if ($Filter -and $target -notlike "*$Filter*") { continue }
            $secret = ''
            if ($cred.CredentialBlobSize -gt 0 -and $cred.CredentialBlob -ne [IntPtr]::Zero) {
                # CredentialBlob is UTF-16 for a Generic credential written by the current user.
                $secret = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($cred.CredentialBlob, [int]($cred.CredentialBlobSize / 2))
            }
            if ($secret) { $out.Add([pscustomobject]@{ Target = $target; User = "$($cred.UserName)"; Secret = $secret }) }
        }
    } finally { if ($ptr -ne [IntPtr]::Zero) { [TcpkCred]::CredFree($ptr) } }
    return $out.ToArray()
}
