#requires -Version 5.1
# Credential-store decryption: recover a Chromium/WebView2 profile master key by user-DPAPI
# and AES-256-GCM-decrypt a v10 cookie/password blob with it -- the infostealer primitive,
# proven. Windows-only (DPAPI + CNG); the fixtures are built with the current user's own
# DPAPI + a local CNG GCM encryptor, so nothing external is needed. Skips off Windows.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:win = ($IsWindows -ne $false)   # $null on Windows PS 5.1, $false on non-Windows PS7
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-cred-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
    if ($script:win) {
        try { Add-Type -AssemblyName System.Security -ErrorAction Stop } catch { }
        # local CNG AES-GCM encryptor to build a v10 fixture (string params must be Unicode)
        Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
namespace TcpkTestGcm { public static class E {
 [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)] static extern int BCryptOpenAlgorithmProvider(out IntPtr h,string id,string impl,int f);
 [DllImport("bcrypt.dll")] static extern int BCryptCloseAlgorithmProvider(IntPtr h,int f);
 [DllImport("bcrypt.dll", CharSet=CharSet.Unicode)] static extern int BCryptSetProperty(IntPtr h,string p,byte[] i,int cb,int f);
 [DllImport("bcrypt.dll")] static extern int BCryptGenerateSymmetricKey(IntPtr a,out IntPtr k,IntPtr ko,int cbko,byte[] s,int cbs,int f);
 [DllImport("bcrypt.dll")] static extern int BCryptDestroyKey(IntPtr k);
 [DllImport("bcrypt.dll")] static extern int BCryptEncrypt(IntPtr k,byte[] i,int cbi,ref AI pad,byte[] iv,int cbiv,byte[] o,int cbo,out int res,int f);
 [StructLayout(LayoutKind.Sequential)] struct AI { public int cbSize; public int dwInfoVersion; public IntPtr pbNonce; public int cbNonce; public IntPtr pbAuthData; public int cbAuthData; public IntPtr pbTag; public int cbTag; public IntPtr pbMacContext; public int cbMacContext; public int cbAAD; public long cbData; public int dwFlags; }
 public static byte[] Enc(byte[] key, byte[] nonce, byte[] plain, byte[] tagOut){
  IntPtr a; if(BCryptOpenAlgorithmProvider(out a,"AES",null,0)!=0) return null; IntPtr k=IntPtr.Zero;
  var gn=GCHandle.Alloc(nonce,GCHandleType.Pinned); var gt=GCHandle.Alloc(tagOut,GCHandleType.Pinned);
  try { byte[] m=System.Text.Encoding.Unicode.GetBytes("ChainingModeGCM\0"); BCryptSetProperty(a,"ChainingMode",m,m.Length,0);
   if(BCryptGenerateSymmetricKey(a,out k,IntPtr.Zero,0,key,key.Length,0)!=0) return null;
   var ai=new AI(); ai.cbSize=Marshal.SizeOf(typeof(AI)); ai.dwInfoVersion=1; ai.pbNonce=gn.AddrOfPinnedObject(); ai.cbNonce=nonce.Length; ai.pbTag=gt.AddrOfPinnedObject(); ai.cbTag=tagOut.Length;
   byte[] o=new byte[plain.Length]; int res; if(BCryptEncrypt(k,plain,plain.Length,ref ai,null,0,o,o.Length,out res,0)!=0) return null; return o;
  } finally { gn.Free(); gt.Free(); if(k!=IntPtr.Zero) BCryptDestroyKey(k); BCryptCloseAlgorithmProvider(a,0); }
 }
}}
'@ -ErrorAction SilentlyContinue

        $script:key = New-Object byte[] 32
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($script:key)
    }
}
AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) { try { [System.IO.Directory]::Delete($script:work, $true) } catch {} }
}

Describe 'Credential-store decryption' {
    BeforeEach { if (-not $script:win) { Set-ItResult -Skipped -Because 'Windows-only (DPAPI + CNG)' } }

    It 'recovers the AES master key from a DPAPI-protected Local State' {
        $prot = [System.Security.Cryptography.ProtectedData]::Protect($script:key, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        $pre = [Text.Encoding]::ASCII.GetBytes('DPAPI')
        $comb = New-Object byte[] ($pre.Length + $prot.Length)
        [Array]::Copy($pre, 0, $comb, 0, $pre.Length); [Array]::Copy($prot, 0, $comb, $pre.Length, $prot.Length)
        $ls = Join-Path $script:work 'Local State'
        (@{ os_crypt = @{ encrypted_key = [Convert]::ToBase64String($comb) } } | ConvertTo-Json) | Set-Content -LiteralPath $ls -Encoding UTF8
        $r = InModuleScope TCPK -Parameters @{ p = $ls } { param($p) Get-TcpkChromiumMasterKey -LocalStatePath $p }
        ($r -join ',') | Should -Be ($script:key -join ',')
    }

    It 'AES-GCM-decrypts a v10 blob with the recovered key' {
        $nonce = New-Object byte[] 12
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nonce)
        $plain = [Text.Encoding]::UTF8.GetBytes('sekret-session-cookie')
        $tag = New-Object byte[] 16
        $cipher = [TcpkTestGcm.E]::Enc($script:key, $nonce, $plain, $tag)
        $cipher | Should -Not -BeNullOrEmpty
        $v10 = New-Object byte[] (3 + 12 + $cipher.Length + 16)
        [Array]::Copy([Text.Encoding]::ASCII.GetBytes('v10'), 0, $v10, 0, 3)
        [Array]::Copy($nonce, 0, $v10, 3, 12)
        [Array]::Copy($cipher, 0, $v10, 15, $cipher.Length)
        [Array]::Copy($tag, 0, $v10, 15 + $cipher.Length, 16)
        $pt = InModuleScope TCPK -Parameters @{ k = $script:key; b = $v10 } { param($k, $b) Unprotect-TcpkChromiumBlob -Key $k -Blob $b }
        $pt | Should -Be 'sekret-session-cookie'
    }

    It 'returns null for a non-DPAPI (App-Bound) encrypted_key (precision)' {
        $comb = [Text.Encoding]::ASCII.GetBytes('APPBsomethingelse')
        $ls = Join-Path $script:work 'Local State APPB'
        (@{ os_crypt = @{ encrypted_key = [Convert]::ToBase64String($comb) } } | ConvertTo-Json) | Set-Content -LiteralPath $ls -Encoding UTF8
        $r = InModuleScope TCPK -Parameters @{ p = $ls } { param($p) Get-TcpkChromiumMasterKey -LocalStatePath $p }
        $r | Should -BeNullOrEmpty
    }

    It 'returns null when a v10 blob is decrypted with the WRONG key (tag mismatch)' {
        $nonce = New-Object byte[] 12; $plain = [Text.Encoding]::UTF8.GetBytes('x'); $tag = New-Object byte[] 16
        $cipher = [TcpkTestGcm.E]::Enc($script:key, $nonce, $plain, $tag)
        $v10 = New-Object byte[] (3 + 12 + $cipher.Length + 16)
        [Array]::Copy([Text.Encoding]::ASCII.GetBytes('v10'), 0, $v10, 0, 3)
        [Array]::Copy($nonce, 0, $v10, 3, 12); [Array]::Copy($cipher, 0, $v10, 15, $cipher.Length); [Array]::Copy($tag, 0, $v10, 15 + $cipher.Length, 16)
        $wrong = New-Object byte[] 32   # all-zero, wrong key
        $pt = InModuleScope TCPK -Parameters @{ k = $wrong; b = $v10 } { param($k, $b) Unprotect-TcpkChromiumBlob -Key $k -Blob $b }
        $pt | Should -BeNullOrEmpty
    }
}
