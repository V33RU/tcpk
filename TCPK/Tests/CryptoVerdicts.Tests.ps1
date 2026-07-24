#requires -Version 5.1
# IL-proven weak crypto: read the actual construction / constant fed to a crypto API
# (a source-string regex rarely survives compilation). Proves weak algorithm choice,
# ECB mode, and hardcoded key/IV as Confirmed (IL). Skips if Mono.Cecil is absent.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:cecil = $false
    try { $script:cecil = & (Get-Module TCPK) { Test-TcpkCecilAvailable } } catch { }
    # The fixtures use OBSOLETE crypto types (DESCryptoServiceProvider, etc.) which the .NET
    # Core / .NET 8 compiler rejects as errors (SYSLIB0021); Add-Type -OutputAssembly on them
    # only compiles under the .NET Framework (Windows PowerShell 5.1 = Desktop edition). The
    # detection code itself is runtime-agnostic; this is purely a fixture-compilation limit.
    $script:desktop = ($PSVersionTable.PSEdition -eq 'Desktop')

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-cry-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
    if ($script:cecil -and $script:desktop) {
        $cs = @'
using System; using System.Text; using System.Security.Cryptography;
public class CryptoBad {
  public void WeakCipher(){ var d = new DESCryptoServiceProvider(); d.GenerateKey(); }
  public void WeakHash(){ var h = MD5.Create(); h.ComputeHash(new byte[1]); }
  public void Ecb(){ var a = Aes.Create(); a.Mode = CipherMode.ECB; }
  public void HardKey(){ var a = Aes.Create(); a.Key = new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}; }
  public void HardKeyStr(){ var a = Aes.Create(); a.Key = Encoding.UTF8.GetBytes("hardcodedkey1234"); }
  public void StaticIv(){ var a = Aes.Create(); a.IV = new byte[16]; }
  public void GoodKey(byte[] k){ var a = Aes.Create(); a.Key = k; a.Mode = CipherMode.CBC; }
}
'@
        $script:dll = Join-Path $script:work 'CryptoBad.dll'
        Add-Type -TypeDefinition $cs -OutputAssembly $script:dll -OutputType Library
        $script:v = @(& (Get-Module TCPK) { param($d) Get-TcpkCryptoVerdicts -DllPath $d } $script:dll)
    }
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'Get-TcpkCryptoVerdicts (IL-proven weak crypto)' {
    BeforeEach {
        if (-not $script:cecil) { Set-ItResult -Skipped -Because 'Mono.Cecil (ILSpy) not available' }
        elseif (-not $script:desktop) { Set-ItResult -Skipped -Because 'fixture uses obsolete crypto types the .NET Core compiler rejects (5.1/Desktop only)' }
    }

    It 'proves a weak cipher construction (DES -> newobj)' {
        $f = $script:v | Where-Object { $_.Method -eq 'WeakCipher' }
        $f.Kind | Should -Be 'weak-cipher'; $f.Severity | Should -Be 'MEDIUM'
    }
    It 'proves a weak hash factory (MD5.Create)' {
        $f = $script:v | Where-Object { $_.Method -eq 'WeakHash' }
        $f.Kind | Should -Be 'weak-hash'
    }
    It 'proves ECB mode from the constant (CipherMode.ECB = 2)' {
        $f = $script:v | Where-Object { $_.Method -eq 'Ecb' }
        $f.Kind | Should -Be 'ecb-mode'; $f.Severity | Should -Be 'MEDIUM'
    }
    It 'proves a hardcoded key from an inline byte[] literal' {
        $f = $script:v | Where-Object { $_.Method -eq 'HardKey' }
        $f.Kind | Should -Be 'hardcoded-key'; $f.Severity | Should -Be 'HIGH'
    }
    It 'proves a hardcoded key from Encoding.GetBytes("literal")' {
        $f = $script:v | Where-Object { $_.Method -eq 'HardKeyStr' }
        $f.Kind | Should -Be 'hardcoded-key'
    }
    It 'proves a static/zero IV from new byte[16]' {
        $f = $script:v | Where-Object { $_.Method -eq 'StaticIv' }
        $f.Kind | Should -Be 'hardcoded-IV'; $f.Severity | Should -Be 'MEDIUM'
    }
    It 'does NOT flag a variable key + CBC mode (precision)' {
        ($script:v | Where-Object { $_.Method -eq 'GoodKey' }) | Should -BeNullOrEmpty
    }
    It 'surfaces these end-to-end as Confirmed (IL) from Test-TcpkCryptoMisuse' {
        $f = @(Test-TcpkCryptoMisuse -Path $script:work | Where-Object { $_.Confidence -eq 'Confirmed (IL)' })
        $f.Count | Should -BeGreaterThan 4
        ($f | Where-Object { $_.RuleId -eq 'crypto.hardcoded-key' }) | Should -Not -BeNullOrEmpty
    }
}
