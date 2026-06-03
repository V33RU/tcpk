#requires -Version 5.1
# Pester 5: deterministic IL confirmation of TLS cert-validation bypass.
# Test-TcpkTlsBypass should promote a cert callback that returns true unconditionally
# (shape: returns bool + has an SslPolicyErrors parameter) to a CONFIRMED CRITICAL
# finding, across any assembly. Skips if Mono.Cecil / the C# compiler is unavailable.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:fx = Join-Path $env:TEMP ('tcpk-tlscb-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx | Out-Null
    $script:dll = Join-Path $script:fx 'AcmeNet.dll'
    $script:compiled = $false
    try {
        $prov = New-Object Microsoft.CSharp.CSharpCodeProvider
        $cp = New-Object System.CodeDom.Compiler.CompilerParameters
        $cp.GenerateExecutable = $false
        $cp.OutputAssembly = $script:dll
        $cp.ReferencedAssemblies.Add('System.dll') | Out-Null
        $src = @'
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class AcmeTls {
    public bool ValidateServerCert(object sender, X509Certificate2 cert, X509Chain chain, SslPolicyErrors errors) {
        return true;   // accepts every certificate
    }
}
'@
        $r = $prov.CompileAssemblyFromSource($cp, $src)
        $script:compiled = (Test-Path $script:dll) -and ($r.Errors.Count -eq 0)
    } catch { }
}
AfterAll {
    if ($script:fx -and (Test-Path $script:fx)) { Remove-Item $script:fx -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Test-TcpkTlsBypass - IL-confirmed accept-all cert callback' {
    It 'flags a bool(...,SslPolicyErrors) callback that returns true unconditionally as CONFIRMED CRITICAL' {
        $cecil = & (Get-Module TCPK) { Initialize-TcpkCecil }
        if (-not $cecil -or -not $script:compiled) {
            Set-ItResult -Skipped -Because 'Mono.Cecil and/or the C# compiler is unavailable'
            return
        }
        $f = @(Test-TcpkTlsBypass -Path $script:dll) | Where-Object RuleId -eq 'tls-bypass.cert-callback-accepts-all'
        $f | Should -Not -BeNullOrEmpty
        $f[0].Severity   | Should -Be 'CRITICAL'
        $f[0].Confidence | Should -Be 'Confirmed'
    }
}
