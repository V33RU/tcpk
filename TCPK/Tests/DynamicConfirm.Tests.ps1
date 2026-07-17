#requires -Version 5.1
# Dynamic harness, slice 1: Invoke-TcpkDynamicConfirm proves (without exploitation) that
# an app FOLLOWS a command-line host/token override by observing whether it connects to a
# TCPK-controlled loopback listener. Gated behind the exploit bucket + -ConfirmDynamic.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-dyn-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null

    # C# console-app fixtures. Add-Type -OutputType ConsoleApplication is unsupported on
    # .NET Core (PSNotSupportedException), and the harness is Windows-only anyway, so build
    # them only on Windows; the Windows-runtime Its below Skip off-Windows.
    if ($IsWindows -ne $false) {
    # "vulnerable" app: follows --host and connects to it, forwarding --token
    $vuln = @'
using System; using System.Net.Sockets; using System.Text; using System.Threading;
class P { static void Main(string[] a){
  string host=null, token="none";
  for(int i=0;i<a.Length-1;i++){ if(a[i]=="--host") host=a[i+1]; if(a[i]=="--token") token=a[i+1]; }
  if(host!=null){ var hp=host.Split(':'); try{ using(var c=new TcpClient(hp[0], int.Parse(hp[1]))){ var b=Encoding.ASCII.GetBytes("CONNECT token="+token); c.GetStream().Write(b,0,b.Length); Thread.Sleep(400);} }catch{} }
  Thread.Sleep(300);
}}
'@
    $script:vulnExe = Join-Path $script:work 'vulnapp.exe'
    Add-Type -TypeDefinition $vuln -OutputAssembly $script:vulnExe -OutputType ConsoleApplication -ReferencedAssemblies 'System'

    # "safe" app: ignores --host, connects nowhere
    $safe = 'using System; using System.Threading; class P { static void Main(string[] a){ Thread.Sleep(300); } }'
    $script:safeExe = Join-Path $script:work 'safeapp.exe'
    Add-Type -TypeDefinition $safe -OutputAssembly $script:safeExe -OutputType ConsoleApplication
    }

    & (Get-Module TCPK) { Enable-TcpkExploit -Acknowledge } | Out-Null
}

AfterAll {
    try { & (Get-Module TCPK) { Disable-TcpkExploit } | Out-Null } catch {}
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'Invoke-TcpkDynamicConfirm gating' {
    It 'throws when the exploit bucket is disabled' {
        & (Get-Module TCPK) { Disable-TcpkExploit } | Out-Null
        { Invoke-TcpkDynamicConfirm -Target $script:safeExe -ConfirmDynamic } | Should -Throw
        & (Get-Module TCPK) { Enable-TcpkExploit -Acknowledge } | Out-Null
    }
    It 'throws without -ConfirmDynamic even when enabled' -Skip:($IsWindows -eq $false) {
        { Invoke-TcpkDynamicConfirm -Target $script:safeExe } | Should -Throw
    }
}

Describe 'Invoke-TcpkDynamicConfirm observation' {
    It 'Confirmed (dynamic) when the app follows the CLI host override' -Skip:($IsWindows -eq $false) {
        $r = @(Invoke-TcpkDynamicConfirm -Target $script:vulnExe -ConfirmDynamic -TimeoutSec 10 6>$null)
        $r[0].RuleId     | Should -Be 'dynamic.argv-session-override'
        $r[0].Confidence | Should -Be 'Confirmed (dynamic)'
        $r[0].Severity   | Should -Be 'HIGH'
    }
    It 'stays Inferred/inconclusive when the app ignores the override' -Skip:($IsWindows -eq $false) {
        $r = @(Invoke-TcpkDynamicConfirm -Target $script:safeExe -ConfirmDynamic -TimeoutSec 4 6>$null)
        $r[0].Confidence | Should -Be 'Inferred'
    }
}
