#requires -Version 5.1
# Pester 5 tests for the deterministic IL XXE detector (Get-TcpkXxeVerdicts) and its
# Test-TcpkXxe integration. Compiles a tiny sample DLL with Add-Type and checks that the
# IL prover reads the CONSTANT fed to each XML setter -- so DtdProcessing.Parse (unsafe) is
# told apart from Prohibit/Ignore (safe), and a real XmlResolver from the null-resolver
# mitigation. Skips if Mono.Cecil (ILSpy) is unavailable. System.Xml is in the BCL, so the
# fixture compiles anywhere the C# in-process compiler is present.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:cecil = $false
    try { $script:cecil = & (Get-Module TCPK) { Test-TcpkCecilAvailable } } catch { }

    if ($script:cecil) {
        $script:work = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-xxe-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:work -Force | Out-Null
        $src = @'
using System.Xml;
public class XxeCases {
    public void VulnFull(string p) {          // Parse + non-null resolver -> CRITICAL
        var s = new XmlReaderSettings();
        s.DtdProcessing = DtdProcessing.Parse;
        s.XmlResolver = new XmlUrlResolver();
        using (var r = XmlReader.Create(p, s)) { while (r.Read()) {} }
    }
    public void VulnParseOnly(string p) {     // Parse only -> HIGH
        var s = new XmlReaderSettings();
        s.DtdProcessing = DtdProcessing.Parse;
        using (var r = XmlReader.Create(p, s)) { while (r.Read()) {} }
    }
    public void VulnXmlDoc(string xml) {      // XmlDocument non-null resolver -> HIGH
        var d = new XmlDocument();
        d.XmlResolver = new XmlUrlResolver();
        d.LoadXml(xml);
    }
    public void SafeProhibit(string p) {      // Prohibit -> not flagged
        var s = new XmlReaderSettings();
        s.DtdProcessing = DtdProcessing.Prohibit;
        using (var r = XmlReader.Create(p, s)) { while (r.Read()) {} }
    }
    public void SafeIgnore(string p) {        // Ignore -> not flagged
        var s = new XmlReaderSettings();
        s.DtdProcessing = DtdProcessing.Ignore;
        using (var r = XmlReader.Create(p, s)) { while (r.Read()) {} }
    }
    public void SafeNullResolver(string p) {  // resolver = null (mitigation) -> not flagged
        var s = new XmlReaderSettings();
        s.XmlResolver = null;
        using (var r = XmlReader.Create(p, s)) { while (r.Read()) {} }
    }
    public void SafeDefault(string p) {       // DtdProcessing never set -> not flagged
        var s = new XmlReaderSettings();
        using (var r = XmlReader.Create(p, s)) { while (r.Read()) {} }
    }
}
'@
        $script:dll = Join-Path $script:work 'XxeCases.dll'
        Add-Type -TypeDefinition $src -OutputAssembly $script:dll -OutputType Library

        $script:verdicts = & (Get-Module TCPK) { param($d) Get-TcpkXxeVerdicts -DllPath $d } $script:dll
        $script:findings = Test-TcpkXxe -Path $script:work
    }
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        Remove-Item -LiteralPath $script:work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Get-TcpkXxeVerdicts - deterministic IL proof' {
    BeforeEach { if (-not $script:cecil) { Set-ItResult -Skipped -Because 'Mono.Cecil (ILSpy) not available' } }

    It 'flags only the vulnerable methods, never a safe one' {
        $flagged = @($script:verdicts | ForEach-Object { $_.Method } | Sort-Object -Unique)
        $flagged | Should -Contain 'VulnFull'
        $flagged | Should -Contain 'VulnParseOnly'
        $flagged | Should -Contain 'VulnXmlDoc'
        ($script:verdicts | Where-Object { $_.Method -like 'Safe*' }) | Should -BeNullOrEmpty
    }

    It 'proves DtdProcessing.Parse (ldc.i4.2) but not Prohibit/Ignore' {
        $parse = @($script:verdicts | Where-Object { $_.Kind -eq 'dtd-processing-parse' })
        $parse.Count | Should -Be 2   # VulnFull + VulnParseOnly
        @($parse | Where-Object { $_.Method -like 'Safe*' }) | Should -BeNullOrEmpty
    }

    It 'flags a non-null XmlResolver but not the null-resolver mitigation' {
        $res = @($script:verdicts | Where-Object { $_.Kind -eq 'external-xml-resolver' })
        $res.Count | Should -Be 2   # VulnFull + VulnXmlDoc
        ($res | ForEach-Object { $_.Method }) | Should -Not -Contain 'SafeNullResolver'
    }

    It 'escalates DTD + resolver in the SAME method to CRITICAL, either alone to HIGH' {
        @($script:verdicts | Where-Object { $_.Method -eq 'VulnFull' -and $_.Severity -eq 'CRITICAL' }).Count | Should -Be 2
        ($script:verdicts | Where-Object { $_.Method -eq 'VulnParseOnly' }).Severity | Should -Be 'HIGH'
        ($script:verdicts | Where-Object { $_.Method -eq 'VulnXmlDoc' }).Severity   | Should -Be 'HIGH'
    }

    It 'writes the IL proof (the setter and its constant) into each verdict' {
        foreach ($v in $script:verdicts) {
            $v.Il | Should -Match 'set_(DtdProcessing|XmlResolver|ProhibitDtd)'
        }
    }
}

Describe 'Test-TcpkXxe - emits Confirmed (IL) findings' {
    BeforeEach { if (-not $script:cecil) { Set-ItResult -Skipped -Because 'Mono.Cecil (ILSpy) not available' } }

    It 'produces four Confirmed (IL) XXE findings for the fixture' {
        $il = @($script:findings | Where-Object { "$($_.Confidence)" -eq 'Confirmed (IL)' })
        $il.Count | Should -Be 4
        ($il | ForEach-Object { "$($_.RuleId)" } | Sort-Object -Unique) | Should -Contain 'xxe.dtd-processing-parse'
        ($il | ForEach-Object { "$($_.RuleId)" } | Sort-Object -Unique) | Should -Contain 'xxe.external-xml-resolver'
    }
}
