#requires -Version 5.1
# Pester 5: SBOM is now CVE-aware.
#  (A) managed components get the true NuGet package id + version from deps.json
#      (accurate pkg:nuget purls, consumable by external SBOM-CVE scanners).
#  (B) Export-TcpkSbom embeds a CycloneDX vulnerabilities[] array linked to the
#      affected component's bom-ref.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'SBOM purl from deps.json (Part A)' {
    It 'uses the deps.json package id + version for a managed component' {
        $fx = Join-Path $env:TEMP ('tcpk-sbomtA-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $fx | Out-Null
        $compiled = $false
        try {
            $prov = New-Object Microsoft.CSharp.CSharpCodeProvider
            $cp = New-Object System.CodeDom.Compiler.CompilerParameters
            $cp.GenerateExecutable = $false; $cp.OutputAssembly = (Join-Path $fx 'AcmeLib.dll')
            $r = $prov.CompileAssemblyFromSource($cp, 'public class A { public int X() { return 1; } }')
            $compiled = (Test-Path (Join-Path $fx 'AcmeLib.dll')) -and ($r.Errors.Count -eq 0)
            $deps = '{ "targets": { ".NETCoreApp,Version=v6.0": { "AcmeLib/9.9.9": { "runtime": { "lib/net6.0/AcmeLib.dll": {} } } } }, "libraries": { "AcmeLib/9.9.9": { "type": "package" } } }'
            Set-Content -LiteralPath (Join-Path $fx 'myapp.deps.json') -Value $deps -Encoding ASCII
        } catch { }
        if (-not $compiled) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        try {
            $comp = & (Get-Module TCPK) { param($p) Get-TcpkSbomComponents -Path $p } $fx | Where-Object Name -eq 'AcmeLib'
            $comp.Version | Should -Be '9.9.9'
            $comp.Purl    | Should -Be 'pkg:nuget/AcmeLib@9.9.9'
            $comp.BomRef  | Should -Be 'AcmeLib@9.9.9'
        } finally { Remove-Item $fx -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'SBOM vulnerabilities array (Part B)' {
    It 'embeds the CVE and links it to the component bom-ref' {
        $out = Join-Path $env:TEMP ('tcpk-sbomtB-' + [guid]::NewGuid().ToString('N') + '.cdx.json')
        $comp = [pscustomobject]@{ Name='Newtonsoft.Json'; Version='12.0.0'; Publisher=''; Sha256='abc'; Managed=$true; Purl='pkg:nuget/Newtonsoft.Json@12.0.0'; Type='library'; BomRef='Newtonsoft.Json@12.0.0'; Path='C:\app\Newtonsoft.Json.dll' }
        $cve  = [pscustomobject]@{ Cve='CVE-2024-21907'; Package='Newtonsoft.Json'; ShippedVersion='12.0.0'; FixedVersion='13.0.1'; Status='Vulnerable'; Severity='HIGH'; Cwe=@('CWE-502'); Title='Newtonsoft.Json DoS'; Summary='nested json'; File='myapp.deps.json'; References=@('https://x') }
        try {
            Export-TcpkSbom -Components @($comp) -CveMatches @($cve) -OutFile $out | Out-Null
            $j = Get-Content $out -Raw | ConvertFrom-Json
            $j.vulnerabilities       | Should -Not -BeNullOrEmpty
            $j.vulnerabilities[0].id | Should -Be 'CVE-2024-21907'
            $j.vulnerabilities[0].ratings[0].severity | Should -Be 'high'
            $j.vulnerabilities[0].affects[0].ref      | Should -Be $j.components[0].'bom-ref'
        } finally { Remove-Item $out -Force -ErrorAction SilentlyContinue }
    }
    It 'marks an unconfirmed native match as in_triage' {
        $out = Join-Path $env:TEMP ('tcpk-sbomtC-' + [guid]::NewGuid().ToString('N') + '.cdx.json')
        $comp = [pscustomobject]@{ Name='WebView2Loader'; Version='1.0.0'; Publisher=''; Sha256='d'; Managed=$false; Purl='pkg:generic/WebView2Loader@1.0.0'; Type='library'; BomRef='WebView2Loader@1.0.0'; Path='C:\app\WebView2Loader.dll' }
        $cve  = [pscustomobject]@{ Cve='CVE-2023-4863'; Package='libwebp'; ShippedVersion=$null; FixedVersion='1.3.2'; Status='PossiblyEmbedded'; Severity='CRITICAL'; Cwe=@('CWE-787'); Title='libwebp overflow'; Summary='webp'; File='WebView2Loader.dll'; References=@() }
        try {
            Export-TcpkSbom -Components @($comp) -CveMatches @($cve) -OutFile $out | Out-Null
            $j = Get-Content $out -Raw | ConvertFrom-Json
            $j.vulnerabilities[0].analysis.state | Should -Be 'in_triage'
        } finally { Remove-Item $out -Force -ErrorAction SilentlyContinue }
    }
}
