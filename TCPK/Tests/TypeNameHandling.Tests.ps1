#requires -Version 5.1
# Json.NET TypeNameHandling != None is a polymorphic-deserialization RCE gadget. A
# source-string match sees the enum NAME but not the VALUE; the IL verdict reads the
# constant fed to set_TypeNameHandling and proves a non-None setting (Confirmed IL),
# leaving None untouched. Needs Mono.Cecil + a Newtonsoft.Json.dll to compile the
# fixture against; skips if either is missing (e.g. a bare CI runner).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:cecil = $false
    try { $script:cecil = & (Get-Module TCPK) { Test-TcpkCecilAvailable } } catch { }
    # A shipped Newtonsoft.Json.dll is typically a .NET Framework build, which the .NET Core
    # compiler will not target -- so build+reference the fixture only under Windows PowerShell
    # 5.1 (Desktop edition). The verdict logic is runtime-agnostic; this is a fixture limit.
    $script:desktop = ($PSVersionTable.PSEdition -eq 'Desktop')

    # locate any Newtonsoft.Json.dll (Program Files apps, NuGet cache, GAC)
    $script:njson = $null
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, (Join-Path $env:USERPROFILE '.nuget'),
               (Join-Path $env:USERPROFILE '.dotnet'), '/usr/share', '/usr/lib') | Where-Object { $_ -and (Test-Path $_) }
    foreach ($r in $roots) {
        $hit = Get-ChildItem -LiteralPath $r -Recurse -File -Filter 'Newtonsoft.Json.dll' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) { $script:njson = $hit.FullName; break }
    }

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-tnh-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
    if ($script:cecil -and $script:njson -and $script:desktop) {
        $vuln = 'using Newtonsoft.Json; public class TnhBad { public object Vuln(string s){ var st = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All }; return JsonConvert.DeserializeObject(s, st); } }'
        $script:dllV = Join-Path $script:work 'TnhBad.dll'
        Add-Type -TypeDefinition $vuln -OutputAssembly $script:dllV -OutputType Library -ReferencedAssemblies $script:njson
        $safe = 'using Newtonsoft.Json; public class TnhSafe { public object Ok(string s){ var st = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None }; return JsonConvert.DeserializeObject(s, st); } }'
        $script:dllS = Join-Path $script:work 'TnhSafe.dll'
        Add-Type -TypeDefinition $safe -OutputAssembly $script:dllS -OutputType Library -ReferencedAssemblies $script:njson
    }
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'TypeNameHandling IL verdict' {
    BeforeEach {
        if (-not $script:cecil) { Set-ItResult -Skipped -Because 'Mono.Cecil (ILSpy) not available' }
        elseif (-not $script:desktop) { Set-ItResult -Skipped -Because 'Newtonsoft fixture needs the .NET Framework compiler (5.1/Desktop only)' }
        elseif (-not $script:njson) { Set-ItResult -Skipped -Because 'no Newtonsoft.Json.dll available to compile the fixture' }
    }

    It 'proves TypeNameHandling.All as a CRITICAL gadget' {
        $v = @(& (Get-Module TCPK) { param($d) Get-TcpkTypeNameHandlingVerdicts -DllPath $d } $script:dllV)
        $v.Count | Should -BeGreaterThan 0
        $v[0].Name     | Should -Be 'All'
        $v[0].Severity | Should -Be 'CRITICAL'
    }

    It 'returns nothing for TypeNameHandling.None (precision)' {
        (@(& (Get-Module TCPK) { param($d) Get-TcpkTypeNameHandlingVerdicts -DllPath $d } $script:dllS)).Count | Should -Be 0
    }

    It 'upgrades a deser.typenamehandling lead to Confirmed (IL) / CRITICAL via Confirm-TcpkCallsiteUsage' {
        $f = & (Get-Module TCPK) { param($p) New-TcpkFinding -Module 'static' -RuleId 'deser.typenamehandling' `
            -Severity 'MEDIUM' -Confidence 'Inferred' -Title 'tnh' -File $p -Evidence 'TypeNameHandling' } $script:dllV
        $r = $f | & (Get-Module TCPK) { $input | Confirm-TcpkCallsiteUsage }
        $r.Confidence | Should -Be 'Confirmed (IL)'
        $r.Severity   | Should -Be 'CRITICAL'
    }

    It 'leaves a None-only deser.typenamehandling lead as Inferred (no over-claim)' {
        $f = & (Get-Module TCPK) { param($p) New-TcpkFinding -Module 'static' -RuleId 'deser.typenamehandling' `
            -Severity 'MEDIUM' -Confidence 'Inferred' -Title 'tnh' -File $p -Evidence 'TypeNameHandling' } $script:dllS
        $r = $f | & (Get-Module TCPK) { $input | Confirm-TcpkCallsiteUsage }
        $r.Confidence | Should -Be 'Inferred'
    }
}
