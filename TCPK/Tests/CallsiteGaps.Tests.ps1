#requires -Version 5.1
# Pester 5: the checklist-gap callsite rules (XAML/ObjectDataProvider RCE, UAC-bypass
# registry hijack, COM elevation moniker) must fire, AND the UTF-16 string scan must
# catch wide string literals regardless of byte alignment (odd-offset #US strings were
# previously missed). Skips if the C# compiler is unavailable.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:fx = Join-Path $env:TEMP ('tcpk-gaps-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx | Out-Null
    $script:dll = Join-Path $script:fx 'GapMarkers.dll'
    $script:compiled = $false
    try {
        $prov = New-Object Microsoft.CSharp.CSharpCodeProvider
        $cp = New-Object System.CodeDom.Compiler.CompilerParameters
        $cp.GenerateExecutable = $false
        $cp.OutputAssembly = $script:dll
        $cp.ReferencedAssemblies.Add('System.dll') | Out-Null
        $src = @'
public class GapMarkers {
    public string a = "XamlReader";
    public string b = "ObjectDataProvider";
    public string c = @"ms-settings\shell\open\command";
    public string d = "Elevation:Administrator!new:{0002DF01-0000-0000-C000-000000000046}";
}
'@
        $r = $prov.CompileAssemblyFromSource($cp, $src)
        $script:compiled = (Test-Path $script:dll) -and ($r.Errors.Count -eq 0)
    } catch { }
}
AfterAll {
    if ($script:fx -and (Test-Path $script:fx)) { Remove-Item $script:fx -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Checklist-gap callsite detections' {
    BeforeAll {
        if ($script:compiled) { $script:rules = @(Test-TcpkCallsites -Path $script:dll).RuleId }
    }
    It 'flags XAML / ObjectDataProvider RCE gadget' {
        if (-not $script:compiled) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        $script:rules | Should -Contain 'callsites.xaml-objectdataprovider-rce'
    }
    It 'flags UAC-bypass registry hijack key' {
        if (-not $script:compiled) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        $script:rules | Should -Contain 'callsites.uac-bypass-registry'
    }
    It 'flags COM elevation moniker (odd-aligned UTF-16 literal)' {
        if (-not $script:compiled) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        $script:rules | Should -Contain 'callsites.com-elevation-moniker'
    }
}

Describe 'UTF-16 string scan is alignment-independent' {
    It 'exposes an odd-aligned UTF-16 view so wide literals are not missed' {
        if (-not $script:compiled) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        $names = & (Get-Module TCPK) { param($p) (Read-TcpkStringViews -Path $p).PSObject.Properties.Name } $script:dll
        $names | Should -Contain 'Utf16LeOdd'
    }
}
