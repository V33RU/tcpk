#requires -Version 5.1
# Regression guard for the bundled ILSpy decompiler engine (ICSharpCode.Decompiler),
# which turns the Decompiler tab's output from raw IL into readable C#.
#
#   1. The engine + the netstandard2.0 facade chain it needs under .NET Framework
#      (System.Reflection.Metadata / Immutable / Memory / ...) are present in lib\Decompiler.
#   2. Initialize-TcpkDecompilerEngine byte-loads them (Mark-of-the-Web proof) and resolves
#      CSharpDecompiler. This is the netstandard2.0-under-.NET-Framework load that cannot be
#      exercised off Windows -- running this test on PS 5.1 confirms it.
#   3. Get-TcpkCSharpDecompile returns real C# for a known managed assembly. The bundled
#      Mono.Cecil.dll is always present, so decompiling one of its types is deterministic.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Bundled decompiler engine is present' {
    It 'ships the engine and its facade chain in lib\Decompiler' {
        InModuleScope TCPK {
            $libDir = Join-Path $script:TcpkRoot 'lib\Decompiler'
            Test-Path (Join-Path $libDir 'ICSharpCode.Decompiler.dll')       | Should -BeTrue
            Test-Path (Join-Path $libDir 'System.Reflection.Metadata.dll')   | Should -BeTrue
            Test-Path (Join-Path $libDir 'System.Collections.Immutable.dll') | Should -BeTrue
        }
    }
}

Describe 'Decompiler engine loads and produces C#' {
    It 'Initialize-TcpkDecompilerEngine loads the engine (netstandard2.0 under .NET FW)' {
        InModuleScope TCPK {
            Initialize-TcpkDecompilerEngine | Should -BeTrue
            [bool]('ICSharpCode.Decompiler.CSharp.CSharpDecompiler' -as [type]) | Should -BeTrue
        }
    }

    It 'Get-TcpkCSharpDecompile returns readable C# for a known type' {
        InModuleScope TCPK {
            $cecil = Join-Path $script:TcpkRoot 'lib\Cecil\Mono.Cecil.dll'
            $cs = Get-TcpkCSharpDecompile -Dll $cecil -TypeFullName 'Mono.Cecil.AssemblyDefinition'
            $cs | Should -Not -BeNullOrEmpty
            $cs | Should -Match 'AssemblyDefinition'
            $cs | Should -Match 'ReadAssembly'
        }
    }

    It 'Invoke-TcpkDecompile -Type returns the whole decompiled type' {
        InModuleScope TCPK {
            $cecil = Join-Path $script:TcpkRoot 'lib\Cecil\Mono.Cecil.dll'
            $cs = Invoke-TcpkDecompile -Dll $cecil -Search 'ReadAssembly' -Type 'Mono.Cecil.AssemblyDefinition' 3>$null
            $cs | Should -Match 'class AssemblyDefinition'
        }
    }
}
