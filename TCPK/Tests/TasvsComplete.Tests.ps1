#requires -Version 5.1
# Pester 5: TASVS v1.8 completeness batch -
#   CODE-4.6 format-string sink, NETWORK-4.1 mail-injection sink (callsite rules),
#   CONF-1.4 leftover dev artifacts (Test-TcpkDevArtifacts),
#   CODE-2.4 debug-build detection (Test-TcpkDebugFlags + DebuggableAttribute via Cecil).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:fx = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-tasvsc-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx | Out-Null
}
AfterAll {
    if ($script:fx -and (Test-Path $script:fx)) { Remove-Item $script:fx -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'New injection-sink rules (CODE-4.6 / NETWORK-4.1)' {
    It 'Test-TcpkCallsites flags format-string and mail APIs (Inferred)' {
        'var s = String.Format(userInput); new SmtpClient().Send(new MailMessage());' |
            Set-Content -LiteralPath (Join-Path $script:fx 'Mail.dll') -Encoding UTF8
        $c = @(Test-TcpkCallsites -Path $script:fx)
        ($c | Where-Object RuleId -like '*format-string*') | Should -Not -BeNullOrEmpty
        ($c | Where-Object RuleId -like '*mail-injection*') | Should -Not -BeNullOrEmpty
        ($c | Where-Object { $_.RuleId -like '*mail-injection*' })[0].Confidence | Should -Be 'Inferred'
    }
}

Describe 'Test-TcpkDevArtifacts (CONF-1.4)' {
    It 'is exported' { Get-Command Test-TcpkDevArtifacts -EA SilentlyContinue | Should -Not -BeNullOrEmpty }
    It 'flags shipped debug symbols, source, backups, dev-config, api-spec, and .git' {
        $d = Join-Path $script:fx 'app'; New-Item -ItemType Directory -Path $d | Out-Null
        'x'   | Set-Content -LiteralPath (Join-Path $d 'app.pdb')
        'c'   | Set-Content -LiteralPath (Join-Path $d 'Foo.cs')
        'old' | Set-Content -LiteralPath (Join-Path $d 'config.bak')
        '{}'  | Set-Content -LiteralPath (Join-Path $d 'appsettings.Development.json')
        '{}'  | Set-Content -LiteralPath (Join-Path $d 'swagger.json')
        New-Item -ItemType Directory -Path (Join-Path $d '.git') | Out-Null
        'ref' | Set-Content -LiteralPath (Join-Path $d '.git\HEAD')
        $f = @(Test-TcpkDevArtifacts -Path $d)
        foreach ($rid in 'devartifact.debug-symbols','devartifact.source','devartifact.backup','devartifact.dev-config','devartifact.api-spec','devartifact.vcs-dir') {
            ($f | Where-Object RuleId -eq $rid) | Should -Not -BeNullOrEmpty
        }
        ($f | Where-Object RuleId -eq 'devartifact.debug-symbols')[0].Severity | Should -Be 'MEDIUM'
    }
}

Describe 'Test-TcpkDebugFlags - debug-build detection (CODE-2.4)' {
    It 'flags a Debug-compiled assembly (JIT optimizer disabled)' {
        $cecil = & (Get-Module TCPK) { Initialize-TcpkCecil }
        $dbgDll = Join-Path $script:fx 'DebugBuilt.dll'
        $compiled = $false
        try {
            if ($PSVersionTable.PSEdition -eq 'Core') {
                # .NET Core: System.CodeDom CSharpCodeProvider throws PlatformNotSupportedException.
                # Compile via Add-Type instead and emit the DebuggableAttribute explicitly with
                # DebuggingModes.DisableOptimizations (IsJITOptimizerDisabled), the same shape a
                # Debug build produces and what the detector reads.
                $src = @'
[assembly: System.Diagnostics.Debuggable(System.Diagnostics.DebuggableAttribute.DebuggingModes.DisableOptimizations)]
public class C { public int X() { return 1; } }
'@
                Add-Type -TypeDefinition $src -OutputAssembly $dbgDll -OutputType Library -ErrorAction Stop
                $compiled = Test-Path $dbgDll
            } else {
                $prov = New-Object Microsoft.CSharp.CSharpCodeProvider
                $cp = New-Object System.CodeDom.Compiler.CompilerParameters
                $cp.GenerateExecutable = $false
                $cp.IncludeDebugInformation = $true     # emits DebuggableAttribute w/ IsJITOptimizerDisabled=true
                $cp.OutputAssembly = $dbgDll
                $r = $prov.CompileAssemblyFromSource($cp, 'public class C { public int X() { return 1; } }')
                $compiled = (Test-Path $dbgDll) -and ($r.Errors.Count -eq 0)
            }
        } catch { }

        if (-not $cecil -or -not $compiled) {
            Set-ItResult -Skipped -Because 'Mono.Cecil and/or the C# compiler is unavailable in this environment'
            return
        }
        # The detector reads the DebuggableAttribute's DebuggingModes/JIT-optimizer flag.
        # Some local CodeDom compilers emit the attribute with 0 ctor args (an
        # unrepresentative form); only assert when the compiled DLL actually carries a
        # parseable optimizer-disabled attribute, otherwise skip (env-dependent).
        $argc = & (Get-Module TCPK) {
            param($p)
            $null = Initialize-TcpkCecil
            try {
                $a = [Mono.Cecil.AssemblyDefinition]::ReadAssembly($p)
                $d = $a.CustomAttributes | Where-Object { $_.AttributeType.Name -eq 'DebuggableAttribute' } | Select-Object -First 1
                $n = if ($d) { $d.ConstructorArguments.Count } else { -1 }
                $a.Dispose(); $n
            } catch { -1 }
        } $dbgDll
        if ($argc -notin 1,2) {
            Set-ItResult -Skipped -Because "this compiler emitted DebuggableAttribute with $argc ctor args (no parseable optimizer flag)"
            return
        }
        $f = @(Test-TcpkDebugFlags -Path (Split-Path $dbgDll -Parent)) | Where-Object RuleId -eq 'debugflags.debug-build'
        $f | Should -Not -BeNullOrEmpty
        $f[0].Confidence | Should -Be 'Confirmed'
    }
}
