#requires -Version 5.1
# Pester 5: Invoke-TcpkJavaDecompile.
#
# CFR and a JRE are optional and usually absent on a build box, so the CFR path self-skips.
# The FALLBACK path needs neither: a .jar is a zip of .class files and the fallback only
# scans bytes, so a fixture jar is built at run time from real zip entries. That means the
# half of this cmdlet that runs when nothing is installed is covered unconditionally, which
# is the half most operators will actually hit.

BeforeDiscovery {
    $script:hasJava = [bool](Get-Command java -ErrorAction SilentlyContinue)
}

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-javadec-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $script:work | Out-Null

    # A .class file's constant pool stores method names and string literals as UTF-8, so a
    # byte scan finds them. This fixture is not a valid class file and does not need to be:
    # the fallback never parses the format, it reads printable runs.
    $script:marker = 'getConnectionSECRETMARKER'
    $classBytes = [Text.Encoding]::UTF8.GetBytes(
        "`0`0`0`0com/example/Db" + $script:marker + "jdbc:sqlserver://db.internal;password=Pr0d")

    $script:classFile = Join-Path $script:work 'Db.class'
    [IO.File]::WriteAllBytes($script:classFile, $classBytes)

    $script:jar = Join-Path $script:work 'app.jar'
    $stage = Join-Path $script:work 'stage'
    New-Item -ItemType Directory -Force -Path (Join-Path $stage 'com\example') | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $stage 'com\example\Db.class'), $classBytes)
    [IO.File]::WriteAllBytes((Join-Path $stage 'com\example\Other.class'),
        [Text.Encoding]::UTF8.GetBytes("`0`0`0`0com/example/OtherharmlessMethod"))
    [System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $script:jar)
}

AfterAll {
    if ($script:work -and (Test-Path $script:work)) {
        Remove-Item $script:work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Invoke-TcpkJavaDecompile: input handling' {
    It 'throws on a missing archive rather than returning an empty result' {
        { Invoke-TcpkJavaDecompile -Archive (Join-Path $script:work 'nope.jar') -Search 'x' } |
            Should -Throw -ExpectedMessage '*not found*'
    }
}

Describe 'Invoke-TcpkJavaDecompile: fallback when CFR is absent' {
    It 'finds a symbol in a .jar and returns surrounding context' {
        $out = Invoke-TcpkJavaDecompile -Archive $script:jar -Search $script:marker `
            -CfrPath (Join-Path $script:work 'no-such-cfr.jar') -WarningAction SilentlyContinue
        "$out" | Should -Match ([regex]::Escape($script:marker))
        "$out" | Should -Match 'constant-pool context'
    }

    It 'names the class the match came from, so the result is actionable' {
        $out = Invoke-TcpkJavaDecompile -Archive $script:jar -Search $script:marker `
            -CfrPath (Join-Path $script:work 'no-such-cfr.jar') -WarningAction SilentlyContinue
        "$out" | Should -Match 'Db\.class'
    }

    It 'works on a bare .class as well as a .jar' {
        $out = Invoke-TcpkJavaDecompile -Archive $script:classFile -Search $script:marker `
            -CfrPath (Join-Path $script:work 'no-such-cfr.jar') -WarningAction SilentlyContinue
        "$out" | Should -Match ([regex]::Escape($script:marker))
    }

    It 'says plainly that the result is NOT decompiled' {
        $warns = @()
        Invoke-TcpkJavaDecompile -Archive $script:jar -Search $script:marker `
            -CfrPath (Join-Path $script:work 'no-such-cfr.jar') -WarningVariable warns -WarningAction SilentlyContinue | Out-Null
        ($warns -join ' ') | Should -Match 'not decompiled'
    }

    It 'reports a clean miss instead of inventing context' {
        $out = Invoke-TcpkJavaDecompile -Archive $script:jar -Search 'ThisSymbolIsNotPresentAnywhere' `
            -CfrPath (Join-Path $script:work 'no-such-cfr.jar') -WarningAction SilentlyContinue
        "$out" | Should -Match 'no match'
    }
}

Describe 'Invoke-TcpkJavaDecompile: the two missing-tool cases are distinguishable' {
    # This is the whole point of the warning split. Invoke-TcpkDecompile once told operators
    # who HAD ilspycmd installed to go and install it, because both failures produced the
    # same message. These assertions pin the two apart.

    It 'says cfr.jar is missing when java exists but CFR does not' -Skip:(-not $script:hasJava) {
        $warns = @()
        Invoke-TcpkJavaDecompile -Archive $script:jar -Search $script:marker `
            -CfrPath (Join-Path $script:work 'no-such-cfr.jar') -WarningVariable warns -WarningAction SilentlyContinue | Out-Null
        ($warns -join ' ') | Should -Match 'cfr\.jar was not'
    }

    It 'says the JRE is missing when CFR exists but java does not' {
        $fakeCfr = Join-Path $script:work 'cfr.jar'
        'not really cfr' | Set-Content -LiteralPath $fakeCfr
        $warns = @()
        Invoke-TcpkJavaDecompile -Archive $script:jar -Search $script:marker `
            -CfrPath $fakeCfr -JavaPath (Join-Path $script:work 'no-such-java.exe') `
            -WarningVariable warns -WarningAction SilentlyContinue | Out-Null
        ($warns -join ' ') | Should -Match 'no JRE is available'
    }
}

Describe 'Get-TcpkJavaConstantPoolContext / Add-TcpkClassPoolContext' {
    It 'returns nothing for a symbol that is absent' {
        InModuleScope TCPK -Parameters @{ jar = $script:jar } {
            param($jar)
            $r = Get-TcpkJavaConstantPoolContext -Archive $jar -Search 'AbsentSymbolXyz'
            "$r" | Should -Match 'no match'
        }
    }

    It 'reports false for a class whose bytes lack the needle, true when present' {
        InModuleScope TCPK {
            $sb = New-Object Text.StringBuilder
            $bytes = [Text.Encoding]::UTF8.GetBytes('nothing interesting here')
            Add-TcpkClassPoolContext -Bytes $bytes -Name 'A.class' -Needle 'zzz' -Sb $sb | Should -BeFalse
            $sb.Length | Should -Be 0

            $bytes2 = [Text.Encoding]::UTF8.GetBytes('prefix NEEDLE suffix')
            Add-TcpkClassPoolContext -Bytes $bytes2 -Name 'B.class' -Needle 'NEEDLE' -Sb $sb | Should -BeTrue
            $sb.ToString() | Should -Match 'B\.class'
        }
    }

    It 'strips non-printable bytes so the output is safe to render in a console' {
        InModuleScope TCPK {
            $sb = New-Object Text.StringBuilder
            $bytes = [byte[]]@(0,1,2) + [Text.Encoding]::UTF8.GetBytes('FINDME') + [byte[]]@(0,7,27)
            Add-TcpkClassPoolContext -Bytes $bytes -Name 'C.class' -Needle 'FINDME' -Sb $sb | Should -BeTrue
            $out = $sb.ToString()
            $out | Should -Match 'FINDME'
            # every control char replaced with '.', so no bell/escape reaches the terminal
            ($out -match "`e") | Should -BeFalse
            ($out -match "`a") | Should -BeFalse
        }
    }
}
