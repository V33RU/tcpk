#requires -Version 5.1
# Pester 5: TASVS-gap "quick wins" batch - package-manifest CVEs, file-system snapshot
# diff, log stack-trace leakage, TLS hostname-verifier bypass, and the new NoSQLi
# injection-sink rule. (Registry world-readable + %TEMP% sweep are environment-specific
# and exercised by the audit, not unit-asserted here.)

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:fx = Join-Path $env:TEMP ('tcpk-gaps-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx | Out-Null
}
AfterAll {
    if ($script:fx -and (Test-Path $script:fx)) { Remove-Item $script:fx -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'New cmdlets are exported' {
    It '<_> is available' -ForEach @('Save-TcpkFileSnapshot','Compare-TcpkFileSnapshot') {
        Get-Command $_ -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe 'Save/Compare-TcpkFileSnapshot - regshot-style FS diff' {
    It 'detects an executable drop (HIGH) and a content change' {
        $w = Join-Path $script:fx 'watch'; New-Item -ItemType Directory -Path $w | Out-Null
        'orig' | Set-Content -LiteralPath (Join-Path $w 'keep.txt')
        $b = Join-Path $script:fx 'b.json'; $a = Join-Path $script:fx 'a.json'
        Save-TcpkFileSnapshot -OutFile $b -Root $w | Out-Null
        'planted' | Set-Content -LiteralPath (Join-Path $w 'evil.dll')
        'changed' | Set-Content -LiteralPath (Join-Path $w 'keep.txt')
        Save-TcpkFileSnapshot -OutFile $a -Root $w | Out-Null
        $diff = @(Compare-TcpkFileSnapshot -Before $b -After $a)
        $added = $diff | Where-Object RuleId -eq 'fs.diff.added-file'
        $added | Should -Not -BeNullOrEmpty
        ($added | Where-Object { $_.File -match 'evil\.dll' }).Severity | Should -Be 'HIGH'
        ($diff | Where-Object RuleId -eq 'fs.diff.changed-file') | Should -Not -BeNullOrEmpty
    }
}

Describe 'Test-TcpkLogFiles - stack-trace leakage' {
    It 'flags a .NET stack trace in a log file' {
        $ld = Join-Path $script:fx 'logs'; New-Item -ItemType Directory -Path $ld | Out-Null
        @'
System.NullReferenceException: Object reference not set
   at Acme.App.Login(String user) in C:\src\Login.cs:line 42
'@ | Set-Content -LiteralPath (Join-Path $ld 'app.log') -Encoding UTF8
        $f = @(Test-TcpkLogFiles -Path $script:fx) | Where-Object RuleId -eq 'log.stack-trace'
        $f | Should -Not -BeNullOrEmpty
        $f[0].Confidence | Should -Be 'Inferred'
    }
}

Describe 'Test-TcpkTlsBypass - hostname-verifier bypass' {
    It 'flags an all-hosts HostnameVerifier' {
        'class X { HostnameVerifier v = (h,s) -> true; }' | Set-Content -LiteralPath (Join-Path $script:fx 'Net.dll') -Encoding UTF8
        $f = @(Test-TcpkTlsBypass -Path $script:fx) | Where-Object { $_.Title -match 'HostnameVerifier' }
        $f | Should -Not -BeNullOrEmpty
    }
}

Describe 'New injection-sink rule - NoSQLi' {
    It 'Test-TcpkCallsites flags NoSQL query construction as Inferred' {
        'var c = db.GetCollection<BsonDocument>("x"); var f = new BsonDocument();' |
            Set-Content -LiteralPath (Join-Path $script:fx 'Data.dll') -Encoding UTF8
        $f = @(Test-TcpkCallsites -Path $script:fx) | Where-Object RuleId -like '*nosql*'
        $f | Should -Not -BeNullOrEmpty
        $f[0].Confidence | Should -Be 'Inferred'
    }
}
