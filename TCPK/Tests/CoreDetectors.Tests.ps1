#requires -Version 5.1
#
# Behavioral tests for core detectors and engines that previously had none. These are the
# first four the audit flagged as untested-with-a-real-input: the SQL-injection source scan,
# the Luhn PAN gate, the delta-minimization engine, and the Mono.Cecil load guard (so the
# large IL-taint suite cannot pass green purely by skipping when Cecil fails to load).

BeforeAll {
    $manifest = Join-Path (Split-Path $PSScriptRoot -Parent) 'TCPK.psd1'
    Import-Module (Resolve-Path $manifest) -Force -ErrorAction Stop
}

Describe 'Test-TcpkSqlInjection (source scan)' {

    BeforeEach {
        $script:dir = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-sqli-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:dir -Force | Out-Null
    }
    AfterEach {
        if ($script:dir -and (Test-Path -LiteralPath $script:dir)) {
            Remove-Item -LiteralPath $script:dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'flags string-concatenated SQL reaching a command object (sqli.source-concat)' {
        # The reaching-definition form the detector exists to catch: a SQL-shaped concat
        # assigned to a local, then that local handed to a command object within the window.
        $cs = @(
            'public void Load(string userId) {'
            '    string sql = "SELECT * FROM Users WHERE id = ' + "'" + '" + userId + "' + "'" + '";'
            '    SqlCommand cmd = new SqlCommand(sql, conn);'
            '    cmd.ExecuteReader();'
            '}'
        ) -join "`r`n"
        Set-Content -LiteralPath (Join-Path $script:dir 'Repo.cs') -Value $cs -Encoding UTF8

        $f = @(Test-TcpkSqlInjection -Path $script:dir)
        ($f | Where-Object { $_.RuleId -eq 'sqli.source-concat' }) | Should -Not -BeNullOrEmpty
    }

    It 'flags dynamic SQL in a .sql file (sqli.dynamic-sql-file)' {
        Set-Content -LiteralPath (Join-Path $script:dir 'proc.sql') `
            -Value "DECLARE @sql nvarchar(max); SET @sql = 'SELECT 1'; EXEC(@sql);" -Encoding UTF8

        $f = @(Test-TcpkSqlInjection -Path $script:dir)
        ($f | Where-Object { $_.RuleId -eq 'sqli.dynamic-sql-file' }) | Should -Not -BeNullOrEmpty
    }

    It 'does NOT flag a parameterized query (no concatenation)' {
        $cs = @(
            'public void Load(string userId) {'
            '    SqlCommand cmd = new SqlCommand("SELECT * FROM Users WHERE id = @id", conn);'
            '    cmd.Parameters.AddWithValue("@id", userId);'
            '    cmd.ExecuteReader();'
            '}'
        ) -join "`r`n"
        Set-Content -LiteralPath (Join-Path $script:dir 'Safe.cs') -Value $cs -Encoding UTF8

        $f = @(Test-TcpkSqlInjection -Path $script:dir)
        ($f | Where-Object { $_.RuleId -like 'sqli.*' }) | Should -BeNullOrEmpty
    }
}

Describe 'Test-TcpkLuhn (PAN gate)' {
    It 'accepts a Luhn-valid 16-digit PAN' {
        (& (Get-Module TCPK) { Test-TcpkLuhn -Digits '4111111111111111' }) | Should -BeTrue
    }
    It 'rejects a number that fails the Luhn check' {
        (& (Get-Module TCPK) { Test-TcpkLuhn -Digits '4111111111111112' }) | Should -BeFalse
    }
    It 'rejects a run shorter than 13 digits' {
        (& (Get-Module TCPK) { Test-TcpkLuhn -Digits '41111' }) | Should -BeFalse
    }
    It 'rejects a run longer than 19 digits' {
        (& (Get-Module TCPK) { Test-TcpkLuhn -Digits '41111111111111111111' }) | Should -BeFalse
    }
}

Describe 'Invoke-TcpkDeltaMinimize (ddmin engine)' {
    It 'reduces the input toward the smallest slice the oracle still accepts' {
        $res = & (Get-Module TCPK) {
            $bytes = [byte[]](1,2,3,4,0x5A,6,7,8,9,10)
            # Oracle: the candidate still "reproduces" while it contains the marker 0x5A.
            $test = { param($cand) [bool]($cand -contains 0x5A) }
            Invoke-TcpkDeltaMinimize -Bytes $bytes -Test $test -MaxTests 200
        }
        $res.Reduced            | Should -BeTrue
        $res.Bytes.Length       | Should -BeLessThan 10
        ($res.Bytes -contains 0x5A) | Should -BeTrue
    }
    It 'does not reduce below MinLength and reports no reduction when nothing can be removed' {
        $res = & (Get-Module TCPK) {
            $bytes = [byte[]](0x5A)
            $test = { param($cand) [bool]($cand -contains 0x5A) }
            Invoke-TcpkDeltaMinimize -Bytes $bytes -Test $test
        }
        $res.Bytes.Length | Should -Be 1
        $res.Reduced      | Should -BeFalse
    }
}

Describe 'Mono.Cecil load guard' {
    It 'Test-TcpkCecilAvailable is true on Windows (the IL suite is not silently skipping)' {
        # The 15 IL-taint test files Set-ItResult -Skipped when Cecil is unavailable, which on
        # Windows would hide a load failure of the shipped Mono.Cecil.dll and turn the whole IL
        # suite green by skip. Assert availability on Windows, where it must work. Skip only off
        # Windows, where the .NET Framework Cecil DLL legitimately does not load.
        if ([System.Environment]::OSVersion.Platform -ne 'Win32NT') {
            Set-ItResult -Skipped -Because 'Mono.Cecil (net framework DLL) only loads on Windows PowerShell'
            return
        }
        (& (Get-Module TCPK) { Test-TcpkCecilAvailable }) | Should -BeTrue
    }
}
