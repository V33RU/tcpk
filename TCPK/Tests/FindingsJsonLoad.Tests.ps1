#requires -Version 5.1
# Pester 5: loading findings.json back into objects.
#
# WHY. Windows PowerShell 5.1's ConvertFrom-Json writes a deserialized array to the
# pipeline as ONE object instead of enumerating it. So
#
#     $raw = @(Get-Content $p -Raw | ConvertFrom-Json)
#
# produces a NESTED array -- one element, which is the real array. Piping that to
# ForEach-Object runs a single iteration with $_ bound to the whole array, and
# $_.Severity member-enumerates into "MEDIUM MEDIUM INFO INFO HIGH ...". Downstream
# that hits New-TcpkFinding's ValidateSet and fails with
# "Cannot validate argument on parameter 'Severity'".
#
# Three call sites shipped that exact shape -- both GUIs' attack-path graph and the
# elevated-relaunch return in Invoke-TcpkAudit -- so the Graph tab was broken in both
# UIs. These tests pin the flat-load contract so it cannot regress.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:fx = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-fjson-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx | Out-Null

    function script:Write-Findings {
        param([string]$Name, [string]$Json)
        $p = Join-Path $script:fx $Name
        Set-Content -LiteralPath $p -Value $Json -Encoding UTF8
        return $p
    }
}
AfterAll {
    if ($script:fx -and (Test-Path $script:fx)) { Remove-Item $script:fx -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Read-TcpkFindingsJson returns a FLAT array' {

    It 'returns one element per finding, not a single nested array' {
        $p = Write-Findings 'multi.json' @'
[
 {"Module":"static","RuleId":"a.one","Severity":"MEDIUM","Confidence":"Inferred","Title":"t1","File":"f1"},
 {"Module":"static","RuleId":"a.two","Severity":"INFO","Confidence":"Confirmed","Title":"t2","File":"f2"},
 {"Module":"static","RuleId":"a.three","Severity":"HIGH","Confidence":"Confirmed","Title":"t3","File":"f3"}
]
'@
        $raw = InModuleScope TCPK -Parameters @{ f = $p } { param($f) @(Read-TcpkFindingsJson -Path $f) }
        $raw.Count | Should -Be 3 -Because 'a nested array would report 1'
        # The failing symptom, asserted directly: a nested array member-enumerates.
        "$($raw[0].Severity)" | Should -Be 'MEDIUM'
        "$($raw[0].Severity)" | Should -Not -Match '\s'
    }

    It 'returns a one-element array for a single-finding file' {
        $p = Write-Findings 'single.json' '{"Module":"static","RuleId":"a.one","Severity":"HIGH","Confidence":"Confirmed","Title":"only"}'
        $raw = InModuleScope TCPK -Parameters @{ f = $p } { param($f) @(Read-TcpkFindingsJson -Path $f) }
        $raw.Count | Should -Be 1
        "$($raw[0].RuleId)" | Should -Be 'a.one'
    }

    It 'returns an empty array for a missing or unparseable file' {
        $missing = Join-Path $script:fx 'nope.json'
        (InModuleScope TCPK -Parameters @{ f = $missing } { param($f) @(Read-TcpkFindingsJson -Path $f) }).Count | Should -Be 0
        $bad = Write-Findings 'bad.json' '{ this is not json'
        (InModuleScope TCPK -Parameters @{ f = $bad } { param($f) @(Read-TcpkFindingsJson -Path $f) }).Count | Should -Be 0
    }
}

Describe 'ConvertTo-TcpkFindingObject' {

    It 'rebuilds real TcpkFinding objects with scalar Severity' {
        $p = Write-Findings 'ok.json' @'
[
 {"Module":"static","RuleId":"a.one","Severity":"MEDIUM","Confidence":"Inferred","Title":"t1","File":"f1","Evidence":"e1","Cwe":["CWE-1"]},
 {"Module":"static","RuleId":"a.two","Severity":"HIGH","Confidence":"Confirmed","Title":"t2","File":"f2"}
]
'@
        $objs = InModuleScope TCPK -Parameters @{ f = $p } {
            param($f) @(ConvertTo-TcpkFindingObject -Raw @(Read-TcpkFindingsJson -Path $f))
        }
        $objs.Count | Should -Be 2
        $objs[0].Severity | Should -Be 'MEDIUM'
        $objs[0].File     | Should -Be 'f1'
        $objs[0].Evidence | Should -Be 'e1'
        @($objs[0].Cwe)   | Should -Contain 'CWE-1'
    }

    It 'skips a malformed row instead of taking out the whole set' {
        # One corrupt Severity used to throw and kill the entire graph build.
        $p = Write-Findings 'mixed.json' @'
[
 {"Module":"static","RuleId":"a.one","Severity":"MEDIUM","Confidence":"Inferred","Title":"good"},
 {"Module":"static","RuleId":"a.bad","Severity":"NOT-A-SEVERITY","Confidence":"Inferred","Title":"bad"},
 {"Module":"static","RuleId":"a.two","Severity":"HIGH","Confidence":"Confirmed","Title":"good2"}
]
'@
        $res = InModuleScope TCPK -Parameters @{ f = $p } {
            param($f)
            $raw = @(Read-TcpkFindingsJson -Path $f)
            [pscustomobject]@{ Raw = $raw.Count; Built = @(ConvertTo-TcpkFindingObject -Raw $raw).Count }
        }
        $res.Raw   | Should -Be 3
        $res.Built | Should -Be 2 -Because 'the malformed row is dropped, the good ones survive'
    }

    It 'defaults a missing Confidence rather than failing the row' {
        $p = Write-Findings 'noconf.json' '[{"Module":"static","RuleId":"a.one","Severity":"LOW","Title":"t"}]'
        $objs = InModuleScope TCPK -Parameters @{ f = $p } {
            param($f) @(ConvertTo-TcpkFindingObject -Raw @(Read-TcpkFindingsJson -Path $f))
        }
        $objs.Count | Should -Be 1
    }

    It 'accepts an empty set without throwing' {
        $objs = InModuleScope TCPK { @(ConvertTo-TcpkFindingObject -Raw @()) }
        $objs.Count | Should -Be 0
    }
}

Describe 'A rebuilt finding set feeds Get-TcpkAttackGraph' {
    It 'pipes into the graph without a Severity validation error' {
        $p = Write-Findings 'graph.json' @'
[
 {"Module":"static","RuleId":"dllsearch.phantom-dll","Severity":"HIGH","Confidence":"Inferred","Title":"phantom","File":"C:\\app\\a.exe"},
 {"Module":"os","RuleId":"acl.install-dir-writable","Severity":"HIGH","Confidence":"Confirmed","Title":"writable","File":"C:\\app"}
]
'@
        { InModuleScope TCPK -Parameters @{ f = $p } {
            param($f)
            $objs = @(ConvertTo-TcpkFindingObject -Raw @(Read-TcpkFindingsJson -Path $f))
            $null = @($objs | Get-TcpkAttackGraph)
        } } | Should -Not -Throw
    }
}

Describe 'No call site still uses the nesting-prone shape' {
    It 'nothing wraps a ConvertFrom-Json pipeline in @() for findings.json' {
        $root = Split-Path (Split-Path $PSCommandPath -Parent) -Parent
        $repo = Split-Path $root -Parent
        $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.ps1' -ErrorAction SilentlyContinue)
        $gui = Join-Path $repo 'Start-TCPKGui.ps1'
        if (Test-Path -LiteralPath $gui) { $files += Get-Item -LiteralPath $gui }
        $bad = @()
        foreach ($f in $files) {
            if ($f.FullName -match 'worktrees|\\Tests\\') { continue }
            foreach ($line in (Get-Content -LiteralPath $f.FullName)) {
                # Skip comments: _Finding.ps1 documents the broken shape on purpose.
                if ($line -match '^\s*#') { continue }
                if ($line -match '@\(\s*Get-Content[^)]*\|\s*ConvertFrom-Json\s*\)') {
                    $bad += ("{0}: {1}" -f $f.Name, $line.Trim())
                }
            }
        }
        $bad | Should -BeNullOrEmpty -Because 'PS 5.1 does not enumerate ConvertFrom-Json output; use Read-TcpkFindingsJson'
    }
}
