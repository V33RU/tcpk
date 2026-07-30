#requires -Version 5.1
# Pester 5: GhostTree/GhostBranch handling. TCPK's safe walker must not follow a directory
# junction loop (so a payload behind the loop is still found and the scan cannot hang), and
# Test-TcpkReparseLoops must flag the loop. Verified on Linux with real symlink loops (the
# ReparsePoint attribute + link target are the same primitives Windows junctions use).

# -Skip is evaluated at DISCOVERY time, so probe symlink capability here (Linux always;
# Windows needs Developer Mode or admin for symlinks -- real junctions do not, but New-Item
# SymbolicLink is the portable primitive, so the suite self-skips where it is unavailable).
BeforeDiscovery {
    $script:hasLink = $false
    $t = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-linktgt-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
    $p = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-linkprobe-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
    New-Item -ItemType Directory -Path $t -Force | Out-Null
    try { New-Item -ItemType SymbolicLink -Path $p -Target $t -ErrorAction Stop | Out-Null; $script:hasLink = $true } catch {}
    Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $t -Recurse -Force -ErrorAction SilentlyContinue
}

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:root = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-ghost-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path (Join-Path $script:root 'app/lib') -Force | Out-Null
    try {
        New-Item -ItemType SymbolicLink -Path (Join-Path $script:root 'app/loop') -Target (Join-Path $script:root 'app') -ErrorAction Stop | Out-Null
        New-Item -ItemType SymbolicLink -Path (Join-Path $script:root 'app/normlink') -Target (Join-Path $script:root 'app/lib') -ErrorAction Stop | Out-Null
    } catch {}
    Set-Content -LiteralPath (Join-Path $script:root 'app/payload.exe') -Value 'MZ'
}
AfterAll { if ($script:root) { Remove-Item -LiteralPath $script:root -Recurse -Force -ErrorAction SilentlyContinue } }

Describe 'GhostTree-safe scanning' -Skip:(-not $script:hasLink) {
    It 'Get-TcpkChildItemSafe finds the payload and does not follow the junction loop' {
        InModuleScope TCPK -Parameters @{ p = (Join-Path $script:root 'app') } {
            param($p)
            $files = @(Get-TcpkChildItemSafe -Path $p -File)
            ($files | Where-Object { $_.Name -eq 'payload.exe' }) | Should -Not -BeNullOrEmpty
            # the loop would produce hundreds of nested 'loop/loop/...' entries if followed
            $files.Count | Should -BeLessThan 50
        }
    }
    It 'Get-TcpkReparseInfo classifies the loop vs the non-recursive link' {
        InModuleScope TCPK -Parameters @{ p = (Join-Path $script:root 'app') } {
            param($p)
            $info = @(Get-TcpkReparseInfo -Path $p)
            ($info | Where-Object { $_.IsLoop }) | Should -Not -BeNullOrEmpty
            ($info | Where-Object { -not $_.IsLoop }) | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Test-TcpkReparseLoops' -Skip:(-not $script:hasLink) {
    It 'flags the recursive junction HIGH and the normal one INFO' {
        $f = @(Test-TcpkReparseLoops -Path (Join-Path $script:root 'app'))
        $rec = $f | Where-Object RuleId -eq 'reparse.recursive-junction'
        $rec | Should -Not -BeNullOrEmpty
        $rec.Severity | Should -Be 'HIGH'
        ($f | Where-Object RuleId -eq 'reparse.junction') | Should -Not -BeNullOrEmpty
    }
    It 'emits nothing recursive for a clean tree' {
        $clean = Join-Path $script:root 'clean'
        New-Item -ItemType Directory -Path $clean -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $clean 'a.txt') -Value 'x'
        (@(Test-TcpkReparseLoops -Path $clean) | Where-Object RuleId -eq 'reparse.recursive-junction') | Should -BeNullOrEmpty
    }
}
