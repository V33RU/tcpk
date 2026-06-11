#requires -Version 5.1
# Invoke-TcpkSweep: audit many install locations in one call (explicit -Target list
# and/or -AppName auto-discovery), then write a merged summary.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-sweep-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null

    # discovery root: two matching dirs + one that must NOT match
    $script:droot = Join-Path $script:work 'roots'
    New-Item -ItemType Directory -Force -Path `
        (Join-Path $script:droot 'acmeapp-desktop'),
        (Join-Path $script:droot 'acmeapp-updater'),
        (Join-Path $script:droot 'unrelated-tool') | Out-Null

    # two tiny audit targets
    $script:t1 = Join-Path $script:work 't1'
    $script:t2 = Join-Path $script:work 't2'
    New-Item -ItemType Directory -Force -Path $script:t1, $script:t2 | Out-Null
    'x' | Set-Content (Join-Path $script:t1 'readme.txt')
    'y' | Set-Content (Join-Path $script:t2 'readme.txt')

    $script:out = Join-Path $script:work 'out'
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'Get-TcpkInstallLocations (discovery)' {
    It 'finds only directories matching the app name' {
        $loc = & (Get-Module TCPK) { param($r) Get-TcpkInstallLocations -AppName 'acmeapp' -Root @($r) } $script:droot
        @($loc).Count | Should -Be 2
        ($loc | ForEach-Object { Split-Path $_ -Leaf }) | Should -Not -Contain 'unrelated-tool'
    }
    It 'returns empty for a name that matches nothing' {
        $loc = & (Get-Module TCPK) { param($r) Get-TcpkInstallLocations -AppName 'zzznope' -Root @($r) } $script:droot
        @($loc).Count | Should -Be 0
    }
}

Describe 'Invoke-TcpkSweep (multi-target audit + merge)' {
    BeforeAll {
        $script:res = @(Invoke-TcpkSweep -Target @($script:t1, $script:t2) -OutDir $script:out -Acknowledge 6>$null 3>$null)
    }

    It 'audits each target into its own subfolder' {
        @(Get-ChildItem -LiteralPath $script:out -Directory).Count | Should -Be 2
    }
    It 'writes the merged sweep outputs' {
        Test-Path (Join-Path $script:out 'sweep-summary.json')  | Should -BeTrue
        Test-Path (Join-Path $script:out 'sweep-findings.json') | Should -BeTrue
        Test-Path (Join-Path $script:out 'sweep-summary.html')  | Should -BeTrue
    }
    It 'records both targets in the summary' {
        $sum = Get-Content (Join-Path $script:out 'sweep-summary.json') -Raw | ConvertFrom-Json
        $sum.targetCount | Should -Be 2
        @($sum.perTarget).Count | Should -Be 2
    }
    It 'returns the merged finding set' {
        $script:res | Should -Not -BeNullOrEmpty
    }
    It 'throws when no targets resolve' {
        { Invoke-TcpkSweep -Target @('Z:\does\not\exist\nope') -OutDir $script:out -Acknowledge 3>$null } |
            Should -Throw
    }
}
