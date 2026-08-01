#requires -Version 5.1
# Pester 5: npm dependency-inventory recovery beyond app.asar.
#
# WHY. The asar reader only finds package.json files INSIDE the archive. Native modules
# are always unpacked to app.asar.unpacked (a .node cannot load from an archive), and a
# webpack/esbuild build inlines every dependency and ships no package.json at all. Before
# this, both cases produced "N packages, 0 vulnerabilities" with no warning -- a scan that
# saw almost nothing rendered identically to a genuinely clean one.
#
# These tests are offline: the disk walkers, the lockfile parsers and the formatter take
# no network. Only Get-TcpkAsarNpmAudit does I/O, and its OSV/registry calls are mocked.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:fx = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-npminv-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx | Out-Null

    function script:New-Pkg {
        param([string]$Root, [string]$RelDir, [string]$Name, [string]$Version)
        $d = Join-Path $Root $RelDir
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        (ConvertTo-Json @{ name = $Name; version = $Version }) |
            Set-Content -LiteralPath (Join-Path $d 'package.json') -Encoding UTF8
    }
}
AfterAll {
    if ($script:fx -and (Test-Path $script:fx)) { Remove-Item $script:fx -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Get-TcpkLooseNpmComponents (node_modules on disk)' {

    It 'finds packages in app.asar.unpacked, which the asar reader cannot see' {
        $root = Join-Path $script:fx 'unpacked'; New-Item -ItemType Directory -Path $root -Force | Out-Null
        New-Pkg $root 'resources\app.asar.unpacked\node_modules\ffi-napi' 'ffi-napi' '2.4.7'
        $r = @(InModuleScope TCPK -Parameters @{ d = $root } { param($d) Get-TcpkLooseNpmComponents -Dir $d })
        $r.Count | Should -Be 1
        $r[0].Name | Should -Be 'ffi-napi'
        $r[0].Version | Should -Be '2.4.7'
        $r[0].Source | Should -Be 'unpacked'
        $r[0].Verified | Should -BeTrue
    }

    It 'labels a plain node_modules tree differently from an unpacked one' {
        $root = Join-Path $script:fx 'plain'; New-Item -ItemType Directory -Path $root -Force | Out-Null
        New-Pkg $root 'resources\node_modules\lodash' 'lodash' '4.17.20'
        $r = @(InModuleScope TCPK -Parameters @{ d = $root } { param($d) Get-TcpkLooseNpmComponents -Dir $d })
        $r[0].Source | Should -Be 'node_modules'
    }

    It 'resolves scoped @scope/name packages one level deeper' {
        $root = Join-Path $script:fx 'scoped'; New-Item -ItemType Directory -Path $root -Force | Out-Null
        New-Pkg $root 'node_modules\@serialport\bindings' '@serialport/bindings' '9.2.3'
        $r = @(InModuleScope TCPK -Parameters @{ d = $root } { param($d) Get-TcpkLooseNpmComponents -Dir $d })
        $r.Count | Should -Be 1
        $r[0].Name | Should -Be '@serialport/bindings'
    }

    It 'finds nested (transitive) node_modules without a second recursive pass' {
        $root = Join-Path $script:fx 'nested'; New-Item -ItemType Directory -Path $root -Force | Out-Null
        New-Pkg $root 'node_modules\a' 'a' '1.0.0'
        New-Pkg $root 'node_modules\a\node_modules\b' 'b' '2.0.0'
        $r = @(InModuleScope TCPK -Parameters @{ d = $root } { param($d) Get-TcpkLooseNpmComponents -Dir $d })
        @($r | Select-Object -ExpandProperty Name | Sort-Object) | Should -Be @('a', 'b')
    }

    It 'skips .bin and any package.json with no name or a non-numeric version' {
        $root = Join-Path $script:fx 'junk'; New-Item -ItemType Directory -Path $root -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $root 'node_modules\.bin') -Force | Out-Null
        '{}' | Set-Content -LiteralPath (Join-Path $root 'node_modules\.bin\package.json') -Encoding UTF8
        New-Pkg $root 'node_modules\nover' 'nover' 'latest'
        New-Pkg $root 'node_modules\good' 'good' '1.0.0'
        $r = @(InModuleScope TCPK -Parameters @{ d = $root } { param($d) Get-TcpkLooseNpmComponents -Dir $d })
        @($r | Select-Object -ExpandProperty Name) | Should -Be @('good')
    }

    It 'honours MaxPackages' {
        $root = Join-Path $script:fx 'cap'; New-Item -ItemType Directory -Path $root -Force | Out-Null
        1..8 | ForEach-Object { New-Pkg $root "node_modules\p$_" "p$_" '1.0.0' }
        $r = @(InModuleScope TCPK -Parameters @{ d = $root } { param($d) Get-TcpkLooseNpmComponents -Dir $d -MaxPackages 3 })
        $r.Count | Should -BeLessOrEqual 3
    }
}

Describe 'Get-TcpkLockfileNpmComponents' {

    It 'parses package-lock v3 despite the empty-string root key that ConvertFrom-Json rejects' {
        # REGRESSION. Every npm 7+ lockfile keys its root project with "". On PowerShell 5.1
        # ConvertFrom-Json builds a PSCustomObject and PSNoteProperty refuses an empty name,
        # so the whole file threw and was silently dropped -- the lockfile fallback was inert
        # for the dominant lockfile format, which is the exact case it exists to cover.
        # -AsHashtable would sidestep it but is PowerShell 6+. Keep the "" key in this fixture.
        $root = Join-Path $script:fx 'lockv3'; New-Item -ItemType Directory -Path $root -Force | Out-Null
        @'
{ "lockfileVersion": 3, "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "node_modules/minimist": { "version": "1.2.5" },
    "node_modules/@babel/core": { "version": "7.12.3" },
    "node_modules/a/node_modules/nested": { "version": "3.1.0" } } }
'@ | Set-Content -LiteralPath (Join-Path $root 'package-lock.json') -Encoding UTF8
        $r = @(InModuleScope TCPK -Parameters @{ d = $root } { param($d) Get-TcpkLockfileNpmComponents -Dir $d })
        $r.Count | Should -BeGreaterThan 0 -Because 'an empty root key must not kill the whole parse'
        $names = @($r | Select-Object -ExpandProperty Name | Sort-Object)
        $names | Should -Contain 'minimist'
        $names | Should -Contain '@babel/core'
        $names | Should -Contain 'nested'
        # The root project is the app, not a dependency, under either spelling.
        $names | Should -Not -Contain 'app'
        $names | Should -Not -Contain '__tcpk_root__'
    }

    It 'unwraps the npm-alias version form instead of dropping the package' {
        $root = Join-Path $script:fx 'alias'; New-Item -ItemType Directory -Path $root -Force | Out-Null
        '{ "lockfileVersion": 1, "dependencies": { "my-alias": { "version": "npm:real-pkg@2.3.4" } } }' |
            Set-Content -LiteralPath (Join-Path $root 'package-lock.json') -Encoding UTF8
        $r = @(InModuleScope TCPK -Parameters @{ d = $root } { param($d) Get-TcpkLockfileNpmComponents -Dir $d })
        # The installed code is real-pkg. Querying OSV for 'my-alias' would ask about a
        # package that does not exist on the registry.
        $r.Count | Should -Be 1
        $r[0].Name    | Should -Be 'real-pkg'
        $r[0].Version | Should -Be '2.3.4'
    }

    It 'parses package-lock v1 (nested dependencies) including transitives' {
        $root = Join-Path $script:fx 'lockv1'; New-Item -ItemType Directory -Path $root -Force | Out-Null
        @'
{ "lockfileVersion": 1, "dependencies": {
    "tar": { "version": "4.4.10", "dependencies": {
        "minipass": { "version": "2.3.5" } } } } }
'@ | Set-Content -LiteralPath (Join-Path $root 'package-lock.json') -Encoding UTF8
        $r = @(InModuleScope TCPK -Parameters @{ d = $root } { param($d) Get-TcpkLockfileNpmComponents -Dir $d })
        @($r | Select-Object -ExpandProperty Name | Sort-Object) | Should -Be @('minipass', 'tar')
    }

    It 'parses yarn v1 and berry, and strips the range without eating an @scope' {
        $root = Join-Path $script:fx 'yarn'; New-Item -ItemType Directory -Path $root -Force | Out-Null
        @'
# yarn lockfile v1
lodash@^4.17.15, lodash@^4.17.19:
  version "4.17.21"

"@types/node@npm:^14.0.0":
  version: 14.14.31
'@ | Set-Content -LiteralPath (Join-Path $root 'yarn.lock') -Encoding UTF8
        $r = @(InModuleScope TCPK -Parameters @{ d = $root } { param($d) Get-TcpkLockfileNpmComponents -Dir $d })
        $map = @{}; foreach ($p in $r) { $map[$p.Name] = $p.Version }
        $map['lodash'] | Should -Be '4.17.21'
        $map['@types/node'] | Should -Be '14.14.31'
    }

    It 'does not report the yarn berry workspace root as a shipped dependency' {
        # REGRESSION. Every berry lockfile carries a workspace entry for the project itself
        # at the sentinel version 0.0.0-use.local. Emitting it invents a package that was
        # never published, and OSV would be queried for a name that does not exist.
        $root = Join-Path $script:fx 'berryws'; New-Item -ItemType Directory -Path $root -Force | Out-Null
        @'
__metadata:
  version: 8
  cacheKey: 10

"my-electron-app@workspace:.":
  version: 0.0.0-use.local
  resolution: "my-electron-app@workspace:."

"strip-ansi@npm:6.0.1":
  version: 6.0.1
  resolution: "strip-ansi@npm:6.0.1"
'@ | Set-Content -LiteralPath (Join-Path $root 'yarn.lock') -Encoding UTF8
        $r = @(InModuleScope TCPK -Parameters @{ d = $root } { param($d) Get-TcpkLockfileNpmComponents -Dir $d })
        $names = @($r | Select-Object -ExpandProperty Name)
        $names | Should -Not -Contain 'my-electron-app'
        $names | Should -Not -Contain '__metadata'
        $names | Should -Contain 'strip-ansi'
    }

    It 'takes the real name from the resolution line for a berry alias or patch entry' {
        # REGRESSION. An alias names one package in the header and a different one in the
        # resolution. Deriving from the header both invented a package and lost the real one.
        $root = Join-Path $script:fx 'berryalias'; New-Item -ItemType Directory -Path $root -Force | Out-Null
        @'
"my-alias@npm:strip-ansi@^6.0.0":
  version: 6.0.1
  resolution: "strip-ansi@npm:6.0.1"
'@ | Set-Content -LiteralPath (Join-Path $root 'yarn.lock') -Encoding UTF8
        $r = @(InModuleScope TCPK -Parameters @{ d = $root } { param($d) Get-TcpkLockfileNpmComponents -Dir $d })
        @($r | Select-Object -ExpandProperty Name) | Should -Contain 'strip-ansi'
        @($r | Select-Object -ExpandProperty Name) | Should -Not -Contain 'my-alias'
    }

    It 'marks every lockfile package unverified, because a lockfile is a declaration' {
        $root = Join-Path $script:fx 'lockunver'; New-Item -ItemType Directory -Path $root -Force | Out-Null
        '{ "lockfileVersion": 3, "packages": { "node_modules/x": { "version": "1.0.0" } } }' |
            Set-Content -LiteralPath (Join-Path $root 'package-lock.json') -Encoding UTF8
        $r = @(InModuleScope TCPK -Parameters @{ d = $root } { param($d) Get-TcpkLockfileNpmComponents -Dir $d })
        $r[0].Verified | Should -BeFalse
        $r[0].Source   | Should -Be 'lockfile'
    }
}

Describe 'Format-TcpkNpmAuditReport blind-spot rendering' {

    It 'puts the incomplete-inventory warning ABOVE the counts, not as a footnote' {
        $r = [ordered]@{
            packages = 3; uniqueNames = 3; vulns = @(); deprecated = @()
            deprecatedChecked = 3; deprecatedCapped = $false; unverified = 0
            blindspot = 'Dependency inventory is INCOMPLETE. Only 3 package(s) were recoverable.'
        }
        $txt = InModuleScope TCPK -Parameters @{ x = $r } { param($x) Format-TcpkNpmAuditReport -Result $x }
        $txt | Should -Match 'INCOMPLETE INVENTORY'
        $txt | Should -Match 'NOT A CLEAN BILL OF HEALTH'
        $warnAt = $txt.IndexOf('INCOMPLETE INVENTORY')
        $cntAt  = $txt.IndexOf('bundled npm packages:')
        $warnAt | Should -BeLessThan $cntAt
    }

    It 'stays quiet when the inventory is believable' {
        $r = [ordered]@{
            packages = 412; uniqueNames = 380; vulns = @(); deprecated = @()
            deprecatedChecked = 60; deprecatedCapped = $true; unverified = 0; blindspot = ''
        }
        $txt = InModuleScope TCPK -Parameters @{ x = $r } { param($x) Format-TcpkNpmAuditReport -Result $x }
        $txt | Should -Not -Match 'INCOMPLETE INVENTORY'
    }

    It 'names the sources and flags lockfile-derived entries as unconfirmed' {
        $r = [ordered]@{
            packages = 5; uniqueNames = 5; vulns = @(); deprecated = @()
            deprecatedChecked = 5; deprecatedCapped = $false; blindspot = ''
            unverified = 2; sources = ([ordered]@{ unpacked = 3; lockfile = 2 })
        }
        $txt = InModuleScope TCPK -Parameters @{ x = $r } { param($x) Format-TcpkNpmAuditReport -Result $x }
        $txt | Should -Match 'app\.asar\.unpacked'
        $txt | Should -Match 'lockfile'
        $txt | Should -Match 'not a confirmed shipped exposure'
    }

    It 'marks a lockfile-declared CVE on its own line, not only in a footnote' {
        # REGRESSION. A CVE in a devDependency that never shipped rendered identically to one
        # in a shipped file, so a reader scanning the list would file it as confirmed.
        $r = [ordered]@{
            packages = 2; uniqueNames = 2; deprecated = @(); deprecatedChecked = 0
            deprecatedCapped = $false; unverified = 1; blindspot = ''
            vulns = @(
                [pscustomobject]@{ Severity = 'HIGH'; Package = 'shipped'; ShippedVersion = '1.0.0'; Cve = 'CVE-1'; Title = 't1'; FixedVersion = ''; Verified = $true }
                [pscustomobject]@{ Severity = 'HIGH'; Package = 'declared'; ShippedVersion = '2.0.0'; Cve = 'CVE-2'; Title = 't2'; FixedVersion = ''; Verified = $false }
            )
        }
        $txt = InModuleScope TCPK -Parameters @{ x = $r } { param($x) Format-TcpkNpmAuditReport -Result $x }
        ($txt -split "`n" | Where-Object { $_ -match 'CVE-2' }) -join '' | Should -Match 'LOCKFILE-DECLARED'
        ($txt -split "`n" | Where-Object { $_ -match 'CVE-1' }) -join '' | Should -Not -Match 'LOCKFILE-DECLARED'
        $txt | Should -Match '1 are lockfile declarations'
    }

    It 'reports a capped enumeration as a floor, never as an exact total' {
        $r = [ordered]@{
            packages = 4000; uniqueNames = 3900; vulns = @(); deprecated = @()
            deprecatedChecked = 60; deprecatedCapped = $true; unverified = 0; blindspot = ''
            inventoryCapped = $true
        }
        $txt = InModuleScope TCPK -Parameters @{ x = $r } { param($x) Format-TcpkNpmAuditReport -Result $x }
        $txt | Should -Match 'AT LEAST 4000'
        $txt | Should -Match 'floor, not a total'
    }

    It 'still renders when sources and blindspot are absent (older result shape)' {
        $r = [ordered]@{ packages = 2; uniqueNames = 2; vulns = @(); deprecated = @(); deprecatedChecked = 2; deprecatedCapped = $false }
        $txt = InModuleScope TCPK -Parameters @{ x = $r } { param($x) Format-TcpkNpmAuditReport -Result $x }
        $txt | Should -Match 'bundled npm packages: 2'
    }
}

Describe 'Get-TcpkAsarNpmAudit merges sources (mocked network)' {

    It 'includes unpacked node_modules that the asar reader missed' {
        $root = Join-Path $script:fx 'merge'; New-Item -ItemType Directory -Path $root -Force | Out-Null
        New-Pkg $root 'app.asar.unpacked\node_modules\ffi-napi' 'ffi-napi' '2.4.7'
        $res = InModuleScope TCPK -Parameters @{ d = $root } {
            param($d)
            Mock Get-TcpkAsarNpmComponents { @() }
            Mock Get-TcpkOsvMatches { @() }
            Mock Get-TcpkNpmDeprecation { $null }
            Get-TcpkAsarNpmAudit -Path $d
        }
        $res.packages | Should -Be 1
        $res.sources['unpacked'] | Should -Be 1
    }

    It 'does not reach for a lockfile when the real-file inventory is already large' {
        $root = Join-Path $script:fx 'nolock'; New-Item -ItemType Directory -Path $root -Force | Out-Null
        '{ "lockfileVersion": 3, "packages": { "node_modules/devonly": { "version": "9.9.9" } } }' |
            Set-Content -LiteralPath (Join-Path $root 'package-lock.json') -Encoding UTF8
        $res = InModuleScope TCPK -Parameters @{ d = $root } {
            param($d)
            Mock Get-TcpkAsarNpmComponents {
                1..25 | ForEach-Object { [pscustomobject]@{ Name = "p$_"; Version = '1.0.0'; File = 'app.asar'; Source = 'asar'; Verified = $true } }
            }
            Mock Get-TcpkLooseNpmComponents { @() }
            Mock Get-TcpkOsvMatches { @() }
            Mock Get-TcpkNpmDeprecation { $null }
            Get-TcpkAsarNpmAudit -Path $d -SkipDeprecated
        }
        $res.lockfileUsed | Should -BeFalse
        @($res.vulns).Count | Should -Be 0
        $res.unverified | Should -Be 0
    }

    It 'a verified package wins over the same name+version from a lockfile' {
        $root = Join-Path $script:fx 'dedup'; New-Item -ItemType Directory -Path $root -Force | Out-Null
        New-Pkg $root 'node_modules\dup' 'dup' '1.0.0'
        '{ "lockfileVersion": 3, "packages": { "node_modules/dup": { "version": "1.0.0" } } }' |
            Set-Content -LiteralPath (Join-Path $root 'package-lock.json') -Encoding UTF8
        $res = InModuleScope TCPK -Parameters @{ d = $root } {
            param($d)
            Mock Get-TcpkAsarNpmComponents { @() }
            Mock Get-TcpkOsvMatches { @() }
            Mock Get-TcpkNpmDeprecation { $null }
            Get-TcpkAsarNpmAudit -Path $d -SkipDeprecated
        }
        $res.packages   | Should -Be 1
        $res.unverified | Should -Be 0
    }
}
