#requires -Version 5.1
# Pester 5: Go / Rust dependency recovery from statically-linked binaries.
# All fixtures are synthetic and built programmatically. No real-world blobs.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:fx = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-gorust-" + [guid]::NewGuid().ToString('N').Substring(0, 10))
    New-Item -ItemType Directory -Path $script:fx -Force | Out-Null

    # --- synthetic Go binary -------------------------------------------------
    # Layout: filler, then the 14-byte "\xff Go buildinf:" magic, then ptrSize (8)
    # and flags (0x02 = inline strings, Go 1.18+), then the tab/newline delimited
    # build-info text block the Go linker writes.
    $magic = [byte[]]@(0xFF, 0x20, 0x47, 0x6F, 0x20, 0x62, 0x75, 0x69, 0x6C, 0x64, 0x69, 0x6E, 0x66, 0x3A)
    $goText = @(
        "go`t1.21.5"
        "path`tgithub.com/example/app"
        "mod`tgithub.com/example/app`t(devel)`t"
        "dep`tgithub.com/some/lib`tv1.2.3`th1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        "dep`tgolang.org/x/net`tv0.17.0`th1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        "dep`tgopkg.in/yaml.v2`tv2.4.0`th1:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
        "=>`tgithub.com/forked/lib`tv0.9.1`th1:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD="
        "build`t-compiler=gc"
        "build`t-buildmode=exe"
        ""
    ) -join "`n"

    $ms = New-Object System.IO.MemoryStream
    $head = [Text.Encoding]::ASCII.GetBytes("MZ synthetic filler bytes for the Go fixture Go build ID: ZZZZ`n")
    $ms.Write($head, 0, $head.Length)
    $ms.Write($magic, 0, $magic.Length)
    $ms.WriteByte(8)      # ptrSize
    $ms.WriteByte(2)      # flags: inline strings
    $body = [Text.Encoding]::UTF8.GetBytes($goText)
    $ms.Write($body, 0, $body.Length)
    $script:goExe = Join-Path $script:fx 'goapp.exe'
    [IO.File]::WriteAllBytes($script:goExe, $ms.ToArray())
    $ms.Dispose()

    # --- synthetic Go binary with NO magic (header stripped) ------------------
    $script:goNoMagic = Join-Path $script:fx 'gostripped.exe'
    [IO.File]::WriteAllBytes($script:goNoMagic, [Text.Encoding]::UTF8.GetBytes(
        "filler`ndep`tgithub.com/only/lib`tv3.1.4`th1:EEE=`nmore filler`n"))

    # --- synthetic Rust binary ------------------------------------------------
    # Cargo source paths as they appear in panic locations / debug info, in both
    # separator styles, plus the rustc commit marker.
    $script:rustExe = Join-Path $script:fx 'rustapp.exe'
    $rustText = @(
        'thread panicked at /home/build/.cargo/registry/src/index.crates.io-6f17d22bba15001f/serde-1.0.188/src/de/mod.rs'
        'C:\Users\build\.cargo\registry\src\index.crates.io-6f17d22bba15001f\rand_core-0.6.4\src\lib.rs'
        '/home/build/.cargo/registry/src/github.com-1ecc6299db9ec823/windows-sys-0.48.0/src/lib.rs'
        '/rustc/9b00956e56009bab2aa15d7bff10916599e3d6d6/library/std/src/panicking.rs'
        'compiled by rustc 1.72.1 (unrelated banner text)'
        ''
    ) -join "`n"
    [IO.File]::WriteAllBytes($script:rustExe, [Text.Encoding]::UTF8.GetBytes($rustText))

    # --- Rust binary with the crate paths stripped ---------------------------
    $script:rustStripped = Join-Path $script:fx 'ruststripped.exe'
    [IO.File]::WriteAllBytes($script:rustStripped, [Text.Encoding]::UTF8.GetBytes(
        "opaque`n/rustc/9b00956e56009bab2aa15d7bff10916599e3d6d6/library/core/src/option.rs`nopaque`n"))

    # --- plain binary that is neither -----------------------------------------
    $script:plainExe = Join-Path $script:fx 'plain.exe'
    [IO.File]::WriteAllBytes($script:plainExe, [Text.Encoding]::UTF8.GetBytes(
        "MZ plain native binary with no build info and no cargo paths at all.`n"))

    $script:Rid = { param($f, $id) @($f | Where-Object { $_.RuleId -eq $id }) }
}

AfterAll {
    if ($script:fx -and (Test-Path -LiteralPath $script:fx)) {
        Remove-Item -LiteralPath $script:fx -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Find-TcpkGoBuildInfoMagic' {
    It 'locates the "\xff Go buildinf:" magic and reads ptrSize + flags' {
        $m = InModuleScope TCPK -Parameters @{ p = $script:goExe } { param($p) Find-TcpkGoBuildInfoMagic -Path $p }
        $m.Found | Should -BeTrue
        $m.Offset | Should -BeGreaterThan 0
        $m.PtrSize | Should -Be 8
        $m.Flags | Should -Be 2
        $m.InlineStrings | Should -BeTrue
    }

    It 'reports Found=false (not an error) when the magic is absent' {
        $m = InModuleScope TCPK -Parameters @{ p = $script:plainExe } { param($p) Find-TcpkGoBuildInfoMagic -Path $p }
        $m.Found | Should -BeFalse
        $m.Offset | Should -Be -1
        $m.Error | Should -BeNullOrEmpty
    }
}

Describe 'Get-TcpkGoRustBinaryInfo' {
    It 'parses dep / mod / => lines out of the Go build-info text block' {
        $i = InModuleScope TCPK -Parameters @{ p = $script:goExe } { param($p) Get-TcpkGoRustBinaryInfo -Path $p }
        $i.IsGo | Should -BeTrue
        $i.IsRust | Should -BeFalse
        $i.MagicFound | Should -BeTrue
        $i.GoToolchain | Should -Be '1.21.5'
        $i.GoMainPath | Should -Be 'github.com/example/app'
        @($i.GoModules).Count | Should -Be 4
        @($i.GoModules | Where-Object { $_.Name -eq 'github.com/some/lib' }).Version | Should -Be '1.2.3'
        @($i.GoModules | Where-Object { $_.Name -eq 'golang.org/x/net' }).Version | Should -Be '0.17.0'
        @($i.GoModules | Where-Object { $_.Name -eq 'github.com/forked/lib' }).Version | Should -Be '0.9.1'
    }

    It 'counts a non-semver main-module version instead of inventing one' {
        $i = InModuleScope TCPK -Parameters @{ p = $script:goExe } { param($p) Get-TcpkGoRustBinaryInfo -Path $p }
        $i.GoMainVersion | Should -Be '(devel)'
        $i.GoUnusableVersions | Should -BeGreaterOrEqual 1
        @($i.GoModules | Where-Object { $_.Version -eq '(devel)' }).Count | Should -Be 0
    }

    It 'captures build settings' {
        $i = InModuleScope TCPK -Parameters @{ p = $script:goExe } { param($p) Get-TcpkGoRustBinaryInfo -Path $p }
        @($i.GoBuildSettings) | Should -Contain '-compiler=gc'
    }

    It 'still identifies Go from dep lines when the magic is absent' {
        $i = InModuleScope TCPK -Parameters @{ p = $script:goNoMagic } { param($p) Get-TcpkGoRustBinaryInfo -Path $p }
        $i.IsGo | Should -BeTrue
        $i.MagicFound | Should -BeFalse
        @($i.GoModules).Count | Should -Be 1
        @($i.GoModules)[0].Name | Should -Be 'github.com/only/lib'
        @($i.GoModules)[0].Version | Should -Be '3.1.4'
    }

    It 'parses cargo registry paths in both separator styles' {
        $i = InModuleScope TCPK -Parameters @{ p = $script:rustExe } { param($p) Get-TcpkGoRustBinaryInfo -Path $p }
        $i.IsRust | Should -BeTrue
        $i.IsGo | Should -BeFalse
        $names = @($i.RustCrates | ForEach-Object { $_.Name })
        $names | Should -Contain 'serde'
        $names | Should -Contain 'rand_core'
        $names | Should -Contain 'windows-sys'
        @($i.RustCrates | Where-Object { $_.Name -eq 'serde' }).Version | Should -Be '1.0.188'
        @($i.RustCrates | Where-Object { $_.Name -eq 'windows-sys' }).Version | Should -Be '0.48.0'
    }

    It 'recovers the rustc commit hash and release string' {
        $i = InModuleScope TCPK -Parameters @{ p = $script:rustExe } { param($p) Get-TcpkGoRustBinaryInfo -Path $p }
        $i.RustcHash | Should -Be '9b00956e56009bab2aa15d7bff10916599e3d6d6'
        $i.RustcVersion | Should -Be '1.72.1'
    }

    It 'flags a Rust binary with no crate paths as Rust with zero crates' {
        $i = InModuleScope TCPK -Parameters @{ p = $script:rustStripped } { param($p) Get-TcpkGoRustBinaryInfo -Path $p }
        $i.IsRust | Should -BeTrue
        @($i.RustCrates).Count | Should -Be 0
    }
}

Describe 'Test-TcpkGoRustDeps findings' {
    It 'emits a Confirmed Go build-info inventory finding' {
        $f = @(Test-TcpkGoRustDeps -Path $script:goExe)
        $g = & $script:Rid $f 'gorust.go-buildinfo'
        $g.Count | Should -Be 1
        $g[0].Severity | Should -Be 'INFO'
        $g[0].Confidence | Should -Be 'Confirmed'
        $g[0].Title | Should -Match '4 module'
        $g[0].Evidence | Should -Match 'ptrSize=8'
        $g[0].Evidence | Should -Match 'inline strings'
        $g[0].Evidence | Should -Match 'toolchain=go1\.21\.5'
    }

    It 'emits a Rust crate finding that states the recovery is best-effort' {
        $f = @(Test-TcpkGoRustDeps -Path $script:rustExe)
        $r = & $script:Rid $f 'gorust.rust-crates'
        $r.Count | Should -Be 1
        $r[0].Severity | Should -Be 'INFO'
        $r[0].Title | Should -Match 'best-effort'
        $r[0].Description | Should -Match 'BEST-EFFORT AND INCOMPLETE'
        $r[0].Evidence | Should -Match 'rustc 1\.72\.1'
    }

    It 'emits Skipped for a Rust binary whose crate paths were stripped' {
        $f = @(Test-TcpkGoRustDeps -Path $script:rustStripped)
        $s = & $script:Rid $f 'gorust.rust-stripped'
        $s.Count | Should -Be 1
        $s[0].Confidence | Should -Be 'Skipped'
    }

    It 'emits Skipped, never silence, for a file that is neither Go nor Rust' {
        $f = @(Test-TcpkGoRustDeps -Path $script:plainExe)
        $f.Count | Should -BeGreaterThan 0
        $n = & $script:Rid $f 'gorust.not-go-rust'
        $n.Count | Should -Be 1
        $n[0].Confidence | Should -Be 'Skipped'
        $n[0].Severity | Should -Be 'INFO'
    }

    It 'emits a directory-level inventory finding with per-ecosystem counts' {
        $f = @(Test-TcpkGoRustDeps -Path $script:fx)
        $inv = & $script:Rid $f 'gorust.inventory'
        $inv.Count | Should -Be 1
        $inv[0].Confidence | Should -Be 'Confirmed'
        $inv[0].Evidence | Should -Match 'Go=2'
        $inv[0].Evidence | Should -Match 'Rust=2'
        $inv[0].ObsValue | Should -Match '"goModules":5'
        $inv[0].ObsValue | Should -Match '"rustCrates":3'
    }

    It 'declares the size cap instead of skipping a large binary silently' {
        $f = @(Test-TcpkGoRustDeps -Path $script:goExe -MaxFileBytes 8)
        $c = & $script:Rid $f 'gorust.file-too-large'
        $c.Count | Should -Be 1
        $c[0].Confidence | Should -Be 'Skipped'
        $c[0].Evidence | Should -Match 'cap=8 bytes'
        (& $script:Rid $f 'gorust.go-buildinfo').Count | Should -Be 0
    }

    It 'declares the per-binary component cap' {
        $f = @(Test-TcpkGoRustDeps -Path $script:goExe -MaxComponentsPerFile 2)
        $c = & $script:Rid $f 'gorust.components-capped'
        $c.Count | Should -Be 1
        $c[0].Confidence | Should -Be 'Skipped'
    }

    It 'declares the file cap' {
        $f = @(Test-TcpkGoRustDeps -Path $script:fx -MaxFiles 1)
        $c = & $script:Rid $f 'gorust.file-budget'
        $c.Count | Should -Be 1
        $c[0].Evidence | Should -Match 'of 5 candidate binaries'
    }

    It 'emits Skipped when the path cannot be opened' {
        $f = @(Test-TcpkGoRustDeps -Path (Join-Path $script:fx 'does-not-exist-xyz'))
        $f.Count | Should -Be 1
        $f[0].RuleId | Should -Be 'gorust.path-unreadable'
        $f[0].Confidence | Should -Be 'Skipped'
    }
}

Describe 'Test-TcpkGoRustDeps -AsComponent (CVE pipeline shape)' {
    It 'returns Name/Version/File objects the OSV feeder consumes' {
        $c = @(Test-TcpkGoRustDeps -Path $script:fx -AsComponent)
        $c.Count | Should -Be 8
        foreach ($x in $c) {
            $x.PSObject.Properties.Name | Should -Contain 'Name'
            $x.PSObject.Properties.Name | Should -Contain 'Version'
            $x.PSObject.Properties.Name | Should -Contain 'File'
            # Versions are normalized to the '^\d' form Get-TcpkCveMatches requires.
            $x.Version | Should -Match '^\d'
        }
    }

    It 'tags Go modules with the Go ecosystem and strips the v prefix' {
        $c = @(Test-TcpkGoRustDeps -Path $script:fx -AsComponent | Where-Object { $_.Ecosystem -eq 'Go' })
        $c.Count | Should -Be 5
        @($c | ForEach-Object { $_.Name }) | Should -Contain 'golang.org/x/net'
        @($c | Where-Object { $_.Name -eq 'golang.org/x/net' }).Version | Should -Be '0.17.0'
        @($c | Where-Object { $_.Name -eq 'golang.org/x/net' }).Verified | Should -BeTrue
    }

    It 'tags Rust crates as crates.io and marks them unverified' {
        $c = @(Test-TcpkGoRustDeps -Path $script:fx -AsComponent | Where-Object { $_.Ecosystem -eq 'crates.io' })
        $c.Count | Should -Be 3
        @($c | Where-Object { $_.Name -eq 'serde' }).Version | Should -Be '1.0.188'
        foreach ($x in $c) { $x.Verified | Should -BeFalse }
    }

    It 'emits no findings in collector mode' {
        $c = @(Test-TcpkGoRustDeps -Path $script:fx -AsComponent)
        @($c | Where-Object { $_.PSObject.Properties.Name -contains 'RuleId' }).Count | Should -Be 0
    }
}

Describe 'Get-TcpkGoRustBinaryComponents (shared collector)' {
    It 'returns the same shape as the other ecosystem collectors' {
        $c = @(InModuleScope TCPK -Parameters @{ p = $script:fx } { param($p) Get-TcpkGoRustBinaryComponents -Dir $p })
        $c.Count | Should -Be 8
        @($c | Where-Object { $_.Ecosystem -eq 'Go' }).Count | Should -Be 5
        @($c | Where-Object { $_.Ecosystem -eq 'crates.io' }).Count | Should -Be 3
    }

    It 'filters to one ecosystem on request' {
        $g = @(InModuleScope TCPK -Parameters @{ p = $script:fx } { param($p) Get-TcpkGoRustBinaryComponents -Dir $p -Ecosystem 'Go' })
        @($g | Where-Object { $_.Ecosystem -ne 'Go' }).Count | Should -Be 0
        $g.Count | Should -Be 5
    }

    It 'returns an empty array for a path with no binaries' {
        $empty = Join-Path $script:fx 'emptydir'
        New-Item -ItemType Directory -Path $empty -Force | Out-Null
        $c = @(InModuleScope TCPK -Parameters @{ p = $empty } { param($p) Get-TcpkGoRustBinaryComponents -Dir $p })
        $c.Count | Should -Be 0
    }
}
