function Test-TcpkGoRustDeps {
<#
.SYNOPSIS
    Recover the embedded dependency tree from statically-linked Go and Rust binaries.

.DESCRIPTION
    .NET ships deps.json, Electron ships package.json, Java ships pom.properties inside
    the jar, and TCPK reads all three. Go and Rust ship ONE statically-linked executable
    with the whole dependency tree compiled in and no manifest beside it, so a Go or Rust
    thick client reached the CVE engine with an empty component list. An empty list reads
    as "clean" when the truth is "never queried". This closes that gap by extracting the
    components out of the binary itself.

    GO -- structured and complete.
      The Go linker stamps runtime/debug.BuildInfo into the image behind the 14-byte
      magic "\xff Go buildinf:", followed by one byte ptrSize and one byte flags
      (bit 0x2 set = module data stored inline as length-delimited strings, Go 1.18+).
      The module list itself is plain tab/newline delimited text:

        path   github.com/example/app
        mod    github.com/example/app   (devel)
        dep    github.com/some/lib      v1.2.3   h1:base64hash=
        build  -compiler=gc

      Every 'dep', 'mod' and '=>' (replacement) line is parsed into name + version. The
      text scan is the primary recovery path because it survives every Go version; the
      magic is read to CONFIRM the Go linker produced the image and to report ptrSize
      and the inline-strings flag. A binary with no magic but real 'dep' lines carrying
      semver still counts as Go.

    RUST -- best-effort and incomplete by construction.
      rustc embeds no manifest of any kind. The only crate identities that survive are
      the Cargo source paths baked into panic locations and debug info:

        .../cargo/registry/src/<registry-host>-<hash>/<crate>-<version>/src/lib.rs

      Those are parsed into crate + version and deduplicated, along with the rustc
      commit hash ("/rustc/<40-hex>/") or release string ("rustc 1.XX.X"). A stripped
      release build, or one built with --remap-path-prefix, carries none of them, so a
      low crate count is NOT evidence of a small dependency tree. Every Rust finding
      states this, and every Rust component is marked Verified = $false.

    This cmdlet EXTRACTS COMPONENTS ONLY. It makes no CVE claim. The components it
    returns use the same shape the online CVE engine already consumes for NuGet / npm /
    Maven / PyPI (Name, Version, File), so Get-TcpkCveMatches feeds them straight to OSV
    under the Go and crates.io ecosystems.

    Reading: the file is streamed through the shared printable-run extractor, so a
    200 MB binary costs bounded memory and every byte is read. Files above -MaxFileBytes
    are not scanned and are reported as Skipped, by name and size. Nothing is dropped
    quietly.

.PARAMETER Path
    Install directory (walked for shipped binaries) or a single file.

.PARAMETER MaxFileBytes
    Per-file size cap. A file above this is not scanned and produces a Skipped finding
    naming the file, its size and the cap. Default 512 MB. 0 disables the cap.

.PARAMETER MaxFiles
    Cap on how many binaries are examined. Hitting it produces a Skipped finding stating
    that the counts below it are a floor, not a total. Default 2000.

.PARAMETER MaxComponentsPerFile
    Cap on components recovered from a single binary. Hitting it produces a Skipped
    finding naming the file. Default 5000.

.PARAMETER AsComponent
    Collector mode. Emit the parsed components as plain objects
    (Name, Version, File, Ecosystem, Source, Verified) instead of findings, for the CVE
    pipeline and SBOM consumers.

.OUTPUTS
    [TcpkFinding], or [pscustomobject] components with -AsComponent.

.EXAMPLE
    Test-TcpkGoRustDeps -Path 'C:\Program Files\Example\'

.EXAMPLE
    # feed the recovered components to the online CVE engine's shape
    Test-TcpkGoRustDeps -Path 'C:\Program Files\Example\' -AsComponent |
        Where-Object Ecosystem -eq 'Go'
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [long]$MaxFileBytes = 536870912,
        [int]$MaxFiles = 2000,
        [int]$MaxComponentsPerFile = 5000,
        [switch]$AsComponent
    )

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) {
        if ($AsComponent) { return }
        New-TcpkFinding -Module 'static' -RuleId 'gorust.path-unreadable' `
            -Severity 'INFO' -Confidence 'Skipped' `
            -Title 'Go/Rust dependency scan did not run: path not readable' `
            -File $Path -Evidence "Get-Item failed for: $Path" `
            -Description 'No Go or Rust binary was examined because the supplied path could not be opened. This result is UNKNOWN, not clean.' `
            -Fix 'Re-run against a readable extracted install directory.'
        return
    }

    $files = @()
    try { $files = @(Get-TcpkPeFiles -Path $item.FullName) } catch { $files = @() }

    $fileBudgetHit = $false
    if ($MaxFiles -gt 0 -and $files.Count -gt $MaxFiles) {
        $fileBudgetHit = $true
        $totalSeen = $files.Count
        $files = @($files | Select-Object -First $MaxFiles)
    } else {
        $totalSeen = $files.Count
    }

    $goComps   = New-Object 'System.Collections.Generic.List[object]'
    $rustComps = New-Object 'System.Collections.Generic.List[object]'
    $seenGo = @{}; $seenRust = @{}
    $pending = New-Object 'System.Collections.Generic.List[object]'   # deferred findings

    $examined = 0; $goBins = 0; $rustBins = 0; $neither = 0; $oversize = 0; $errored = 0

    foreach ($f in $files) {
        if ($MaxFileBytes -gt 0 -and $f.Length -gt $MaxFileBytes) {
            $oversize++
            $pending.Add((New-TcpkFinding -Module 'static' -RuleId 'gorust.file-too-large' `
                -Severity 'INFO' -Confidence 'Skipped' `
                -Title "Binary not scanned for Go/Rust dependencies: over the size cap" `
                -File $f.FullName `
                -Evidence ("size={0} bytes ({1} MB); cap={2} bytes" -f $f.Length, [math]::Round($f.Length / 1MB, 1), $MaxFileBytes) `
                -Description 'This binary was skipped by the per-file size cap, so any Go module list or Rust crate path inside it was NOT extracted and NOT sent for CVE matching. Absence of a component from this file is unknown, not clean.' `
                -AttributionBasis 'established-footprint' `
                -Fix "Re-run with -MaxFileBytes 0 to scan it in full (it streams, so memory stays bounded)."))
            continue
        }

        $examined++
        $info = $null
        try { $info = Get-TcpkGoRustBinaryInfo -Path $f.FullName -MaxComponents $MaxComponentsPerFile } catch { $info = $null }

        if (-not $info -or $info.Error) {
            $errored++
            $msg = if ($info) { "$($info.Error)" } else { 'reader returned nothing' }
            $pending.Add((New-TcpkFinding -Module 'static' -RuleId 'gorust.file-error' `
                -Severity 'INFO' -Confidence 'Skipped' `
                -Title 'Binary could not be read for Go/Rust dependency extraction' `
                -File $f.FullName -Evidence $msg `
                -Description 'The file could not be streamed, so no Go module list or Rust crate path was extracted from it.' `
                -AttributionBasis 'established-footprint' `
                -Fix 'Check the file is readable and not locked, then re-run.'))
            if (-not $info) { continue }
        }

        if ($info.Capped) {
            $pending.Add((New-TcpkFinding -Module 'static' -RuleId 'gorust.components-capped' `
                -Severity 'INFO' -Confidence 'Skipped' `
                -Title 'Component extraction stopped at the per-binary cap' `
                -File $f.FullName `
                -Evidence ("cap={0} component(s) reached; extraction stopped early" -f $MaxComponentsPerFile) `
                -Description 'The component list for this binary is a FLOOR, not a total. Components past the cap were never extracted and never sent for CVE matching.' `
                -AttributionBasis 'established-footprint' `
                -Fix 'Re-run with a higher -MaxComponentsPerFile to recover the full list.'))
        }

        $isGo = [bool]$info.IsGo; $isRust = [bool]$info.IsRust
        if (-not $isGo -and -not $isRust) { $neither++; continue }

        # ---- Go ----
        if ($isGo) {
            $goBins++
            foreach ($m in @($info.GoModules)) {
                $k = "$("$($m.Name)".ToLowerInvariant())|$($m.Version)"
                if ($seenGo.ContainsKey($k)) { continue }
                $seenGo[$k] = $true
                $goComps.Add([pscustomobject]@{ Name = $m.Name; Version = $m.Version; File = $f.Name
                                                Ecosystem = 'Go'; Source = 'go-buildinfo'; Verified = $true })
            }

            $ev = New-Object System.Collections.Generic.List[string]
            if ($info.MagicFound) {
                $ev.Add(("buildinfo magic '\xff Go buildinf:' at offset 0x{0:X}" -f $info.MagicOffset))
                $ev.Add("ptrSize=$($info.PtrSize)")
                $inl = 'pointer-stored (pre-1.18 layout)'
                if ($info.InlineStrings) { $inl = 'inline strings (Go 1.18+)' }
                $ev.Add(("flags=0x{0:X2} -> {1}" -f $info.Flags, $inl))
            } else {
                $ev.Add("buildinfo magic not located; identified by embedded module text")
            }
            if ($info.GoToolchain)   { $ev.Add("toolchain=go$($info.GoToolchain)") }
            if ($info.GoMainPath)    { $ev.Add("main module=$($info.GoMainPath) $($info.GoMainVersion)") }
            $ev.Add("dep/mod lines parsed=$($info.GoModulesRaw)")
            $ev.Add("modules with a queryable version=$($info.GoModules.Count)")
            if ($info.GoUnusableVersions -gt 0) { $ev.Add("non-semver versions (e.g. (devel))=$($info.GoUnusableVersions)") }
            if ($info.GoBuildSettings.Count) { $ev.Add("build settings: " + ((@($info.GoBuildSettings) | Select-Object -First 6) -join ' ')) }
            $sample = @(@($info.GoModules) | Select-Object -First 8 | ForEach-Object { "$($_.Name)@$($_.Version)" })
            if ($sample.Count) { $ev.Add("sample: " + ($sample -join ', ')) }

            $obs = "{{""goModules"":{0},""rawLines"":{1},""magic"":{2}}}" -f $info.GoModules.Count, $info.GoModulesRaw, $info.MagicFound.ToString().ToLowerInvariant()
            $pending.Add((New-TcpkFinding -Module 'static' -RuleId 'gorust.go-buildinfo' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "Go build info: $($info.GoModules.Count) module(s) recovered from $($f.Name)" `
                -File $f.FullName -Evidence ($ev -join '; ') `
                -Description 'Go links every dependency into one binary and stamps runtime/debug.BuildInfo into the image, so the full module list is recoverable without any manifest on disk. These modules are the supply-chain surface of this executable and are the input to Go-ecosystem CVE matching.' `
                -AttributionBasis 'established-footprint' `
                -Subject ("gorust:" + $f.FullName.ToLowerInvariant()) -Dimension 'gorust.go-module-inventory' `
                -ObsValue $obs -Basis 'Measured' `
                -Fix 'Track these modules in a dependency inventory and match them against the Go vulnerability database (Get-TcpkCveMatches queries OSV for the Go ecosystem).'))

            if ($info.MagicFound -and $info.GoModules.Count -eq 0) {
                $pending.Add((New-TcpkFinding -Module 'static' -RuleId 'gorust.go-no-modules' `
                    -Severity 'INFO' -Confidence 'Skipped' `
                    -Title "Go binary with no recoverable module list: $($f.Name)" `
                    -File $f.FullName `
                    -Evidence ("magic found at offset 0x{0:X}, ptrSize={1}, flags=0x{2:X2}; zero dep/mod lines with a queryable version" -f $info.MagicOffset, $info.PtrSize, $info.Flags) `
                    -Description 'The Go build-info header is present but no dep/mod line carried a queryable version. A binary built with -buildvcs=false from a vendored or GOPATH build records no dependency list. This result is UNKNOWN, not a clean dependency tree.' `
                    -AttributionBasis 'established-footprint' `
                    -Fix 'Obtain the module list from the vendor build (go version -m <binary>, or the project go.mod) to complete the inventory.'))
            }
        }

        # ---- Rust ----
        if ($isRust) {
            $rustBins++
            foreach ($c in @($info.RustCrates)) {
                $k = "$("$($c.Name)".ToLowerInvariant())|$($c.Version)"
                if ($seenRust.ContainsKey($k)) { continue }
                $seenRust[$k] = $true
                $rustComps.Add([pscustomobject]@{ Name = $c.Name; Version = $c.Version; File = $f.Name
                                                  Ecosystem = 'crates.io'; Source = 'cargo-path'; Verified = $false })
            }

            $rv = New-Object System.Collections.Generic.List[string]
            if ($info.RustcVersion) { $rv.Add("rustc $($info.RustcVersion)") }
            if ($info.RustcHash)    { $rv.Add("rustc commit $($info.RustcHash)") }
            $rv.Add("cargo registry/vendor source paths -> $($info.RustCrates.Count) unique crate-version pair(s)")
            $rsample = @(@($info.RustCrates) | Select-Object -First 8 | ForEach-Object { "$($_.Name)@$($_.Version)" })
            if ($rsample.Count) { $rv.Add("sample: " + ($rsample -join ', ')) }

            if ($info.RustCrates.Count -gt 0) {
                $robs = "{{""crates"":{0},""source"":""cargo-path""}}" -f $info.RustCrates.Count
                $pending.Add((New-TcpkFinding -Module 'static' -RuleId 'gorust.rust-crates' `
                    -Severity 'INFO' -Confidence 'Confirmed' `
                    -Title "Rust: $($info.RustCrates.Count) crate(s) recovered (best-effort) from $($f.Name)" `
                    -File $f.FullName -Evidence ($rv -join '; ') `
                    -Description ('Rust embeds NO structured manifest. These crate names and versions were read from Cargo source paths left in panic locations and debug info, which means the recovery is BEST-EFFORT AND INCOMPLETE: a stripped build, or one built with --remap-path-prefix, keeps none of those paths, and crates that never panic may leave no path at all. The count above is a FLOOR, not the dependency tree. Do not read a low count, or a later zero-CVE result, as a clean supply chain.') `
                    -AttributionBasis 'established-footprint' `
                    -Subject ("gorust:" + $f.FullName.ToLowerInvariant()) -Dimension 'gorust.rust-crate-inventory' `
                    -ObsValue $robs -Basis 'Measured' `
                    -Fix 'Ask the vendor for the Cargo.lock (or cargo-auditable / CycloneDX output) to obtain the complete crate list; the paths recovered here only establish a lower bound.'))
            } else {
                $pending.Add((New-TcpkFinding -Module 'static' -RuleId 'gorust.rust-stripped' `
                    -Severity 'INFO' -Confidence 'Skipped' `
                    -Title "Rust binary with no recoverable crate paths: $($f.Name)" `
                    -File $f.FullName -Evidence ($rv -join '; ') `
                    -Description 'The binary is identifiably Rust (rustc marker present) but carries no Cargo registry source paths, which is what a stripped or path-remapped release build looks like. NO crate was recovered and NO crate was sent for CVE matching. This result is UNKNOWN, not clean.' `
                    -AttributionBasis 'established-footprint' `
                    -Fix 'Request Cargo.lock or a cargo-auditable / CycloneDX SBOM from the vendor; no static recovery is possible from this binary alone.'))
            }
        }
    }

    # ---- collector mode -------------------------------------------------------
    if ($AsComponent) {
        foreach ($c in $goComps)   { $c }
        foreach ($c in $rustComps) { $c }
        return
    }

    foreach ($p in $pending) { $p }

    if ($fileBudgetHit) {
        New-TcpkFinding -Module 'static' -RuleId 'gorust.file-budget' `
            -Severity 'INFO' -Confidence 'Skipped' `
            -Title 'Go/Rust dependency scan stopped at the file cap' `
            -File $item.FullName `
            -Evidence ("examined {0} of {1} candidate binaries (-MaxFiles {0})" -f $MaxFiles, $totalSeen) `
            -Description 'Binaries past the cap were never opened, so any Go module list or Rust crate list inside them is missing from the counts above. Those counts are a floor, not a total.' `
            -AttributionBasis 'established-footprint' `
            -Fix 'Re-run with a higher -MaxFiles to cover the whole install tree.'
    }

    if ($files.Count -eq 0) {
        New-TcpkFinding -Module 'static' -RuleId 'gorust.no-binaries' `
            -Severity 'INFO' -Confidence 'Skipped' `
            -Title 'Go/Rust dependency scan found no candidate binaries' `
            -File $item.FullName -Evidence "no .exe / .dll / .sys / .node / .pyd under: $($item.FullName)" `
            -Description 'Nothing was examined, so no Go or Rust dependency data exists for this path. This result is UNKNOWN, not clean.' `
            -Fix 'Point -Path at the extracted install directory containing the shipped executables.'
        return
    }

    $summary = New-Object System.Collections.Generic.List[string]
    $summary.Add("binaries examined=$examined")
    $summary.Add("Go=$goBins")
    $summary.Add("Rust=$rustBins")
    $summary.Add("neither=$neither")
    $summary.Add("Go modules=$($goComps.Count)")
    $summary.Add("Rust crates=$($rustComps.Count)")
    if ($oversize -gt 0) { $summary.Add("skipped over size cap=$oversize") }
    if ($errored -gt 0)  { $summary.Add("unreadable=$errored") }
    if ($fileBudgetHit)  { $summary.Add("file cap hit at $MaxFiles of $totalSeen") }

    if ($goBins -eq 0 -and $rustBins -eq 0) {
        New-TcpkFinding -Module 'static' -RuleId 'gorust.not-go-rust' `
            -Severity 'INFO' -Confidence 'Skipped' `
            -Title "No Go or Rust binary found among $examined examined binary/binaries" `
            -File $item.FullName -Evidence ($summary -join '; ') `
            -Description 'Every binary examined was read in full and carried neither Go build info nor a rustc/Cargo marker, so this cmdlet contributed no components. That is a statement about these files, not a clean supply-chain result for the target.' `
            -AttributionBasis 'established-footprint' `
            -Fix 'None required for this check. Other ecosystems (.NET, npm, Maven, PyPI, native) are covered by their own collectors.'
        return
    }

    New-TcpkFinding -Module 'static' -RuleId 'gorust.inventory' `
        -Severity 'INFO' -Confidence 'Confirmed' `
        -Title "Go/Rust supply chain: $($goComps.Count) Go module(s), $($rustComps.Count) Rust crate(s) recovered" `
        -File $item.FullName -Evidence ($summary -join '; ') `
        -Description 'Components recovered from statically-linked binaries, in the shape the online CVE engine consumes (Go modules -> OSV Go, Rust crates -> OSV crates.io). Go recovery is complete for any binary carrying build info; Rust recovery is best-effort from Cargo source paths and is a lower bound only.' `
        -AttributionBasis 'established-footprint' `
        -Subject ("gorust:" + $item.FullName.ToLowerInvariant()) -Dimension 'gorust.component-inventory' `
        -ObsValue ("{{""goModules"":{0},""rustCrates"":{1},""goBinaries"":{2},""rustBinaries"":{3},""examined"":{4}}}" -f $goComps.Count, $rustComps.Count, $goBins, $rustBins, $examined) `
        -Basis 'Measured' `
        -Fix 'Run Get-TcpkCveMatches against the same path to match these components live against OSV.'
}
