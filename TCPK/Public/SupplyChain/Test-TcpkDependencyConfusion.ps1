function Test-TcpkDependencyConfusion {
<#
.SYNOPSIS
    C29. Dependency confusion attack surface in package manager configuration.

.DESCRIPTION
    Scans package manager configuration files for structural misconfigurations
    that enable dependency confusion attacks: an attacker publishes a public
    package with the same name as an internal package and the package manager
    resolves the attacker-controlled version.

    Checks performed (static, no network):

    NuGet:
      - NuGet.config has both a private feed and nuget.org as sources, but
        no <packageSourceMapping> section.  Without PackageSourceMapping every
        feed can supply every package; the highest version wins regardless of
        feed order, so a higher-versioned public package shadows the private one.
      - Private feeds without protocolVersion="3" may not participate correctly
        in source mapping even when it is present.

    npm:
      - .npmrc sets a private registry URL for the default scope but provides
        no @scope:registry mappings.  Un-scoped package names in package.json
        fall through to the public npm registry.

    pip:
      - requirements.txt / pip.conf / setup.cfg / pyproject.toml uses
        --extra-index-url (additive, not replacing).  pip picks the highest
        version across ALL indexes, so a public version that exceeds the
        internal one is installed automatically.

    All findings are Confirmed because the misconfiguration is directly
    observable in the config files.

.PARAMETER Path
    Root directory of the application to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkDependencyConfusion')) { return }
    if (-not (Test-Path $Path)) { return }

    # ------------------------------------------------------------------ NuGet
    $nugetConfigs = @(Get-ChildItem -Path $Path -Recurse -Filter 'NuGet.config' -File `
                        -ErrorAction SilentlyContinue | Select-Object -First 20)

    foreach ($cfg in $nugetConfigs) {
        try { [xml]$xml = Get-Content $cfg.FullName -Raw -ErrorAction Stop } catch { continue }

        $sources = @($xml.configuration.packageSources.add | Where-Object { $_ -ne $null })
        if ($sources.Count -lt 2) { continue }

        $publicSrcs  = @($sources | Where-Object { "$($_.value)" -match 'nuget\.org' })
        $privateSrcs = @($sources | Where-Object { "$($_.value)" -notmatch 'nuget\.org' })
        if (-not ($publicSrcs.Count -and $privateSrcs.Count)) { continue }

        # PackageSourceMapping (NuGet 6.0+): <packageSourceMapping><packageSource key="...">
        # If absent or has no children, confusion is possible.
        $psmNode   = $xml.configuration.packageSourceMapping
        $hasPSM    = $psmNode -ne $null -and @($psmNode.packageSource).Count -gt 0

        if (-not $hasPSM) {
            $srcList = ($sources | ForEach-Object { "$($_.key)=$($_.value)" }) -join '; '
            New-TcpkFinding -Module 'supply-chain' -RuleId 'nuget.dep-confusion.no-psm' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title 'NuGet config has private + public feeds without PackageSourceMapping' `
                -File $cfg.FullName `
                -Evidence "Sources: $srcList" `
                -Cwe @('CWE-829','CWE-494') `
                -Description ('NuGet.config declares both a private feed and nuget.org as package ' +
                    'sources but contains no <packageSourceMapping> section. Without source mapping, ' +
                    'NuGet resolves every package from ALL configured feeds and installs the ' +
                    'highest version found -- a technique known as dependency confusion. An ' +
                    'attacker who knows an internal package name can publish a higher-versioned ' +
                    'public package on nuget.org to have it installed automatically. Affects ' +
                    'CI/CD pipelines, developer machines, and any system that runs dotnet restore.') `
                -Fix ('Add <packageSourceMapping> in NuGet.config so each package pattern is ' +
                    'pinned to exactly one feed. Alternatively, remove nuget.org from the source ' +
                    'list and proxy all packages through the internal feed. ' +
                    'Ref: https://learn.microsoft.com/nuget/consume-packages/package-source-mapping')
        }

        # Warn on v2 private feeds -- even with PSM they may not block correctly on older clients.
        foreach ($ps in $privateSrcs) {
            $proto = "$($ps.protocolVersion)"
            if ($proto -and $proto -ne '3') {
                New-TcpkFinding -Module 'supply-chain' -RuleId 'nuget.dep-confusion.v2-feed' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "Private NuGet feed uses protocol v$proto (v3 recommended)" `
                    -File $cfg.FullName `
                    -Evidence "Feed: $($ps.key)=$($ps.value) protocolVersion=$proto" `
                    -Cwe @('CWE-829') `
                    -Description ('NuGet v2 protocol feeds may not honour PackageSourceMapping ' +
                        'in all client versions. Upgrade the private feed to a v3 endpoint ' +
                        '(Azure Artifacts, GitHub Packages, and Artifactory all support v3). ' +
                        'Older NuGet clients (pre-6.0) ignore source mapping entirely regardless ' +
                        'of protocol version.') `
                    -Fix 'Configure the private feed endpoint as a NuGet v3 API URL and set protocolVersion="3" in NuGet.config.'
            }
        }
    }

    # ------------------------------------------------------------------ npm
    $npmrcFiles = @(Get-ChildItem -Path $Path -Recurse -Filter '.npmrc' -File `
                      -ErrorAction SilentlyContinue | Select-Object -First 20)

    foreach ($rc in $npmrcFiles) {
        $rcContent = Get-Content $rc.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $rcContent) { continue }

        # registry=<url>  that is NOT the public npm registry
        $hasPrivateReg = $rcContent -match '(?im)^registry\s*=\s*(?!https?://(registry\.npmjs\.org|www\.npmjs\.com))'
        if (-not $hasPrivateReg) { continue }

        # @scope:registry=<url>  entries lock scoped packages to a specific feed
        $hasScopeMap = $rcContent -match '(?im)^@[a-z0-9_-]+:registry\s*='

        if (-not $hasScopeMap) {
            # Look for un-scoped dependency names in nearby package.json
            $pkgJson = $null
            $dir = $rc.DirectoryName
            $candidate = Join-Path $dir 'package.json'
            if (Test-Path $candidate) {
                try { $pkgJson = Get-Content $candidate -Raw -ErrorAction Stop | ConvertFrom-Json } catch {}
            }

            $unscoped = @()
            if ($pkgJson) {
                $allDeps = @()
                if ($pkgJson.dependencies)    { $pkgJson.dependencies.PSObject.Properties    | ForEach-Object { $allDeps += $_.Name } }
                if ($pkgJson.devDependencies) { $pkgJson.devDependencies.PSObject.Properties | ForEach-Object { $allDeps += $_.Name } }
                $unscoped = @($allDeps | Where-Object { $_ -notmatch '^@' })
            }

            $unscopedHint = if ($unscoped.Count) {
                " Un-scoped packages found: $( ($unscoped | Select-Object -First 8) -join ', ')$(if ($unscoped.Count -gt 8) { ' ...' } else { '' })"
            } else { '' }

            New-TcpkFinding -Module 'supply-chain' -RuleId 'npm.dep-confusion.no-scope-map' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title 'npm .npmrc sets private registry without @scope:registry mapping' `
                -File $rc.FullName `
                -Evidence ("Private registry configured; no @scope:registry lines found.$unscopedHint") `
                -Cwe @('CWE-829','CWE-494') `
                -Description ('The .npmrc file redirects the default registry to a private feed ' +
                    'but does not bind any package scope to that feed with @scope:registry=<url>. ' +
                    'Package names that lack an @scope prefix are resolved by falling back to the ' +
                    'public npm registry (registry.npmjs.org) when the package is absent from the ' +
                    'private feed. An attacker who knows internal un-scoped package names can ' +
                    'publish higher-versioned packages on npm to get them installed during ' +
                    'npm install / CI pipeline runs.') `
                -Fix ('Prefix all internal packages with a private scope (e.g. @company/pkg-name) ' +
                    'and add "@company:registry=<private-url>" to .npmrc. Alternatively, set ' +
                    '"disableDefaultRegistryFallback=true" if supported by your npm version (>= 8.x). ' +
                    'Ref: https://docs.npmjs.com/cli/v10/configuring-npm/npmrc')
        }
    }

    # ------------------------------------------------------------------ pip
    $pipFiles = @(Get-ChildItem -Path $Path -Recurse `
                    -Include 'requirements*.txt','pip.conf','setup.cfg' -File `
                    -ErrorAction SilentlyContinue | Select-Object -First 30)

    # Also check pyproject.toml tool.pip section
    $pyprojects = @(Get-ChildItem -Path $Path -Recurse -Filter 'pyproject.toml' -File `
                      -ErrorAction SilentlyContinue | Select-Object -First 10)

    $allPipFiles = @($pipFiles) + @($pyprojects)

    foreach ($pf in $allPipFiles) {
        $content = Get-Content $pf.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }

        # --extra-index-url is the dangerous form: pip queries ALL indexes and picks highest version.
        # --index-url alone (without extra) replaces the default index safely.
        if ($content -notmatch '(?im)(--extra-index-url|extra-index-url\s*=\s*\S|extra_index_url\s*=\s*\S)') { continue }

        # Extract the private index URL from --index-url if present (for evidence)
        $privateIdx = ''
        if ($content -match '(?im)(?:--index-url|index-url\s*=|index_url\s*=)\s+(\S+)') {
            $privateIdx = $matches[1]
        }

        # Extract extra-index-url values
        $extraUrls = @()
        $content | Select-String '(?im)(?:--extra-index-url|extra[_-]index[_-]url\s*[=\s])\s*(\S+)' -AllMatches |
            ForEach-Object { $_.Matches | ForEach-Object { $extraUrls += $_.Groups[1].Value } }

        $evidence = "extra-index-url: $($extraUrls -join ', ')"
        if ($privateIdx) { $evidence = "index-url: $privateIdx; $evidence" }

        New-TcpkFinding -Module 'supply-chain' -RuleId 'pip.dep-confusion.extra-index-url' `
            -Severity 'HIGH' -Confidence 'Confirmed' `
            -Title "pip extra-index-url enables dependency confusion in $($pf.Name)" `
            -File $pf.FullName `
            -Evidence $evidence `
            -Cwe @('CWE-829','CWE-494') `
            -Description ('The pip configuration uses --extra-index-url, which ADDS an index rather ' +
                'than replacing the default. When pip resolves a package, it queries all indexes and ' +
                'installs the package with the highest version number, regardless of which index it ' +
                'came from. An attacker who knows internal package names can publish a higher-versioned ' +
                'package on PyPI to have it installed instead of the private one. This is the exact ' +
                'mechanism behind Alex Birsan''s original dependency confusion disclosure (2021).') `
            -Fix ('Replace --extra-index-url with --index-url pointing exclusively to the private ' +
                'feed, and proxy or mirror public packages through that feed. If individual public ' +
                'packages must be referenced directly, pin them with exact version hashes in ' +
                'requirements.txt using pip-compile --generate-hashes. ' +
                'Ref: https://pip.pypa.io/en/stable/cli/pip_install/#hash-checking-mode')
    }
}
