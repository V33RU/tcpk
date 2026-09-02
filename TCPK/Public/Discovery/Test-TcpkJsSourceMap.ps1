function Test-TcpkJsSourceMap {
<#
.SYNOPSIS
    A61. JavaScript source-map exposure: shipped .js.map files and `//# sourceMappingURL=`
    comments in bundled JS.

.DESCRIPTION
    A JavaScript source map (.js.map) reconstructs the ORIGINAL TypeScript / JSX including
    comments, private class names, inline endpoint literals and any secret that survived
    the minifier as a string constant. A shipped .js with a `//# sourceMappingURL=` comment
    (or a sibling .map file) hands a reverse engineer the pre-bundle source for free.

    Two shapes fire, per shipped .js:

    Rules:
      js.sourcemap.shipped          MEDIUM  Confirmed  A .js.map file is present alongside a
                                                        shipped .js (Electron asar payload,
                                                        Webview2 dist tree, Node app.asar
                                                        extraction, or any first-party JS
                                                        shipped as loose files).
      js.sourcemap.comment-inline   MEDIUM  Confirmed  A shipped .js has a
                                                        '//# sourceMappingURL='
                                                        comment. If the URL points at an
                                                        absolute http(s):// endpoint the
                                                        source is fetched at devtools open;
                                                        if it points at a local .map that
                                                        also ships in the tree, both rules
                                                        may fire.
      js.sourcemap.datauri          HIGH    Confirmed  The sourceMappingURL is a
                                                        'data:application/json;base64,...'
                                                        URI - the entire pre-bundle source
                                                        is inlined in the shipped .js.

    Excludes conventional third-party locations so the report doesn't drown in vendor
    noise: node_modules\.bin, site-packages\, resources\electron\, any \electron-vendor\
    subdirectory. That keeps the finding scoped to first-party app JS.

.PARAMETER Path
    Install directory or a single .js file.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    # Path substrings we skip as "known third-party vendor JS": they SHOULD ship maps and
    # firing on them would drown the first-party signal.
    $vendorSkipRx = '(?i)[\\/](node_modules[\\/](\.bin|core-js|@babel|@types|typescript|react|react-dom|lodash|moment|axios|electron|electron-updater|node-notifier)|site-packages|resources[\\/](electron|inspector|node_modules)|vendor[\\/])'

    $item = Get-Item -LiteralPath $Path
    $jsFiles  = @()
    $mapFiles = @()
    if ($item.PSIsContainer) {
        try {
            $all = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                     Where-Object {
                         $ext = $_.Extension.ToLowerInvariant()
                         ($ext -eq '.js' -or $ext -eq '.mjs' -or $ext -eq '.map') -and
                         $_.Length -lt 20971520 -and     # skip individual files > 20 MB
                         -not ($_.FullName -match $vendorSkipRx)
                     })
            $jsFiles  = @($all | Where-Object { $_.Extension -in '.js','.mjs' })
            $mapFiles = @($all | Where-Object { $_.Extension -eq '.map' })
        } catch { return }
    } elseif ($item.Extension -in '.js','.mjs') {
        $jsFiles = @($item)
    }

    # Index .map files by basename minus '.map' so a sibling lookup is O(1).
    $mapIndex = @{}
    foreach ($m in $mapFiles) {
        $key = $m.FullName.Substring(0, $m.FullName.Length - 4).ToLowerInvariant()
        $mapIndex[$key] = $m
    }

    foreach ($j in $jsFiles) {
        # ---- js.sourcemap.shipped: sibling .map file present? ------------------------
        $sibling = $null
        $keyLc = $j.FullName.ToLowerInvariant()
        if ($mapIndex.ContainsKey($keyLc)) { $sibling = $mapIndex[$keyLc] }
        if ($sibling) {
            $sizeKb = [Math]::Round($sibling.Length / 1024, 1)
            New-TcpkFinding -Module 'discovery' -RuleId 'js.sourcemap.shipped' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "Source map shipped alongside $($j.Name): $($sibling.Name) (${sizeKb} KB)" `
                -File $sibling.FullName -Evidence "sibling of $($j.FullName); size=$($sibling.Length) bytes" `
                -Cwe @('CWE-540','CWE-1188') `
                -Description ('A .js.map file ships in the install tree next to the corresponding .js. Loading ' +
                    'the .js in Chrome / Edge DevTools reconstructs the original TypeScript / JSX including ' +
                    'comments, original type / class names and any strings that survived the bundler as literals ' +
                    '(inline endpoints, internal codenames, occasionally hardcoded secrets). Skips known ' +
                    'third-party vendor locations (node_modules, site-packages, resources/electron, vendor/).') `
                -Fix 'Do not ship .js.map in a release build. Configure the bundler (webpack.devtool=hidden-source-map / rollup sourcemap: hidden / tsc --sourceMap false) so maps are produced only during CI upload to a monitoring service.'
        }

        # ---- js.sourcemap.comment-inline / .datauri ----------------------------------
        # Read up to the first 2 MB of the .js and look near the tail for the sourceMappingURL
        # comment - bundlers emit it as the LAST comment. A prefilter avoids re-reading files
        # that don't mention 'sourceMappingURL' at all.
        $body = $null
        try {
            if ($j.Length -gt 2097152) {
                # Tail read for very large bundles.
                $fs = [IO.File]::OpenRead($j.FullName)
                try {
                    $tailLen = [Math]::Min([long]65536, $j.Length)
                    $fs.Seek(-$tailLen, [IO.SeekOrigin]::End) | Out-Null
                    $buf = New-Object byte[] $tailLen
                    [void]$fs.Read($buf, 0, $tailLen)
                    $body = [Text.Encoding]::UTF8.GetString($buf)
                } finally { $fs.Dispose() }
            } else {
                $body = [IO.File]::ReadAllText($j.FullName)
            }
        } catch { continue }
        if (-not $body -or $body.IndexOf('sourceMappingURL', [StringComparison]::Ordinal) -lt 0) { continue }

        $m = [regex]::Match($body, '(?im)^\s*(?://|/\*)#\s*sourceMappingURL\s*=\s*(\S+?)\s*(?:\*/)?\s*$')
        if (-not $m.Success) { continue }
        $mapUri = $m.Groups[1].Value
        if ($mapUri -match '^(?i)data:') {
            $sample = $mapUri.Substring(0, [Math]::Min(64, $mapUri.Length)) + '...'
            New-TcpkFinding -Module 'discovery' -RuleId 'js.sourcemap.datauri' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Inline source map in $($j.Name): sourceMappingURL is a data:... URI" `
                -File $j.FullName -Evidence "sourceMappingURL=$sample" `
                -Cwe @('CWE-540','CWE-1188') `
                -Description ('The .js embeds its source map inline as a data URI (typically ' +
                    '`data:application/json;base64,...`). The pre-bundle source is present verbatim in ' +
                    'the shipped file - a reverse engineer decodes the base64 and reads the original ' +
                    'TypeScript / JSX. Higher severity than a sibling .js.map because the exposure is ' +
                    'inescapable even if the map file were later removed from the tree.') `
                -Fix 'Rebuild with the bundler set to nosources / hidden-source-map, or drop the inline map by removing devtool="inline-source-map" from the build config.'
        } else {
            New-TcpkFinding -Module 'discovery' -RuleId 'js.sourcemap.comment-inline' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "$($j.Name) declares a sourceMappingURL: $mapUri" `
                -File $j.FullName -Evidence "sourceMappingURL=$mapUri" `
                -Cwe @('CWE-540','CWE-1188') `
                -Description ('The shipped .js carries a `//# sourceMappingURL=` comment. If the URL is ' +
                    'absolute (http:// / https://) DevTools fetches the map when the file is opened; if ' +
                    'it points at a local .map that also ships in the tree, `js.sourcemap.shipped` fires ' +
                    'in addition. Either way the pre-bundle source is exposed to anyone with the shipped .js.') `
                -Fix 'Strip the sourceMappingURL comment from release builds. Rebuild with the bundler set to hidden-source-map (webpack / rollup / esbuild) so the map is produced for CI upload only.'
        }
    }
}
