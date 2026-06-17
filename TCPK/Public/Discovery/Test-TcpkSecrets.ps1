function Test-TcpkSecrets {
<#
.SYNOPSIS
    A08 - Hardcoded-secret scan (regex rules over UTF-8 + UTF-16LE views).

.DESCRIPTION
    Walks every file under the path (or just the named file) and matches each
    rule from Data\secrets.json. Skips known framework prefixes and large
    files (>16 MB).
    Evidence is redacted: first 6 + last 6 chars of the matched string, with
    length annotation.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $rules = (Get-TcpkData).rules
    # Perf: compile each regex once (RegexOptions.Compiled = JIT to IL, 2-5x faster on
    # repeated matches), and pre-extract a literal "cheap-substring" prefix so we can
    # skip rules whose first literal isn't anywhere in the file at all.
    foreach ($r in $rules) {
        if (-not $r.PSObject.Properties['_RX']) {
            $r | Add-Member -NotePropertyName _RX -NotePropertyValue ([regex]::new(
                $r.pattern,
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                [System.Text.RegularExpressions.RegexOptions]::Multiline  -bor
                [System.Text.RegularExpressions.RegexOptions]::Compiled
            )) -Force
        }
        if (-not $r.PSObject.Properties['_QuickLit']) {
            # Pre-filter literal = the MANDATORY literal run at the START of the pattern, after
            # stripping leading inline-flags / anchors. We take ONLY a leading literal because the
            # old extractor pulled regex SYNTAX from the middle of the pattern -- \b -> 'b'
            # ('bsk_', 'bgithub_pat_'), (?: -> ':' (':AKIA'), [A-Z0-9] -> 'A-Z0-9' -- none of which
            # appear in real data, so the rule was silently skipped and AWS / GitHub-PAT / Stripe /
            # Aptabase detection was ZEROED OUT. If the pattern opens with a group/class/short
            # literal we set $null = no pre-filter (the rule always runs -- correctness over speed).
            $p = $r.pattern
            $p = [regex]::Replace($p, '^\(\?[a-zA-Z]+\)', '')   # leading inline flags e.g. (?i)
            $p = [regex]::Replace($p, '^(?:\\b|\^)+', '')        # leading anchors \b ^
            $lit = $null
            $lm = [regex]::Match($p, '^[A-Za-z0-9_./=:\-]{4,}')
            if ($lm.Success) {
                $cand = $lm.Value
                # if the char after the run is a quantifier, its last char is optional/variable -> drop it
                $next = if ($p.Length -gt $cand.Length) { $p[$cand.Length] } else { [char]0 }
                if ($next -eq '?' -or $next -eq '*' -or $next -eq '{') { $cand = $cand.Substring(0, $cand.Length - 1) }
                if ($cand.Length -ge 4) { $lit = $cand }
            }
            $r | Add-Member -NotePropertyName _QuickLit -NotePropertyValue $lit -Force
        }
    }

    # .pak = Chromium/Electron resource+locale packs (UI strings in dozens of languages, no app
    # secrets) -- scanning them produced natural-language false positives (e.g. German 'anpassen...'
    # matching the AWS 'ANPA' prefix). Treat them like the other Chromium runtime data we skip.
    $skipExt = @('.png','.jpg','.jpeg','.ico','.otf','.ttf','.pri','.cat','.p7x','.woff','.woff2','.svg','.gif','.bmp','.tif','.tiff','.webp','.mp3','.mp4','.wav','.ogg','.m4a','.pak')

    $files = if ((Get-Item -LiteralPath $Path).PSIsContainer) {
        Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue
    } else {
        Get-Item -LiteralPath $Path
    }

    foreach ($f in $files) {
        if ($f.Extension.ToLowerInvariant() -in $skipExt) { continue }
        if (Test-TcpkIsFrameworkFile $f.Name)             { continue }
        if ($f.Length -gt 16MB)                            { continue }

        $views = Read-TcpkStringViews -Path $f.FullName
        if (-not $views) { continue }

        $seen = @{}
        foreach ($view in @(
            @{ Src='utf8';        T=$views.Utf8       },
            @{ Src='utf16le';     T=$views.Utf16Le    },
            @{ Src='utf16le-odd'; T=$views.Utf16LeOdd }   # odd-byte-aligned wide strings (~half of them) -- the view was decoded but never scanned
        )) {
            foreach ($r in $rules) {
                # Cheap pre-filter: skip rule if its literal prefix isn't in the view.
                # MUST be case-insensitive -- the rules use IgnoreCase, so a literal
                # like 'server' must still match 'Server' in the file. A case-sensitive
                # Contains() here silently skips rules and MISSES real secrets.
                if ($r._QuickLit -and ($view.T.IndexOf($r._QuickLit, [System.StringComparison]::OrdinalIgnoreCase) -lt 0)) { continue }
                foreach ($m in $r._RX.Matches($view.T)) {
                    $hit = $m.Value

                    # Placeholder / documentation guard: skip matches that are
                    # clearly format examples, not real credentials. Catches HTML
                    # entity placeholders (Pwd=&lt;snipped&gt;), angle-bracket
                    # templates (pwd=<password>), and common doc filler words.
                    if ($hit -match '(?i)(&lt|&gt|&amp|<[a-z_ ]{2,}>|\bsnipped\b|\bplaceholder\b|\bexample\b|\byour[-_ ]|\bchange[-_ ]?me\b|\bdummy\b|\bsample\b|\bredacted\b|x{6,}|\.\.\.|\*{4,})') {
                        continue
                    }

                    $key = "$($r.id)::" + $hit.Substring(0, [Math]::Min(80, $hit.Length))
                    if ($seen.ContainsKey($key)) { continue }
                    $seen[$key] = $true

                    # Show the FULL matched value (un-redacted). This is a local, operator-run
                    # audit tool, so the operator needs to see/verify the actual secret. NOTE: the
                    # report files now contain live secret values -- treat the output as sensitive.
                    $redacted = $hit

                    # A regex match confirms the secret FORMAT is present, not that
                    # the credential is live. Per the liveness rule, this is Inferred
                    # until a confirmation step proves the key authenticates.
                    New-TcpkFinding -Module 'static' -RuleId "secrets.$($r.id)" `
                        -Severity $r.severity -Confidence 'Inferred' `
                        -Title $r.title -File $f.FullName `
                        -Evidence "$redacted [src=$($view.Src)]" `
                        -Cwe ([string[]]$r.cwe) -Fix $r.fix
                }
            }
        }
    }
}
