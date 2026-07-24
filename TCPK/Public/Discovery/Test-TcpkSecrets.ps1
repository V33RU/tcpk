function Test-TcpkSecrets {
<#
.SYNOPSIS
    A08 - Hardcoded-secret scan (regex rules over UTF-8 + UTF-16LE views).

.DESCRIPTION
    Walks every file under the path (or just the named file) and matches each
    rule from Data\secrets.json. Skips known framework prefixes and binary
    media / .pak blobs. NO size cap -- files <=64 MB load whole, larger files
    stream in bounded overlapping chunks. Rules may carry a 'prefilter' (cheap
    literal needles); such a rule's regex only runs on a view that contains a
    needle, so huge binaries with no trigger word are not ground over.
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
        # Optional multi-needle pre-filter (rule.prefilter): a set of cheap literal triggers.
        # When set, the rule's (often heavy) regex only runs on a view that contains at least one
        # needle. The credential rules require a password-ish keyword to match, so gating on it is
        # loss-free AND stops the regex from grinding over hundreds of MB of binary blobs that
        # contain no such keyword (the cause of the no-size-cap hang on Electron/Chromium apps).
        if (-not $r.PSObject.Properties['_Needles']) {
            $nd = @()
            if ($r.PSObject.Properties['prefilter'] -and $r.prefilter) { $nd = @($r.prefilter | ForEach-Object { "$_" }) }
            $r | Add-Member -NotePropertyName _Needles -NotePropertyValue $nd -Force
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

    # Scan one decoded text view against every rule, emitting findings. Shared by the
    # full-load path (normal files) and the chunked-streaming path (large files). Reads
    # $rules / $seen / $f from the enclosing scope; $seen dedupes within a file (and across
    # the overlapping chunks of a large file). The matched value is shown un-redacted --
    # this is a local operator-run tool, so treat the report files as sensitive.
    $scanText = {
        param([string]$Text, [string]$Src)
        if ([string]::IsNullOrEmpty($Text)) { return }
        foreach ($r in $rules) {
            # Cheap, case-insensitive literal pre-filter (skip a rule whose literal prefix
            # is nowhere in the view). Case-insensitive because the rules use IgnoreCase.
            if ($r._QuickLit -and ($Text.IndexOf($r._QuickLit, [System.StringComparison]::OrdinalIgnoreCase) -lt 0)) { continue }
            if ($r._Needles -and @($r._Needles).Count) {
                $hasNeedle = $false
                foreach ($nd in $r._Needles) { if ($Text.IndexOf($nd, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $hasNeedle = $true; break } }
                if (-not $hasNeedle) { continue }
            }
            foreach ($m in $r._RX.Matches($Text)) {
                $hit = $m.Value
                # Placeholder / documentation guard: skip format examples, not real credentials
                # (HTML entities, angle-bracket templates, common filler words).
                # private-key-xml is exempt from the placeholder guard: a real RSAKeyValue is full of
                # legit XML tags (<RSAKeyValue>/<Modulus>/<D>) that the generic `<[a-z_ ]{2,}>`
                # template-placeholder pattern matches case-insensitively -- which was silently
                # suppressing EVERY private-key-in-XML hit. The rule's own `<D>[A-Za-z0-9+/=]{20,}</D>`
                # requirement already excludes a `<D>your-key-here</D>` placeholder.
                # Two more false-positive classes seen in real Electron apps:
                #  * a UI-message / i18n string, where the "credential" VALUE is a quoted
                #    natural-language phrase -- e.g. WRONG_PASSWORD: "Wrong Password", or
                #    "Enter your password". A real hardcoded password almost always carries a
                #    digit/symbol, so a quoted run of 2+ pure-alpha words is a label, not a secret.
                #  * the canonical basic-auth URL placeholder (user:pass@host / username:password@)
                #    that appears in docs/help text (e.g. "credentials like https://user:pass@host/").
                if ("$($r.id)" -ne 'private-key-xml' -and ($hit -match '(?i)(&lt|&gt|&amp|<[a-z_ ]{2,}>|\bsnipped\b|\bplaceholder\b|\bexample\b|\byour[-_ ]|\bchange[-_ ]?me\b|\breplace[-_ ]?me\b|\bdummy\b|\bsample\b|\bredacted\b|x{6,}|\.\.\.|\*{4,}|["''][A-Za-z]{2,}(?: [A-Za-z]{2,})+["'']|://(?:user(?:name)?|admin|test|example|foo|bar):(?:pass(?:word|wd)?|secret|test|xxx+)@)')) { continue }
                $key = "$($r.id)::" + $hit.Substring(0, [Math]::Min(80, $hit.Length))
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $true
                # Inferred: a regex match confirms the FORMAT is present, not that the credential is live.
                New-TcpkFinding -Module 'static' -RuleId "secrets.$($r.id)" `
                    -Severity $r.severity -Confidence 'Inferred' `
                    -Title $r.title -File $f.FullName `
                    -Evidence "$hit [src=$Src]" `
                    -Cwe ([string[]]$r.cwe) -Fix $r.fix
            }
        }
    }

    $fileArr = @($files); $fileTotal = $fileArr.Count; $fileIdx = 0
    foreach ($f in $fileArr) {
        $fileIdx++
        Write-TcpkProgress -Id 77 -ParentId 1 -Activity 'Secrets scan' -Status ("{0} ({1} MB) [{2}/{3}]" -f $f.Name, [int]($f.Length / 1MB), $fileIdx, $fileTotal) -Current $fileIdx -Total $fileTotal
        if ($f.Extension.ToLowerInvariant() -in $skipExt) { continue }
        if (Test-TcpkIsFrameworkFile $f.Name)             { continue }
        # Skip bundled runtime / Chromium / NSIS / license files (a secret matched inside a
        # framework binary or third-party licence text is not a first-party finding).
        if (-not (Test-TcpkIsFirstParty -Name $f.Name -SizeBytes $f.Length -Path $f.FullName)) { continue }

        # NO size cap: EVERY file is analyzed regardless of size. Files up to a memory-safe
        # threshold are loaded whole (and view-cached); larger files are streamed in bounded
        # OVERLAPPING chunks -- so nothing is ever skipped for being big, and a multi-GB file
        # cannot exhaust memory. The overlap (64KB) exceeds the longest rule match, so a secret
        # straddling a chunk boundary is still caught.
        $seen = @{}
        if ($f.Length -le 64MB) {
            $views = Read-TcpkStringViews -Path $f.FullName
            if (-not $views) { continue }
            & $scanText $views.Utf8       'utf8'
            & $scanText $views.Utf16Le    'utf16le'
            & $scanText $views.Utf16LeOdd 'utf16le-odd'
        }
        else {
            try {
                $fsr = [System.IO.FileStream]::new($f.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
                       ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
                try {
                    $chunkSize = 16MB; $overlap = 64KB
                    $buf = New-Object byte[] ([int](16MB + 64KB))
                    $carry = 0
                    while ($true) {
                        $n = $fsr.Read($buf, $carry, $chunkSize)
                        $total = $carry + $n
                        if ($total -le 0) { break }
                        & $scanText ([System.Text.Encoding]::UTF8.GetString($buf, 0, $total))    'utf8'
                        & $scanText ([System.Text.Encoding]::Unicode.GetString($buf, 0, $total)) 'utf16le'
                        if ($total -gt 1) { & $scanText ([System.Text.Encoding]::Unicode.GetString($buf, 1, $total - 1)) 'utf16le-odd' }
                        if ($n -le 0) { break }
                        $keep = [Math]::Min($overlap, $total)
                        [Array]::Copy($buf, $total - $keep, $buf, 0, $keep)
                        $carry = $keep
                    }
                } finally { $fsr.Dispose() }
            } catch { }
        }
    }
    Complete-TcpkProgress -Id 77
}
