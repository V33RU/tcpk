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

    # Rules come from the shared builder in Private\_MemRead.ps1, which compiles _RX with
    # the mandatory match timeout and attaches both pre-filter gates. This block used to
    # build all three inline; the duplicate disagreed with the other builder about the
    # timeout, the Multiline flag and the gates, and since Get-TcpkData hands out cached
    # objects that both mutated, whichever check ran first in a session won. The comments
    # explaining each decision moved with the code.
    $rules = Get-TcpkSecretRegexRules

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
            # Both pre-filter gates, in the one implementation every secret consumer shares.
            # Inlining them here again is what let the live-memory, clipboard, env-block, UI
            # and archive scanners drift into running the rules ungated.
            if (-not (Test-TcpkSecretRuleApplies -Rule $r -Text $Text)) { continue }
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
    $budgetSkipped = 0
    foreach ($f in $fileArr) {
        $fileIdx++
        # Same cooperative budget as the other heavy per-file checks. Stopping early keeps
        # every secret already found; throwing would discard the lot, because Invoke-TcpkAudit
        # collects a check's output with `$r = & $Block`.
        if (Test-TcpkCheckBudgetExpired) { $budgetSkipped = $fileTotal - $fileIdx + 1; break }
        Write-TcpkHeartbeat -Component 'Test-TcpkSecrets' -Index $fileIdx -Total $fileTotal -Current $f.Name -CurrentBytes $f.Length
        Write-TcpkProgress -Id 77 -ParentId 1 -Activity 'Secrets scan' -Status ("{0} ({1} MB) [{2}/{3}]" -f $f.Name, [int]($f.Length / 1MB), $fileIdx, $fileTotal) -Current $fileIdx -Total $fileTotal
        if ($f.Extension.ToLowerInvariant() -in $skipExt) { continue }
        if (Test-TcpkIsFrameworkFile $f.Name)             { continue }
        # Skip bundled runtime / Chromium / NSIS / license files (a secret matched inside a
        # framework binary or third-party licence text is not a first-party finding).
        if (-not (Test-TcpkIsFirstParty -Name $f.Name -SizeBytes $f.Length -Path $f.FullName)) { continue }

        # NO size cap: EVERY file is analyzed regardless of size. Read-TcpkStringViews decodes
        # a small file verbatim and streams a large one through the C# printable-run extractor,
        # so every byte is read in bounded memory. That also shrinks the matched text to
        # typically 2-5% of the file, which is what makes 49 rules over a 200 MB binary
        # tractable at all: verbatim, the per-rule OrdinalIgnoreCase pre-filter alone is
        # ~18 billion character comparisons.
        #
        # A per-FILE catch, not a per-check one. Invoke-TcpkAudit collects a check's output
        # with `$r = & $Block`, so an exception escaping this loop would discard every finding
        # already produced -- a runaway match on file 400 of 900 would throw away files 1-399.
        # Catch it here, record the file, and carry on.
        $seen = @{}
        $fsw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
        $views = Read-TcpkStringViews -Path $f.FullName
        if ($views) {
            & $scanText $views.Utf8       'utf8'
            & $scanText $views.Utf16Le    'utf16le'
            & $scanText $views.Utf16LeOdd 'utf16le-odd'
        }
        else {
            # Only reached when the extractor could not be compiled on this host. Walk the
            # file in overlapping chunks: bounded memory, nothing skipped, nothing truncated.
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
        $fsw.Stop()
        # Attribute a slow scan to the FILE that caused it. Without this a long check
        # just looks frozen, and the operator cannot tell a 200 MB binary being read
        # from a hang. 5s is well above a normal per-file scan.
        if ($fsw.Elapsed.TotalSeconds -ge 5.0) {
            $sm = ("{0} took {1}s to scan ({2} MB)" -f $f.Name, [math]::Round($fsw.Elapsed.TotalSeconds, 1), [int]($f.Length / 1MB))
            try { Write-Information -MessageData "  [slow file] $sm" -InformationAction Continue } catch { }
            try { Write-TcpkLog -Level INFO -Component 'secrets' -Message $sm -DurationMs ([int]$fsw.Elapsed.TotalMilliseconds) | Out-Null } catch { }
        }
        } catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
            $fsw.Stop()
            New-TcpkSkippedFinding -RuleId 'secrets.rule-timeout' `
                -Title "Secret rules timed out on $($f.Name)" `
                -Reason ("A regex exceeded the match timeout on this file, so its remaining rules " +
                    "did not run. Other files were unaffected. Review it directly: strings -a " +
                    "`"$($f.FullName)`"")
        } catch {
            $fsw.Stop()
            try { Write-TcpkLog -Level ERROR -Component 'secrets' -Message ("$($f.Name): $($_.Exception.Message)") | Out-Null } catch { }
            New-TcpkSkippedFinding -RuleId 'secrets.file-error' `
                -Title "Secret scan failed on $($f.Name)" `
                -Reason "$($_.Exception.Message)"
        }
    }
    if ($budgetSkipped -gt 0) {
        New-TcpkSkippedFinding -RuleId 'secrets.budget-exhausted' `
            -Title "Secret scan stopped early: $budgetSkipped of $fileTotal files not scanned" `
            -Reason ("This check hit its wall-clock budget after $($fileIdx - 1) files. The remaining " +
                "$budgetSkipped were NOT scanned, so the absence of a secret finding for them is " +
                "UNKNOWN, not clean. Narrow -Path or raise the budget and re-run to cover them.")
    }
    Complete-TcpkProgress -Id 77
}
