function Test-TcpkUserRules {
<#
.SYNOPSIS
    A54. Run every user-authored check under TCPK/Data/rules/ against a target.

.DESCRIPTION
    The user-authored extension surface. Anyone can add a detection by dropping a JSON
    rule into TCPK/Data/rules/ or into a directory passed via -ExtraPath. The rule format,
    sandbox model and worked examples are in docs/EXTENDING.md.

    Phase 1 supports type 'file-regex' only: glob + regex over file contents. Refuses to
    load any rule with an unknown field or an unknown type, so an accidental "type: script"
    or "run: powershell.exe" line fails at load time rather than being silently ignored.

    A malformed rule surfaces as a Skipped finding (rules.malformed) with the exact file and
    the parser error. A rule that matches produces a finding under the rule's own id, with
    the rule's severity, CWE, description and fix.

.PARAMETER Path
    Directory to scan (or a single file). Usually the target's install directory.

.PARAMETER ExtraPath
    Additional directories to load rules from, in addition to TCPK/Data/rules/. Useful for
    engagement-specific rules that should not ship in the tool.

.PARAMETER FirstParty
    When set, skip files matched by Test-TcpkIsFirstParty. Same behaviour as Test-TcpkStrings
    -FirstParty. Off by default because a user rule might legitimately target a shipped
    third-party file (a licence blob, a vendor config).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$ExtraPath = @(),
        [switch]$FirstParty
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }

    $loaded = Get-TcpkUserRules -ExtraPath $ExtraPath
    foreach ($e in $loaded.Errors) {
        New-TcpkSkippedFinding -RuleId 'rules.malformed' -Title "User rule refused: $e"
    }
    if (-not $loaded.Rules.Count) { return }

    # Compile the globs once. A rule with an already-invalid regex was refused at load.
    $compiled = @()
    foreach ($r in $loaded.Rules) {
        $globRx = Convert-TcpkGlobToRegex -Glob $r.Glob
        $opts = if ($r.IgnoreCase) { [System.Text.RegularExpressions.RegexOptions]::IgnoreCase } else { [System.Text.RegularExpressions.RegexOptions]::None }
        $bodyRx = [regex]::new($r.Regex, $opts)
        $compiled += [pscustomobject]@{ Rule = $r; Glob = [regex]::new($globRx); Body = $bodyRx }
    }

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }

    $files = @()
    if ($item.PSIsContainer) {
        try { $files = @(Get-TcpkChildItemSafe -Path $Path -File) } catch { return }
    } else {
        $files = @($item)
    }

    foreach ($f in $files) {
        $normPath = ($f.FullName -replace '\\','/')
        # Any rule whose glob matches this path is a candidate.
        $candidates = @($compiled | Where-Object { $_.Glob.IsMatch($normPath) })
        if (-not $candidates.Count) { continue }
        if ($FirstParty -and -not (Test-TcpkIsFirstParty -Name $f.Name -SizeBytes $f.Length -Path $f.FullName)) { continue }

        # Read once, run every candidate rule against the same text.
        $text = ''
        try { $text = [IO.File]::ReadAllText($f.FullName) } catch { continue }
        if (-not $text) { continue }

        foreach ($c in $candidates) {
            $r = $c.Rule
            # Prefilter is a cheap literal contains-check that a rule author can supply to
            # skip the regex compile-and-match cost on files that obviously do not carry the
            # pattern. Same shape as secrets.json.
            if ($r.Prefilter -and $r.Prefilter.Count) {
                $any = $false
                foreach ($pf in $r.Prefilter) { if ($text.IndexOf("$pf", [StringComparison]::OrdinalIgnoreCase) -ge 0) { $any = $true; break } }
                if (-not $any) { continue }
            }
            $mc = $c.Body.Matches($text)
            if (-not $mc.Count) { continue }

            # Cap hits per file to bound the noise a bad rule can produce.
            $take = [Math]::Min($mc.Count, [Math]::Max(1, $r.MaxHits))
            $samples = for ($i = 0; $i -lt $take; $i++) {
                $m = $mc[$i]
                $s = "$($m.Value)"
                if ($s.Length -gt 120) { $s = $s.Substring(0, 120) + '...' }
                $s
            }
            $ev = "matches=$($mc.Count) sample=" + ($samples -join ' | ')

            New-TcpkFinding -Module 'user' -RuleId $r.Id `
                -Severity $r.Severity -Confidence 'Inferred' `
                -Title "$($r.Title): $([IO.Path]::GetFileName($f.FullName))" `
                -File $f.FullName -Evidence $ev `
                -Cwe $r.Cwe `
                -Description ($r.Description + " Rule source: $($r.Source).") `
                -Fix $r.Fix
        }
    }
}
