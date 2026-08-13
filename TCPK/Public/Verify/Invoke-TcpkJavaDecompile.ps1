function Invoke-TcpkJavaDecompile {
<#
.SYNOPSIS
    Drive CFR to decompile a .jar / .war / .class and return source context for a symbol.

.DESCRIPTION
    The Java counterpart to Invoke-TcpkDecompile. Test-TcpkJavaBundle already reads the
    STRINGS inside a jar's class constant pools, which finds secrets and risky API names
    but never shows the code around them. This decompiles for real.

    CFR (github.com/leibnitz27/cfr) is a single self-contained jar, so it resolves exactly
    the way ilspycmd does: an explicit -CfrPath, then tools\cfr\cfr.jar next to the tool
    folder, then PATH. It is NOT redistributed with TCPK; install it yourself. A JRE is
    also required, since CFR is itself Java.

    WHEN CFR IS MISSING it falls back to reading printable UTF-8 runs out of the class
    constant pool and returning the bytes around the match, which is the same fallback
    shape the .NET path uses. That fallback is NOT decompilation and says so.

    THE TWO FAILURE MODES ARE REPORTED SEPARATELY, deliberately. Invoke-TcpkDecompile
    carried a bug for a long time where a broken ilspycmd invocation silently fell through
    to byte-grep, so an operator who HAD the decompiler installed was told to install it.
    Distinguishing "not installed" from "installed but produced nothing" is the only way
    that class of bug surfaces instead of hiding.

.PARAMETER Archive
    Path to a .jar, .war, .ear or a single .class file.

.PARAMETER Search
    Method, field or symbol name to find in the decompiled source.

.PARAMETER Context
    Lines of context around each match. Default 6, matching Invoke-TcpkDecompile.

.PARAMETER CfrPath
    Explicit path to cfr.jar. Otherwise tools\cfr\cfr.jar, then PATH.

.PARAMETER JavaPath
    Explicit path to java(.exe). Otherwise PATH, then JAVA_HOME\bin.

.PARAMETER TimeoutSec
    Give up on CFR after this long. Default 120. A large jar with thousands of classes can
    take minutes, and an unbounded wait would hang a GUI audit with no way out.

.EXAMPLE
    Invoke-TcpkJavaDecompile -Archive '.\app.jar' -Search 'getConnection'

.OUTPUTS
    [string] -- the decompiled or byte-context source around the match.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Archive,
        [Parameter(Mandatory)][string]$Search,
        [int]$Context = 6,
        [string]$CfrPath,
        [string]$JavaPath,
        [int]$TimeoutSec = 120
    )

    if (-not (Test-Path -LiteralPath $Archive)) { throw "Archive not found: $Archive" }

    # 1) Locate java. CFR is itself a jar, so no JRE means no decompilation at all.
    if (-not $JavaPath) {
        $cmd = Get-Command java -ErrorAction SilentlyContinue
        if ($cmd) { $JavaPath = $cmd.Source }
        elseif ($env:JAVA_HOME) {
            $cand = Join-Path $env:JAVA_HOME 'bin\java.exe'
            if (Test-Path -LiteralPath $cand) { $JavaPath = $cand }
        }
    }

    # 2) Locate cfr.jar. One level up from $script:TcpkRoot, which is <tool folder>\TCPK.
    #    Invoke-TcpkDecompile used '..\..\' here once and resolved to a SIBLING of the tool
    #    folder, so a bundled copy was never found. One level, not two.
    if (-not $CfrPath) {
        $bundled = Join-Path $script:TcpkRoot '..\tools\cfr\cfr.jar'
        if (Test-Path $bundled) { $CfrPath = (Resolve-Path $bundled).Path }
        else {
            $onPath = Get-Command 'cfr.jar' -ErrorAction SilentlyContinue
            if ($onPath) { $CfrPath = $onPath.Source }
        }
    }

    $haveCfr = ($JavaPath -and (Test-Path -LiteralPath $JavaPath) -and $CfrPath -and (Test-Path -LiteralPath $CfrPath))

    if ($haveCfr) {
        # CFR writes one .java per class, so decompile into a dedicated empty directory and
        # take whatever appears rather than assuming a filename. Everything TCPK creates
        # stays inside the tool folder: Get-TcpkWorkDir, never %TEMP%.
        $tmpDir = Get-TcpkWorkDir -Kind 'run' -Leaf ('javadec-' + [guid]::NewGuid().ToString('N').Substring(0, 12))
        $produced = 0
        try {
            $full = (Resolve-Path -LiteralPath $Archive).Path
            # No --silent or other niceties: I have not verified CFR's exact flag spelling,
            # and inventing one is precisely the bug that made Invoke-TcpkDecompile fall
            # through to byte-grep on every run. --outputdir is the one flag being relied on
            # and it must be confirmed on Windows. Console chatter is harmless behind
            # -WindowStyle Hidden. ($args is an automatic variable, hence $cfrArgs.)
            $cfrArgs = @('-jar', $CfrPath, $full, '--outputdir', $tmpDir)
            $p = Start-Process -FilePath $JavaPath -ArgumentList $cfrArgs -PassThru -WindowStyle Hidden -ErrorAction Stop

            # Bounded, polled wait. An unbounded WaitForExit on a multi-thousand-class jar
            # hangs the caller with no diagnostic; a timeout at least names what happened.
            $waited = 0
            while (-not $p.HasExited -and $waited -lt $TimeoutSec) { Start-Sleep -Seconds 1; $waited++ }
            if (-not $p.HasExited) {
                try { $p.Kill() } catch { }
                Write-Warning "CFR did not finish within $TimeoutSec s; killed. Raise -TimeoutSec or decompile a single .class instead of the whole archive."
            }

            $javaFiles = @(Get-ChildItem -LiteralPath $tmpDir -Filter '*.java' -File -Recurse -ErrorAction SilentlyContinue)
            $produced = $javaFiles.Count

            if ($produced -gt 0) {
                $sb = New-Object Text.StringBuilder
                $hits = 0
                foreach ($jf in $javaFiles) {
                    $lines = @(Get-Content -LiteralPath $jf.FullName -ErrorAction SilentlyContinue)
                    for ($i = 0; $i -lt $lines.Count; $i++) {
                        if ($lines[$i] -match [regex]::Escape($Search)) {
                            $hits++
                            $start = [Math]::Max(0, $i - $Context)
                            $end   = [Math]::Min($lines.Count - 1, $i + $Context)
                            [void]$sb.AppendLine("--- $($jf.Name) line $($i + 1) ---")
                            for ($j = $start; $j -le $end; $j++) {
                                [void]$sb.AppendLine(("{0,5}: {1}" -f ($j + 1), $lines[$j]))
                            }
                            [void]$sb.AppendLine('')
                        }
                    }
                }
                if ($hits -eq 0) {
                    return "(CFR decompiled $produced class(es); no match for '$Search')"
                }
                return $sb.ToString()
            }
        } finally {
            # Remove the whole scratch directory, not one file: this is decompiled target
            # source and none of it should outlive the call.
            if ($tmpDir -and (Test-Path -LiteralPath $tmpDir)) {
                Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # 3) Fallback: printable UTF-8 runs out of the class constant pool.
    # Which of the two reasons we are here matters, and conflating them is what hid the
    # ilspycmd bug for as long as it existed.
    if ($haveCfr) {
        Write-Warning "CFR is installed at $CfrPath but produced no .java output; returning constant-pool context (NOT decompiled)."
    } elseif ($JavaPath -and (Test-Path -LiteralPath $JavaPath)) {
        Write-Warning "java was found but cfr.jar was not; returning constant-pool context (not decompiled). Put cfr.jar in tools\cfr\ or pass -CfrPath."
    } elseif ($CfrPath) {
        Write-Warning "cfr.jar was found but no JRE is available; returning constant-pool context (not decompiled). Install a JRE or pass -JavaPath."
    } else {
        Write-Warning "Neither java nor cfr.jar is available; returning constant-pool context (not decompiled). See docs/INSTALL.md."
    }

    return (Get-TcpkJavaConstantPoolContext -Archive $Archive -Search $Search)
}

function Get-TcpkJavaConstantPoolContext {
<#
.SYNOPSIS
    Printable context around a symbol in a jar's class constant pools, for when CFR is absent.

.DESCRIPTION
    Private helper for Invoke-TcpkJavaDecompile. A .jar is a zip of .class files, and a
    .class carries its method names, field names and string literals as UTF-8 in the
    constant pool, so a plain byte scan finds the symbol even with no decompiler present.

    This is emphatically NOT decompilation. It proves the symbol is present in a class and
    shows the neighbouring printable bytes; it does not show control flow, and the callers
    say so rather than letting the output pass for source.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Archive,
        [Parameter(Mandatory)][string]$Search
    )

    $ext = [IO.Path]::GetExtension($Archive)
    $out = New-Object Text.StringBuilder

    if ($ext -ieq '.class') {
        $bytes = [IO.File]::ReadAllBytes($Archive)
        [void](Add-TcpkClassPoolContext -Bytes $bytes -Name (Split-Path $Archive -Leaf) -Needle $Search -Sb $out)
    } else {
        $zip = $null
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
            $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $Archive).Path)
        } catch {
            return "(could not open '$Archive' as an archive: $($_.Exception.Message))"
        }
        try {
            $scanned = 0
            foreach ($entry in $zip.Entries) {
                if ($entry.FullName -notmatch '\.class$') { continue }
                if ($scanned -ge 4000) {
                    [void]$out.AppendLine('--- stopped after 4000 classes; narrow the target or install CFR ---')
                    break
                }
                $scanned++
                $ms = New-Object IO.MemoryStream
                try {
                    $es = $entry.Open(); $es.CopyTo($ms); $es.Dispose()
                    [void](Add-TcpkClassPoolContext -Bytes $ms.ToArray() -Name $entry.FullName -Needle $Search -Sb $out)
                } catch { } finally { $ms.Dispose() }
            }
        } finally { if ($zip) { $zip.Dispose() } }
    }

    if ($out.Length -eq 0) { return "(no match for '$Search' in $Archive)" }
    return $out.ToString()
}

function Add-TcpkClassPoolContext {
<#
.SYNOPSIS
    Append printable context around a needle found in one .class file's bytes.

.DESCRIPTION
    Private helper for Get-TcpkJavaConstantPoolContext. Top level rather than nested,
    matching how every other helper under Public/ is declared; a nested "function script:"
    would put it in module scope anyway while looking local.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Needle,
        [Parameter(Mandatory)][Text.StringBuilder]$Sb
    )
    $t = [Text.Encoding]::UTF8.GetString($Bytes)
    $i = $t.IndexOf($Needle)
    if ($i -lt 0) { return $false }
    $start = [Math]::Max(0, $i - 160)
    $len   = [Math]::Min($t.Length - $start, 400)
    $chunk = ($t.Substring($start, $len) -replace '[^\x20-\x7E]', '.')
    [void]$Sb.AppendLine("--- $Name, constant-pool context at byte $i ---")
    [void]$Sb.AppendLine($chunk)
    [void]$Sb.AppendLine('')
    return $true
}
