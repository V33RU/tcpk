function Test-TcpkV8Bytecode {
<#
.SYNOPSIS
    A45. Electron JavaScript compiled to V8 bytecode (bytenode / .jsc) -- a blind spot
    for every JS check, reported so their silence is not mistaken for a clean result.

.DESCRIPTION
    Electron ships application logic as plaintext JavaScript inside app.asar, which is
    why TCPK can unpack it and why Test-TcpkElectronJs can find sinks in it.

    Some applications compile that JavaScript to V8 BYTECODE instead, using bytenode or
    an equivalent, and ship .jsc files. The source is then not present at all: asar
    extraction succeeds, the JS pattern scanners run, and they find nothing -- because
    there is nothing readable there, not because the application is clean.

    That is the problem this check exists to solve. Without it the report is not merely
    incomplete, it is WRONG: an application that deliberately hid its logic produces the
    same clean output as one with nothing to hide. This is the same principle as
    scan.incomplete-coverage -- a blind spot the tool does not notice is a bug, while one
    it declares is a limitation.

    Signals, strongest first:
      1. .jsc files present, loose or inside app.asar, whose contents are binary rather
         than text.
      2. bytenode declared in a package.json dependency list.
      3. bytenode API use in shipped JS (require('bytenode'), runBytecodeFile,
         compileFile, or vm.Script with cachedData + produceCachedData).

    NOT flagged: v8-compile-cache and Electron's own code cache. Those are performance
    caches written ALONGSIDE the original JavaScript, which remains readable, so they
    blind nothing. Confusing the two would make this check fire on a large share of
    normal Electron applications.

    Static and read-only.

.PARAMETER Path
    File or directory to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $dir = if ($item.PSIsContainer) { $item.FullName } else { $item.DirectoryName }

    $asars = @(Get-TcpkChildItemSafe -Path $dir -File |
        Where-Object { $_.Extension.ToLowerInvariant() -eq '.asar' })
    $looseJs = @(Get-TcpkChildItemSafe -Path $dir -File |
        Where-Object { $_.Extension.ToLowerInvariant() -in @('.js', '.jsc') })

    # Electron-shaped target only; otherwise stay silent rather than guess.
    if (-not $asars.Count -and -not $looseJs.Count) { return }

    # A .jsc that is really V8 bytecode is binary. Checking that rather than trusting the
    # extension keeps a stray text file named .jsc from firing this.
    function _LooksBinary([byte[]]$Bytes, [int]$Take = 512) {
        if (-not $Bytes -or $Bytes.Length -lt 16) { return $false }
        $n = [Math]::Min($Take, $Bytes.Length)
        $ctrl = 0
        for ($i = 0; $i -lt $n; $i++) {
            $b = $Bytes[$i]
            if ($b -eq 0) { return $true }                       # NUL: never in source text
            if ($b -lt 9 -or ($b -gt 13 -and $b -lt 32)) { $ctrl++ }
        }
        return (($ctrl * 100 / $n) -gt 5)
    }

    $jscLoose = New-Object 'System.Collections.Generic.List[string]'
    # Count and sample are tracked separately: the count must stay exact for the severity
    # decision, while the sample is capped so a big bundle cannot balloon the evidence.
    $jscAsarCount = 0
    $jscSample = New-Object 'System.Collections.Generic.List[string]'
    $jsCount = 0

    foreach ($f in $looseJs) {
        if ($f.Extension.ToLowerInvariant() -eq '.js') { $jsCount++; continue }
        $head = $null
        try {
            $fs = [IO.File]::OpenRead($f.FullName)
            try {
                $len = [Math]::Min(512, [int]$fs.Length)
                $head = New-Object byte[] $len
                [void]$fs.Read($head, 0, $len)
            } finally { $fs.Dispose() }
        } catch { }
        if (_LooksBinary $head) { $jscLoose.Add($f.FullName) }
    }

    # Inside app.asar: walk the header file table. Same parse Get-TcpkAsarNpmComponents
    # uses, so the two cannot disagree about asar layout.
    $asarJs = 0
    foreach ($asar in $asars) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($asar.FullName)
            if ($bytes.Length -lt 16) { continue }
            $headerObjSize = [System.BitConverter]::ToUInt32($bytes, 4)
            $jsonSize      = [System.BitConverter]::ToUInt32($bytes, 12)
            if (($jsonSize + 16) -gt $bytes.Length) { continue }
            $tree = ([System.Text.Encoding]::UTF8.GetString($bytes, 16, $jsonSize)) | ConvertFrom-Json

            $stack = New-Object System.Collections.Generic.Stack[object]
            $stack.Push([pscustomobject]@{ Node = $tree; Prefix = '' })
            while ($stack.Count) {
                $cur = $stack.Pop()
                if (-not $cur.Node.files) { continue }
                foreach ($p in $cur.Node.files.PSObject.Properties) {
                    $child = $p.Value
                    $name = "$($p.Name)"
                    if ($child.files) {
                        $stack.Push([pscustomobject]@{ Node = $child; Prefix = "$($cur.Prefix)$name/" })
                        continue
                    }
                    if ($name -like '*.js') { $asarJs++; continue }
                    if ($name -notlike '*.jsc') { continue }
                    $jscAsarCount++
                    if ($jscSample.Count -lt 20) { $jscSample.Add("$($asar.Name):$($cur.Prefix)$name") }
                }
            }
        } catch { }
    }
    $jsCount += $asarJs

    # bytenode as a declared dependency, and its API in shipped JS.
    $depHit = ''
    foreach ($pjp in @(
            (Join-Path $dir 'package.json'),
            (Join-Path $dir 'resources\app\package.json'),
            (Join-Path $dir 'resources\package.json'))) {
        if (-not (Test-Path -LiteralPath $pjp)) { continue }
        try {
            $pj = Get-Content -LiteralPath $pjp -Raw -ErrorAction Stop | ConvertFrom-Json
            foreach ($dk in @('dependencies', 'devDependencies', 'optionalDependencies')) {
                if ($pj.$dk -and $pj.$dk.'bytenode') { $depHit = "$pjp -> bytenode@$($pj.$dk.'bytenode')"; break }
            }
        } catch { }
        if ($depHit) { break }
    }

    $apiHit = ''
    foreach ($t in (@($asars) + @($looseJs | Where-Object { $_.Extension.ToLowerInvariant() -eq '.js' }) | Select-Object -First 40)) {
        $txt = ''
        try { $txt = Read-TcpkAllText -Path $t.FullName } catch { continue }
        if (-not $txt) { continue }
        $m = [regex]::Match($txt, "(?i)(require\s*\(\s*['""]bytenode['""]\s*\)|bytenode\s*\.\s*(runBytecodeFile|compileFile|compileElectronCode)|produceCachedData\s*:\s*true)")
        if ($m.Success) { $apiHit = "$($t.Name): $($m.Value)"; break }
    }

    $jscTotal = $jscLoose.Count + $jscAsarCount
    if ($jscTotal -eq 0 -and -not $depHit -and -not $apiHit) { return }

    # Severity reflects how much of the logic is actually hidden. Bytecode present with
    # almost no readable JS left means the JS checks saw essentially nothing.
    $sev = 'LOW'
    if ($jscTotal -gt 0) { $sev = 'MEDIUM' }
    if ($jscTotal -gt 0 -and $jsCount -le $jscTotal) { $sev = 'HIGH' }

    $ev = New-Object 'System.Collections.Generic.List[string]'
    $ev.Add("jsc=$jscTotal; readable .js=$jsCount")
    if ($depHit) { $ev.Add("dependency: $depHit") }
    if ($apiHit) { $ev.Add("api: $apiHit") }
    foreach ($sm in (@($jscSample) + @($jscLoose) | Select-Object -First 8)) { $ev.Add("$sm") }

    New-TcpkFinding -Module 'static' -RuleId 'electron.v8-bytecode' `
        -Severity $sev -Confidence 'Confirmed' `
        -Title "Application logic is compiled to V8 bytecode ($jscTotal .jsc file(s)) -- JavaScript checks are blind" `
        -File $dir `
        -Evidence ($ev -join '; ') `
        -Cwe @('CWE-656') `
        -Description ('This application ships its JavaScript compiled to V8 bytecode rather than ' +
            'source. Unpacking app.asar therefore yields bytecode, and every JavaScript check in ' +
            'TCPK (electronjs.*, electron.*, secrets, endpoints) reads nothing usable from those ' +
            'files. TREAT THE ABSENCE OF JavaScript FINDINGS AS UNKNOWN, NOT AS CLEAN: the checks ' +
            'did not pass, they were unable to run. Note also that V8 bytecode is version-bound ' +
            'and not a security control -- it obstructs review without preventing an attacker who ' +
            'runs the matching Electron build from recovering behaviour.') `
        -Fix 'For review, obtain the original sources from the vendor, or run the app under a matching Electron build and recover behaviour dynamically. Compiling to bytecode is obfuscation, not a security boundary, and should not be relied on to protect secrets or logic.'
}
