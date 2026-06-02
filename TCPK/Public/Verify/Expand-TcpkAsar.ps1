function Expand-TcpkAsar {
<#
.SYNOPSIS
    Parse an Electron app.asar header file-table, extract each bundled module, and
    scan the extracted JS/config for secrets and insecure Electron flags.

.DESCRIPTION
    Test-TcpkElectron scans the asar as one raw blob. This properly parses the asar
    format (8-byte pickle + JSON header file-table) to enumerate and UNPACK each
    individual file to -OutDir, then runs the shared secret-pattern rules and the
    Electron insecure-flag markers (nodeIntegration / contextIsolation:false /
    webSecurity:false / allowRunningInsecureContent / sandbox:false) over the
    extracted text - per-file, with real paths.

    Pattern hits are Confidence='Inferred'.

.PARAMETER Path
    A .asar file, or a folder (recursive) containing one or more *.asar.

.PARAMETER OutDir
    Where to extract. Default: a fresh folder under %TEMP%.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$OutDir
    )

    $asars = if ((Get-Item -LiteralPath $Path).PSIsContainer) {
        Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -ieq '.asar' }
    } elseif ((Get-Item -LiteralPath $Path).Extension -ieq '.asar') {
        @(Get-Item -LiteralPath $Path)
    } else { @() }

    if (-not $OutDir) { $OutDir = Join-Path $env:TEMP ('tcpk-asar-' + [guid]::NewGuid().ToString('N')) }
    $rules = Get-TcpkSecretRegexRules
    $flagRx = '(?i)(nodeIntegration\s*:\s*true|contextIsolation\s*:\s*false|webSecurity\s*:\s*false|allowRunningInsecureContent\s*:\s*true|sandbox\s*:\s*false)'
    $scanExt = @('.js','.mjs','.cjs','.ts','.json','.html','.env','.txt','.map')

    foreach ($asar in $asars) {
        $fs = $null; $br = $null
        try {
            $fs = [IO.File]::OpenRead($asar.FullName)
            $br = [IO.BinaryReader]::new($fs)
            if ($fs.Length -lt 16) { continue }
            $null    = $br.ReadUInt32()        # always 4
            $hdrSize = $br.ReadUInt32()        # header pickle size
            $jsonLen = $br.ReadUInt32()        # json string length (first field of header pickle)
            if ($jsonLen -le 0 -or $jsonLen -gt ($fs.Length)) { continue }
            $jsonBytes = $br.ReadBytes([int]$jsonLen)
            $json = [Text.Encoding]::UTF8.GetString($jsonBytes)
            $base = 8 + [int]$hdrSize          # data section start
            $tree = $json | ConvertFrom-Json
        } catch {
            if ($br) { $br.Dispose() }; if ($fs) { $fs.Dispose() }
            New-TcpkFinding -Module 'static' -RuleId 'asar.parse-failed' -Severity 'INFO' -Confidence 'Skipped' `
                -Title "Could not parse asar header: $($asar.Name)" -File $asar.FullName -Evidence $_.Exception.Message
            continue
        }

        $outRoot = Join-Path $OutDir $asar.BaseName
        $extracted = 0
        # Iterative walk of the file tree (name -> node; node has .files (dir) or .offset/.size (file))
        $stack = New-Object System.Collections.Stack
        $stack.Push([pscustomobject]@{ Node = $tree; Rel = '' })
        while ($stack.Count -gt 0) {
            $cur = $stack.Pop()
            $filesNode = $cur.Node.files
            if (-not $filesNode) { continue }
            foreach ($prop in $filesNode.PSObject.Properties) {
                $name = $prop.Name; $child = $prop.Value
                $rel = if ($cur.Rel) { Join-Path $cur.Rel $name } else { $name }
                if ($child.PSObject.Properties['files']) {
                    $stack.Push([pscustomobject]@{ Node = $child; Rel = $rel })
                }
                elseif ($child.PSObject.Properties['offset']) {
                    if ($child.unpacked -eq $true) { continue }   # stored outside the asar
                    try {
                        $off = [int64]$child.offset; $sz = [int64]$child.size
                        if ($sz -lt 0 -or ($base + $off + $sz) -gt $fs.Length) { continue }
                        $dest = Join-Path $outRoot $rel
                        $ddir = Split-Path -Parent $dest
                        if (-not (Test-Path -LiteralPath $ddir)) { New-Item -ItemType Directory -Path $ddir -Force | Out-Null }
                        $fs.Position = $base + $off
                        $buf = $br.ReadBytes([int][Math]::Min($sz, [int64][int]::MaxValue))
                        [IO.File]::WriteAllBytes($dest, $buf)
                        $extracted++
                    } catch { }
                }
            }
        }
        $br.Dispose(); $fs.Dispose()

        New-TcpkFinding -Module 'static' -RuleId 'asar.expanded' -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "Extracted $extracted files from $($asar.Name)" -File $outRoot `
            -Evidence "asar -> $outRoot" `
            -Description 'The asar bundle was unpacked. Each JS module is now on disk for per-file review.'

        # --- scan extracted text for secrets + insecure Electron flags ---
        if ($extracted -gt 0 -and (Test-Path -LiteralPath $outRoot)) {
            foreach ($ef in (Get-ChildItem -LiteralPath $outRoot -Recurse -File -ErrorAction SilentlyContinue |
                              Where-Object { $_.Extension.ToLowerInvariant() -in $scanExt -and $_.Length -lt 4MB })) {
                $t = $null; try { $t = [IO.File]::ReadAllText($ef.FullName) } catch { continue }
                if (-not $t) { continue }
                foreach ($r in $rules) {
                    $m = $r._RX.Match($t)
                    if ($m.Success) {
                        $v = $m.Value; if ($v.Length -gt 80) { $v = $v.Substring(0,80) + ' ...' }
                        New-TcpkFinding -Module 'static' -RuleId "asar.$($r.id)" `
                            -Severity $(if ($r.severity) { $r.severity } else { 'MEDIUM' }) -Confidence 'Inferred' `
                            -Title "$($r.title) in $($ef.Name) (asar)" -File $ef.FullName -Evidence $v -Cwe (@($r.cwe)) `
                            -Description 'A secret-pattern match in an extracted asar module. Confirm and rotate if live.'
                        break
                    }
                }
                $fm = [regex]::Match($t, $flagRx)
                if ($fm.Success) {
                    New-TcpkFinding -Module 'static' -RuleId 'asar.electron-insecure-flag' `
                        -Severity 'HIGH' -Confidence 'Inferred' `
                        -Title "Insecure Electron flag in $($ef.Name) (asar): $($fm.Value)" `
                        -File $ef.FullName -Evidence $fm.Value -Cwe @('CWE-79','CWE-829') `
                        -Description 'An extracted module sets an insecure BrowserWindow/webPreferences flag. With nodeIntegration on / contextIsolation off, any rendered untrusted content can reach Node and execute code.' `
                        -Fix 'Set contextIsolation:true, nodeIntegration:false, sandbox:true, webSecurity:true.'
                }
            }
        }
    }
}
