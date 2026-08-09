function Invoke-TcpkDecompile {
<#
.SYNOPSIS
    Drive ILSpy CLI to decompile and return source context for a method.

.DESCRIPTION
    Uses ilspycmd (a dotnet global tool that ships with ILSpy) to decompile
    the named assembly and search for the named method. Returns the
    decompiled C# around the match. If ilspycmd is not on PATH, falls back
    to a literal string-grep against the binary's UTF-8 + UTF-16LE views
    and returns the surrounding byte context.

.PARAMETER Dll
    Path to the .NET assembly.

.PARAMETER Search
    Method or symbol name to find.

.PARAMETER Context
    Number of lines of context around each match. Default 6.

.PARAMETER IlspycmdPath
    Override path to ilspycmd.exe. If not given, looks on PATH, then in
    .\tools\ilspycmd\, then falls back to byte-grep.

.EXAMPLE
    Invoke-TcpkDecompile -Dll '.\YourApp.dll' -Search 'ServerCertificateCustomValidationCallback'

.OUTPUTS
    [string] -- the decompiled or byte-context source around the match.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Dll,
        [Parameter(Mandatory)][string]$Search,
        [int]$Context = 6,
        [string]$IlspycmdPath
    )

    if (-not (Test-Path -LiteralPath $Dll)) { throw "DLL not found: $Dll" }

    # 1) Find ilspycmd
    if (-not $IlspycmdPath) {
        $cmd = Get-Command ilspycmd -ErrorAction SilentlyContinue
        if ($cmd) { $IlspycmdPath = $cmd.Source }
        else {
            # One level up, not two: $script:TcpkRoot is <tool folder>\TCPK, so '..\..\'
            # resolved to a sibling of the tool folder and never found a bundled copy.
            $bundled = Join-Path $script:TcpkRoot '..\tools\ilspycmd\ilspycmd.exe'
            if (Test-Path $bundled) { $IlspycmdPath = (Resolve-Path $bundled).Path }
        }
    }

    if ($IlspycmdPath -and (Test-Path -LiteralPath $IlspycmdPath)) {
        # 2) Decompile the whole module, then grep + extract context.
        #
        # The previous invocation was  -o <dir> -p <leaf> $Dll  and could never work:
        # ilspycmd's -p/--project is a BOOLEAN switch, so <leaf> was consumed as an extra
        # positional ASSEMBLY name, and -p also selects project mode, which writes a source
        # tree rather than the single .cs the code then looked for. Test-Path on that file
        # always failed, so this fell through to byte-grep on every run even when ilspycmd
        # was installed. Per ilspycmd's own docs, "-o <dir>" WITHOUT -p is what produces a
        # single C# file.
        #
        # The output name is chosen by ilspycmd from the assembly name, so decompile into a
        # dedicated empty directory and take whatever .cs appears rather than assuming one.
        $tmpDir = Get-TcpkWorkDir -Kind 'run' -Leaf ('decompile-' + [guid]::NewGuid().ToString('N').Substring(0, 12))
        $tmp = $null
        try {
            & $IlspycmdPath -o $tmpDir $Dll 2>&1 | Out-Null
            $tmp = (Get-ChildItem -LiteralPath $tmpDir -Filter '*.cs' -File -Recurse -ErrorAction SilentlyContinue |
                    Sort-Object Length -Descending | Select-Object -First 1).FullName
            if (-not $tmp) {
                Write-Warning "ilspycmd produced no .cs output in $tmpDir; falling back to byte-grep."
            } else {
                $lines = Get-Content -LiteralPath $tmp
                $sb = New-Object Text.StringBuilder
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    if ($lines[$i] -match [regex]::Escape($Search)) {
                        $start = [Math]::Max(0, $i - $Context)
                        $end   = [Math]::Min($lines.Count - 1, $i + $Context)
                        [void]$sb.AppendLine("--- match at line $($i+1) ---")
                        for ($j = $start; $j -le $end; $j++) {
                            [void]$sb.AppendLine(("{0,5}: {1}" -f ($j+1), $lines[$j]))
                        }
                        [void]$sb.AppendLine('')
                    }
                }
                return $sb.ToString()
            }
        } finally {
            # Remove the whole scratch directory, not just the one .cs we read: ilspycmd
            # can emit several files and they are decompiled target source.
            if ($tmpDir -and (Test-Path -LiteralPath $tmpDir)) {
                Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # 3) Fallback: byte-grep over UTF-8 + UTF-16LE.
    # This is reached two different ways, and saying "not available" for both hid the bug
    # above for as long as it existed: with ilspycmd installed and failing, the operator was
    # told to install the thing they already had.
    if ($IlspycmdPath -and (Test-Path -LiteralPath $IlspycmdPath)) {
        Write-Warning "ilspycmd is installed at $IlspycmdPath but produced no C# output; returning byte context (NOT decompiled)."
    } else {
        Write-Warning "ilspycmd not available; returning byte context (not decompiled). Install via: dotnet tool install -g ilspycmd"
    }
    $bytes = [IO.File]::ReadAllBytes($Dll)
    foreach ($enc in @(@{N='utf8';E=[Text.Encoding]::UTF8}, @{N='utf16le';E=[Text.Encoding]::Unicode})) {
        $t = $enc.E.GetString($bytes)
        $i = $t.IndexOf($Search)
        if ($i -lt 0) { continue }
        $start = [Math]::Max(0, $i - 200)
        $len = [Math]::Min($t.Length - $start, 500)
        $chunk = ($t.Substring($start, $len) -replace '[^\x20-\x7E]', '.')
        return "--- byte context, enc=$($enc.N), char offset $i ---`n$chunk"
    }
    return "(no match for '$Search' in $Dll)"
}
