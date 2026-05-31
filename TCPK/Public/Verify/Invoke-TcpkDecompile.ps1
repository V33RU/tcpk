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
            $bundled = Join-Path $script:TcpkRoot '..\..\tools\ilspycmd\ilspycmd.exe'
            if (Test-Path $bundled) { $IlspycmdPath = (Resolve-Path $bundled).Path }
        }
    }

    if ($IlspycmdPath -and (Test-Path -LiteralPath $IlspycmdPath)) {
        # 2) Decompile whole module to a temp file, then grep + extract context
        $tmp = Join-Path $env:TEMP "tcpk-decompile-$([Guid]::NewGuid().ToString().Substring(0,8)).cs"
        try {
            & $IlspycmdPath -o (Split-Path $tmp -Parent) -p (Split-Path $tmp -Leaf) $Dll 2>&1 | Out-Null
            if (-not (Test-Path $tmp)) {
                Write-Warning "ilspycmd produced no output; falling back to byte-grep."
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
            if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
        }
    }

    # 3) Fallback: byte-grep over UTF-8 + UTF-16LE
    Write-Warning "ilspycmd not available; returning byte context (not decompiled). Install via: dotnet tool install -g ilspycmd"
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
