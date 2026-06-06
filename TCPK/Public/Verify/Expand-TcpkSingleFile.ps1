function Expand-TcpkSingleFile {
<#
.SYNOPSIS
    Extract the managed assemblies bundled inside a .NET single-file (PublishSingleFile)
    apphost so the rest of TCPK can actually scan them.

.DESCRIPTION
    `dotnet publish -p:PublishSingleFile=true` appends every managed assembly (and
    deps.json / runtimeconfig.json, optionally Deflate-compressed) into the apphost
    .exe as a "bundle". TCPK's static scanners read loose .dll/.exe files, so for a
    single-file app there is nothing on disk to read and the secret / callsite /
    TLS-bypass / deserialization / CVE checks would silently see almost nothing.

    This parses the bundle manifest (Microsoft.NET.HostModel format, major versions
    1 / 2 / 6), carves each embedded file back to -OutDir (decompressing where
    needed), then runs the shared secret-regex rules over the recovered assemblies.
    After extracting, point any other Test-Tcpk* cmdlet at -OutDir for full coverage
    (the full audit does this automatically).

    Secret-pattern hits are Confidence='Inferred'.

.PARAMETER Path
    A single-file .exe, or a folder (recursive) that contains one or more of them.

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

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $exes = if ($item.PSIsContainer) {
        Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension.ToLowerInvariant() -eq '.exe' }
    } else { @($item) }

    if (-not $OutDir) { $OutDir = Join-Path $env:TEMP ('tcpk-singlefile-' + [guid]::NewGuid().ToString('N')) }
    $rules = Get-TcpkSecretRegexRules

    foreach ($exe in $exes) {
        if ($null -eq (Test-TcpkSingleFileExe -Path $exe.FullName)) { continue }

        $outRoot = Join-Path $OutDir $exe.BaseName
        $extracted = @()
        try {
            $extracted = @(Expand-TcpkSingleFileBundle -Path $exe.FullName -OutDir $outRoot)
        } catch {
            New-TcpkFinding -Module 'static' -RuleId 'singlefile.parse-failed' -Severity 'INFO' -Confidence 'Skipped' `
                -Title "Could not parse single-file bundle: $($exe.Name)" -File $exe.FullName -Evidence $_.Exception.Message
            continue
        }

        $asm = @($extracted | Where-Object { $_.Type -eq 'Assembly' }).Count
        $nat = @($extracted | Where-Object { $_.Type -eq 'NativeBinary' }).Count
        New-TcpkFinding -Module 'static' -RuleId 'singlefile.expanded' -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "Extracted $($extracted.Count) bundled files from $($exe.Name)" -File $outRoot `
            -Evidence "assemblies=$asm native=$nat -> $outRoot" `
            -Description 'A .NET single-file apphost was unpacked. Its managed assemblies are now on disk, so the static scanners can read them. Point other Test-Tcpk* checks at this folder for full coverage.' `
            -Fix 'Single-file packaging is not a security control -- assume all bundled code and strings are recoverable.'

        # --- light secret scan over the recovered managed assemblies ---
        foreach ($ef in ($extracted | Where-Object { $_.Type -eq 'Assembly' -or $_.Name -match '(?i)\.(dll|exe|json)$' })) {
            if (-not (Test-Path -LiteralPath $ef.Path)) { continue }
            if (Test-TcpkIsFrameworkFile $ef.Name) { continue }
            $t = Read-TcpkAllText -Path $ef.Path
            if (-not $t) { continue }
            foreach ($r in $rules) {
                $m = $r._RX.Match($t)
                if ($m.Success) {
                    $v = $m.Value; if ($v.Length -gt 80) { $v = $v.Substring(0, 80) + ' ...' }
                    New-TcpkFinding -Module 'static' -RuleId "singlefile.$($r.id)" `
                        -Severity $(if ($r.severity) { $r.severity } else { 'MEDIUM' }) -Confidence 'Inferred' `
                        -Title "$($r.title) in $($ef.Name) (single-file)" -File $ef.Path -Evidence $v -Cwe (@($r.cwe)) `
                        -Description 'A secret-pattern match in an assembly recovered from the single-file bundle. Confirm and rotate if live.'
                    break
                }
            }
        }
    }
}
