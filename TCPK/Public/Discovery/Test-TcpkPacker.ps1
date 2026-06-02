function Test-TcpkPacker {
<#
.SYNOPSIS
    A22. Packer / obfuscator detection -- and the inverse: source-recoverable
    (not-obfuscated) first-party assemblies.

.DESCRIPTION
    Three real signals:
      1. PACKER  -- known packer/protector section names (UPX/Themida/VMProtect/
         ASPack/Enigma/MPRESS/...) read from the PE section table.
      2. OBFUSCATOR -- .NET obfuscator attribute/marker strings (ConfuserEx,
         Dotfuscator, SmartAssembly, Eazfuscator, Babel, .NET Reactor, Agile.NET,
         Crypto Obfuscator) found in the assembly.
      3. NOT-OBFUSCATED -- first-party managed (.NET) assemblies with no packer
         and no obfuscator -> the source/logic is fully recoverable in a
         decompiler (intellectual-property / logic-exposure risk). Reported once
         as a summary.

.PARAMETER Path
    File or directory.

.PARAMETER Unpack
    Opt-in: when a UPX-packed binary is found and upx.exe is on PATH, auto-unpack a
    COPY (upx -d) to %TEMP% and report the path so the static checks can run on the
    real code. Only UPX is auto-reversible; commercial protectors (Themida/VMProtect)
    require a dynamic unpacker and are never touched.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Unpack
    )

    $upxExe = if ($Unpack) { (Get-Command upx -ErrorAction SilentlyContinue).Source } else { $null }

    # packer / protector section-name signatures
    $packerSecs = @{
        'UPX0'='UPX'; 'UPX1'='UPX'; 'UPX2'='UPX'; '.UPX0'='UPX'
        '.themida'='Themida/WinLicense'; '.winlice'='Themida/WinLicense'
        '.vmp0'='VMProtect'; '.vmp1'='VMProtect'; '.vmp2'='VMProtect'
        '.aspack'='ASPack'; '.adata'='ASPack'
        '.petite'='Petite'; '.nsp0'='NsPack'; '.nsp1'='NsPack'
        'FSG!'='FSG'; 'MEW'='MEW'; '.MPRESS1'='MPRESS'; '.MPRESS2'='MPRESS'
        '.enigma1'='Enigma'; '.enigma2'='Enigma'; '.boom'='Boomerang'
        '.y0da'='yoda'; '.yP'='yoda'; 'pebundle'='PEBundle'; '.perplex'='Perplex'
        '.svkp'='SVKP'; '.taz'='PESpin'; '.packed'='Generic packer'
    }
    # .NET obfuscator markers
    $obfMarkers = @{
        'ConfusedByAttribute'='ConfuserEx'; 'ConfuserEx'='ConfuserEx'
        'DotfuscatorAttribute'='Dotfuscator'; 'DotfuscatedByAttribute'='Dotfuscator'
        'SmartAssembly.Attributes'='SmartAssembly'; 'PoweredByAttribute'='SmartAssembly'
        'EazfuscatorAttribute'='Eazfuscator.NET'; 'Eazfuscator.NET'='Eazfuscator.NET'
        'BabelObfuscatorAttribute'='Babel'; 'BabelAttribute'='Babel'
        'NETReactor'='.NET Reactor'; 'NetReactorSlightlyImproved'='.NET Reactor'
        'Crypto Obfuscator'='Crypto Obfuscator'; 'CryptoObfuscator'='Crypto Obfuscator'
        'ObfuscatedByGoliath'='Goliath.NET'; 'Agile.NET'='Agile.NET / CliSecure'
        'ZYXDNGuarder'='DNGuard'
    }

    $managedNotObf = New-Object 'System.Collections.Generic.List[string]'
    $managedTotal = 0

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        $info = Read-TcpkPe -Path $pe.FullName
        if (-not $info) { continue }

        # 1) packer sections
        foreach ($sn in $info.SectionNames) {
            $key = $packerSecs.Keys | Where-Object { $sn -ieq $_ -or $sn -like "$_*" } | Select-Object -First 1
            if ($key) {
                $packerName = $packerSecs[$key]
                New-TcpkFinding -Module 'static' -RuleId 'packer.detected' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "$($pe.Name) is packed/protected ($packerName)" `
                    -File $pe.FullName -Evidence "section '$sn'" -Cwe @('CWE-656') `
                    -Description "A packer/protector section was found. Packing hides code from static analysis and is sometimes used to evade AV; confirm it is intentional (commercial protector) and unpack to audit the real code." `
                    -Fix 'If this is your own product, ensure the protector is a known commercial one and document it; otherwise treat as suspicious.'

                if ($Unpack -and $packerName -eq 'UPX') {
                    if (-not $upxExe) {
                        New-TcpkFinding -Module 'static' -RuleId 'packer.unpack-skipped' `
                            -Severity 'INFO' -Confidence 'Skipped' `
                            -Title "Cannot auto-unpack $($pe.Name): upx.exe not on PATH" `
                            -File $pe.FullName -Evidence 'install UPX and re-run with -Unpack' `
                            -Description 'UPX was detected but the upx tool is not available to reverse it.'
                    } else {
                        $dest = Join-Path $env:TEMP ('tcpk-unpacked-' + [guid]::NewGuid().ToString('N') + '-' + $pe.Name)
                        try {
                            Copy-Item -LiteralPath $pe.FullName -Destination $dest -Force
                            & $upxExe -d -q $dest 2>$null | Out-Null
                            if ($LASTEXITCODE -eq 0) {
                                New-TcpkFinding -Module 'static' -RuleId 'packer.unpacked' `
                                    -Severity 'INFO' -Confidence 'Confirmed' `
                                    -Title "Unpacked $($pe.Name) (UPX) for analysis" `
                                    -File $dest -Evidence 'upx -d succeeded' `
                                    -Description 'A UPX-unpacked copy was written. Re-run the static checks (secrets/strings/callsites/PE) against this path to audit the real code.'
                            } else {
                                New-TcpkFinding -Module 'static' -RuleId 'packer.unpack-failed' `
                                    -Severity 'INFO' -Confidence 'Skipped' `
                                    -Title "UPX unpack failed for $($pe.Name)" `
                                    -File $pe.FullName -Evidence "upx exit $LASTEXITCODE (may be a modified/secondary-packed UPX)"
                                Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
                            }
                        } catch { }
                    }
                }
                break
            }
        }

        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        $managed = $text.Contains('BSJB')   # .NET metadata root signature

        # 2) obfuscator markers
        $hitObf = $null
        foreach ($mk in $obfMarkers.Keys) { if ($text.Contains($mk)) { $hitObf = $obfMarkers[$mk]; $hitMk = $mk; break } }
        if ($hitObf) {
            New-TcpkFinding -Module 'static' -RuleId 'obfuscation.present' `
                -Severity 'INFO' -Confidence 'Inferred' `
                -Title "$($pe.Name) is obfuscated ($hitObf)" `
                -File $pe.FullName -Evidence "marker: $hitMk" -Cwe @('CWE-656') `
                -Description 'Defensive signal -- code is obfuscated, raising the bar for reverse engineering. Note: obfuscation is not a security control; confirm secrets are not merely hidden.'
            continue
        }

        # 3) not-obfuscated first-party managed assembly
        if ($managed -and -not (Test-TcpkIsFrameworkFile $pe.Name) -and -not (Test-TcpkIsNativeNoise $pe.Name)) {
            $managedTotal++
            $managedNotObf.Add($pe.Name)
        }
    }

    if ($managedNotObf.Count -gt 0) {
        $sample = (@($managedNotObf) | Select-Object -First 12) -join ', '
        New-TcpkFinding -Module 'static' -RuleId 'obfuscation.absent' `
            -Severity 'LOW' -Confidence 'Confirmed' `
            -Title "$($managedNotObf.Count) first-party .NET assemblies are NOT obfuscated (source recoverable)" `
            -File $Path -Evidence $sample -Cwe @('CWE-656','CWE-1294') `
            -Description 'These managed assemblies have no packer and no obfuscator, so a decompiler (ILSpy/dnSpy) recovers near-original source: business logic, license checks, hardcoded values, and any embedded secrets are fully readable.' `
            -Fix 'If the logic/IP or any client-side check matters, apply an obfuscator AND move trust decisions server-side. Never rely on obfuscation to hide secrets.'
    }
}
